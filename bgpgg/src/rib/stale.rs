// Copyright 2026 bgpgg Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::bgp::community;
use crate::rib::path_id::PathIdAllocator;
use crate::rib::{Path, Route};
use std::net::IpAddr;
use std::sync::Arc;

/// Defines how stale routes should be processed.
pub(crate) enum StaleStrategy {
    /// GR sweep: remove all stale paths from the peer.
    Sweep,
    /// LLGR transition: remove NO_LLGR paths, tag rest with LLGR_STALE.
    TransitionToLlgr,
}

impl StaleStrategy {
    /// Apply the strategy to a stale path. Returns true if the path is retained.
    fn apply(&self, path: &mut Arc<Path>) -> bool {
        match self {
            StaleStrategy::Sweep => false,
            StaleStrategy::TransitionToLlgr => {
                if path.attrs.communities.contains(&community::NO_LLGR) {
                    return false;
                }
                let mutable = Arc::make_mut(path);
                if !mutable.attrs.communities.contains(&community::LLGR_STALE) {
                    mutable.attrs_mut().communities.push(community::LLGR_STALE);
                }
                true
            }
        }
    }
}

/// Mark all paths from a peer as stale across the given routes.
pub(crate) fn mark_stale<'a>(
    routes: impl Iterator<Item = &'a mut Route>,
    peer_ip: IpAddr,
) -> usize {
    let mut count = 0;
    for route in routes {
        for path in &mut route.paths {
            if path.is_from_peer(peer_ip) {
                Arc::make_mut(path).stale = true;
                count += 1;
            }
        }
    }
    count
}

/// Process stale paths in a single route: apply the strategy, free removed path IDs.
/// Returns the old best path (before modification) for delta tracking.
pub(crate) fn apply_stale_to_route<A: PathIdAllocator>(
    route: &mut Route,
    peer_ip: IpAddr,
    path_ids: &mut A,
    strategy: &StaleStrategy,
) -> Option<Arc<Path>> {
    let has_stale = route
        .paths
        .iter()
        .any(|p| p.is_from_peer(peer_ip) && p.stale);
    if !has_stale {
        return None;
    }

    let old_best = route.paths.first().map(Arc::clone);

    let mut kept = Vec::with_capacity(route.paths.len());
    for mut path in route.paths.drain(..) {
        if path.is_from_peer(peer_ip) && path.stale && !strategy.apply(&mut path) {
            if let Some(id) = path.local_path_id {
                path_ids.free(id);
            }
            continue;
        }
        kept.push(path);
    }
    route.paths = kept;
    route.paths.sort_by(|a, b| b.best_path_cmp(a));

    old_best
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::community;
    use crate::rib::types::RouteKey;
    use crate::rib::Route;
    use crate::test_helpers::*;
    use std::net::Ipv4Addr;

    fn peer_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    }

    fn bgp_id() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn other_peer_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))
    }

    fn other_bgp_id() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 2)
    }

    fn make_route(paths: Vec<Arc<Path>>) -> Route {
        use crate::net::{IpNetwork, Ipv4Net};
        let prefix = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        });
        Route {
            key: RouteKey::Prefix(prefix),
            paths,
        }
    }

    #[test]
    fn test_mark_stale() {
        let mut route = make_route(vec![
            create_test_path(peer_ip(), bgp_id()),
            create_test_path(other_peer_ip(), other_bgp_id()),
        ]);

        let count = mark_stale(std::iter::once(&mut route), peer_ip());
        assert_eq!(count, 1);
        assert!(route.paths[0].stale);
        assert!(!route.paths[1].stale);
    }

    #[test]
    fn test_sweep() {
        let mut alloc = FakeAllocator::new();
        let mut route = make_route(vec![
            create_test_path_with(peer_ip(), bgp_id(), |p| {
                p.stale = true;
                p.local_path_id = Some(42);
            }),
            create_test_path(other_peer_ip(), other_bgp_id()),
        ]);

        let old_best =
            apply_stale_to_route(&mut route, peer_ip(), &mut alloc, &StaleStrategy::Sweep);
        assert!(old_best.is_some());
        assert_eq!(route.paths.len(), 1);
        assert!(route.paths[0].is_from_peer(other_peer_ip()));
        assert!(alloc.freed.contains(&42));
    }

    #[test]
    fn test_sweep_removes_empty() {
        let mut alloc = FakeAllocator::new();
        let mut route = make_route(vec![create_test_path_with(peer_ip(), bgp_id(), |p| {
            p.stale = true;
            p.local_path_id = Some(43);
        })]);

        apply_stale_to_route(&mut route, peer_ip(), &mut alloc, &StaleStrategy::Sweep);
        assert!(route.paths.is_empty());
        assert!(alloc.freed.contains(&43));
    }

    #[test]
    fn test_llgr_transition() {
        let mut alloc = FakeAllocator::new();

        // Clean stale path -> tagged with LLGR_STALE
        let mut route_clean = make_route(vec![create_test_path_with(peer_ip(), bgp_id(), |p| {
            p.stale = true;
            p.local_path_id = Some(1);
        })]);
        apply_stale_to_route(
            &mut route_clean,
            peer_ip(),
            &mut alloc,
            &StaleStrategy::TransitionToLlgr,
        );
        assert!(route_clean.paths[0]
            .attrs
            .communities
            .contains(&community::LLGR_STALE));

        // NO_LLGR path -> removed
        let mut route_no_llgr = make_route(vec![create_test_path_with(peer_ip(), bgp_id(), |p| {
            p.stale = true;
            p.local_path_id = Some(2);
            p.attrs_mut().communities.push(community::NO_LLGR);
        })]);
        apply_stale_to_route(
            &mut route_no_llgr,
            peer_ip(),
            &mut alloc,
            &StaleStrategy::TransitionToLlgr,
        );
        assert!(route_no_llgr.paths.is_empty());
        assert!(alloc.freed.contains(&2));

        // Already tagged -> not double-tagged
        let mut route_already = make_route(vec![create_test_path_with(peer_ip(), bgp_id(), |p| {
            p.stale = true;
            p.local_path_id = Some(3);
            p.attrs_mut().communities.push(community::LLGR_STALE);
        })]);
        apply_stale_to_route(
            &mut route_already,
            peer_ip(),
            &mut alloc,
            &StaleStrategy::TransitionToLlgr,
        );
        assert_eq!(
            route_already.paths[0]
                .attrs
                .communities
                .iter()
                .filter(|c| **c == community::LLGR_STALE)
                .count(),
            1
        );
    }

    #[test]
    fn test_no_stale_paths_returns_none() {
        let mut alloc = FakeAllocator::new();
        let mut route = make_route(vec![create_test_path(peer_ip(), bgp_id())]);

        let old_best =
            apply_stale_to_route(&mut route, peer_ip(), &mut alloc, &StaleStrategy::Sweep);
        assert!(old_best.is_none());
        assert_eq!(route.paths.len(), 1);
    }
}
