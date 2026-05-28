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

use crate::bgp::multiprotocol::{Afi, AfiSafi};
use crate::rib::{Path, Route, RouteKey};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Adj-RIB-Out: Per-peer output routing table
///
/// Tracks routes actually exported to a specific BGP peer.
/// Keyed by RouteKey (IP prefix or BGP-LS NLRI), then by local_path_id.
pub struct AdjRibOut {
    routes: HashMap<RouteKey, HashMap<u32, Arc<Path>>>,
}

impl AdjRibOut {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Insert a route into the adj-rib-out.
    /// The path must have a local_path_id assigned.
    pub fn insert(&mut self, key: RouteKey, path: Arc<Path>) {
        let path_id = path.local_path_id.expect("loc-rib path must have ID");
        self.routes.entry(key).or_default().insert(path_id, path);
    }

    /// Remove a specific path by route key and path_id.
    pub fn remove_path(&mut self, key: &RouteKey, path_id: u32) {
        if let Some(paths) = self.routes.get_mut(key) {
            paths.remove(&path_id);
            if paths.is_empty() {
                self.routes.remove(key);
            }
        }
    }

    /// Remove all entries for a given AFI.
    pub fn clear_afi(&mut self, afi: Afi) {
        self.routes.retain(|key, _| key.afi_safi().afi != afi);
    }

    /// Clear all routes (used on peer disconnect).
    pub fn clear(&mut self) {
        self.routes.clear();
    }

    /// Get all path_ids for a given route key.
    pub fn path_ids(&self, key: &RouteKey) -> Vec<u32> {
        self.routes
            .get(key)
            .map(|paths| paths.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Get paths that are in adj-rib-out but not in the active set.
    /// Used to identify stale routes that need to be withdrawn.
    pub fn stale_paths(&self, key: &RouteKey, active: &[crate::rib::RoutePath]) -> Vec<Arc<Path>> {
        let Some(paths) = self.routes.get(key) else {
            return vec![];
        };

        let active_ids: HashSet<u32> = active
            .iter()
            .filter_map(|rp| rp.path.local_path_id)
            .collect();

        paths
            .iter()
            .filter(|(pid, _)| !active_ids.contains(pid))
            .map(|(_, path)| path.clone())
            .collect()
    }

    /// Get all route keys for a given AFI.
    pub fn keys_for_afi(&self, afi: Afi) -> Vec<RouteKey> {
        self.routes
            .keys()
            .filter(|key| key.afi_safi().afi == afi)
            .cloned()
            .collect()
    }

    /// Get all routes, suitable for gRPC responses.
    pub fn get_routes(&self, afi_safi: Option<AfiSafi>) -> Vec<Route> {
        self.routes
            .iter()
            .filter(|(key, _)| afi_safi.is_none_or(|af| key.afi_safi() == af))
            .map(|(key, paths)| Route {
                key: key.clone(),
                paths: paths.values().cloned().collect(),
            })
            .collect()
    }
}

impl Default for AdjRibOut {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::IpNetwork;
    use crate::test_helpers::create_test_path_with;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_path(path_id: u32) -> Arc<Path> {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let bgp_id = Ipv4Addr::new(1, 1, 1, 1);
        create_test_path_with(peer_ip, bgp_id, |path| {
            path.local_path_id = Some(path_id);
        })
    }

    fn route_key_v4(s: &str) -> RouteKey {
        let prefix: IpNetwork = s.parse().unwrap();
        RouteKey::Prefix(prefix)
    }

    #[test]
    fn test_insert_and_get_routes() {
        let mut rib = AdjRibOut::new();
        let key = route_key_v4("10.0.0.0/24");
        let path = make_path(1);

        rib.insert(key.clone(), path.clone());

        let routes = rib.get_routes(None);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].key, key);
        assert_eq!(routes[0].paths.len(), 1);
    }

    #[test]
    fn test_remove_path() {
        let mut rib = AdjRibOut::new();
        let key = route_key_v4("10.0.0.0/24");
        rib.insert(key.clone(), make_path(1));
        rib.insert(key.clone(), make_path(2));

        rib.remove_path(&key, 1);
        let ids = rib.path_ids(&key);
        assert_eq!(ids, vec![2]);
    }

    #[test]
    fn test_path_ids() {
        let mut rib = AdjRibOut::new();
        let key_a = route_key_v4("10.0.0.0/24");
        let key_b = route_key_v4("10.0.1.0/24");
        rib.insert(key_a.clone(), make_path(1));
        rib.insert(key_a.clone(), make_path(2));
        rib.insert(key_b, make_path(3));

        let mut ids = rib.path_ids(&key_a);
        ids.sort();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    fn test_clear() {
        let mut rib = AdjRibOut::new();
        rib.insert(route_key_v4("10.0.0.0/24"), make_path(1));
        rib.insert(route_key_v4("10.0.1.0/24"), make_path(2));

        rib.clear();
        assert_eq!(rib.get_routes(None).len(), 0);
    }

    #[test]
    fn test_stale_paths() {
        let key = route_key_v4("10.0.0.0/24");

        struct Case {
            name: &'static str,
            in_rib: Vec<u32>,
            active: Vec<u32>,
            expected: Vec<u32>,
        }

        let cases = vec![
            Case {
                name: "key not in rib",
                in_rib: vec![],
                active: vec![],
                expected: vec![],
            },
            Case {
                name: "all paths active",
                in_rib: vec![1, 2],
                active: vec![1, 2],
                expected: vec![],
            },
            Case {
                name: "some paths stale",
                in_rib: vec![1, 2, 3],
                active: vec![2],
                expected: vec![1, 3],
            },
            Case {
                name: "all paths stale",
                in_rib: vec![1, 2],
                active: vec![],
                expected: vec![1, 2],
            },
            Case {
                name: "active has ids not in rib",
                in_rib: vec![1],
                active: vec![1, 99],
                expected: vec![],
            },
        ];

        for tc in cases {
            let mut rib = AdjRibOut::new();
            for id in &tc.in_rib {
                rib.insert(key.clone(), make_path(*id));
            }
            let active: Vec<crate::rib::RoutePath> = tc
                .active
                .iter()
                .map(|id| crate::rib::RoutePath {
                    key: key.clone(),
                    path: make_path(*id),
                })
                .collect();

            let mut stale_ids: Vec<u32> = rib
                .stale_paths(&key, &active)
                .iter()
                .filter_map(|p| p.local_path_id)
                .collect();
            stale_ids.sort_unstable();

            let mut expected = tc.expected.clone();
            expected.sort_unstable();

            assert_eq!(stale_ids, expected, "case: {}", tc.name);
        }
    }

    #[test]
    fn test_clear_afi() {
        let mut rib = AdjRibOut::new();
        rib.insert(route_key_v4("10.0.0.0/24"), make_path(1));
        rib.insert(route_key_v4("10.0.1.0/24"), make_path(2));

        rib.clear_afi(Afi::Ipv4);
        assert_eq!(rib.get_routes(None).len(), 0);

        // Insert new route after clear
        rib.insert(route_key_v4("192.168.0.0/24"), make_path(3));
        assert_eq!(rib.get_routes(None).len(), 1);
    }
}
