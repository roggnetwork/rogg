// Copyright 2025 bgpgg Authors
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

use crate::bgp::bgpls_nlri::LsNlri;
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::net::{IpNetwork, Ipv4Net, Ipv6Net};
use crate::rib::types::RouteKey;
use crate::rib::{Path, Route};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

/// Adj-RIB-In: Per-peer input routing table
///
/// Stores routes received from a specific BGP peer before any import policy
/// or best path selection has been applied.
pub struct AdjRibIn {
    // Per-AFI/SAFI tables
    ipv4_unicast: HashMap<Ipv4Net, Route>,
    ipv6_unicast: HashMap<Ipv6Net, Route>,
    link_state: HashMap<LsNlri, Route>,
}

impl Default for AdjRibIn {
    fn default() -> Self {
        Self::new()
    }
}

impl AdjRibIn {
    pub fn new() -> Self {
        AdjRibIn {
            ipv4_unicast: HashMap::new(),
            ipv6_unicast: HashMap::new(),
            link_state: HashMap::new(),
        }
    }

    pub fn add_route(&mut self, key: RouteKey, path: Arc<Path>) {
        match &key {
            RouteKey::Prefix(prefix) => match prefix {
                IpNetwork::V4(net) => Self::upsert_path(&mut self.ipv4_unicast, *net, key, path),
                IpNetwork::V6(net) => Self::upsert_path(&mut self.ipv6_unicast, *net, key, path),
            },
            RouteKey::LinkState(nlri) => {
                Self::upsert_path(&mut self.link_state, (**nlri).clone(), key, path)
            }
        }
    }

    pub fn remove_route(&mut self, key: &RouteKey, remote_path_id: Option<u32>) {
        match key {
            RouteKey::Prefix(prefix) => match prefix {
                IpNetwork::V4(net) => {
                    Self::remove_path(&mut self.ipv4_unicast, net, remote_path_id)
                }
                IpNetwork::V6(net) => {
                    Self::remove_path(&mut self.ipv6_unicast, net, remote_path_id)
                }
            },
            RouteKey::LinkState(nlri) => {
                Self::remove_path(&mut self.link_state, nlri, remote_path_id)
            }
        }
    }

    pub fn get_route(&self, key: &RouteKey) -> Option<&Route> {
        match key {
            RouteKey::Prefix(prefix) => match prefix {
                IpNetwork::V4(net) => self.ipv4_unicast.get(net),
                IpNetwork::V6(net) => self.ipv6_unicast.get(net),
            },
            RouteKey::LinkState(nlri) => self.link_state.get(nlri),
        }
    }

    pub fn get_routes(&self, afi_safi: Option<AfiSafi>) -> Vec<Route> {
        match afi_safi {
            Some(af) => match (af.afi, af.safi) {
                (Afi::Ipv4, Safi::Unicast) => self.ipv4_unicast.values().cloned().collect(),
                (Afi::Ipv6, Safi::Unicast) => self.ipv6_unicast.values().cloned().collect(),
                (Afi::LinkState, Safi::LinkState | Safi::LinkStateVpn) => {
                    self.link_state.values().cloned().collect()
                }
                _ => vec![],
            },
            None => {
                let mut routes = Vec::new();
                routes.extend(self.ipv4_unicast.values().cloned());
                routes.extend(self.ipv6_unicast.values().cloned());
                routes.extend(self.link_state.values().cloned());
                routes
            }
        }
    }

    pub fn prefix_count(&self) -> usize {
        self.ipv4_unicast.len() + self.ipv6_unicast.len() + self.link_state.len()
    }

    /// Return the route count for a specific address family.
    pub fn family_count(&self, family: &AfiSafi) -> usize {
        match (family.afi, family.safi) {
            (Afi::Ipv4, Safi::Unicast) => self.ipv4_unicast.len(),
            (Afi::Ipv6, Safi::Unicast) => self.ipv6_unicast.len(),
            (Afi::LinkState, Safi::LinkState | Safi::LinkStateVpn) => self.link_state.len(),
            _ => 0,
        }
    }

    pub fn clear(&mut self) {
        self.ipv4_unicast.clear();
        self.ipv6_unicast.clear();
        self.link_state.clear();
    }

    pub fn clear_afi_safi(&mut self, afi_safi: AfiSafi) -> usize {
        match (afi_safi.afi, afi_safi.safi) {
            (Afi::Ipv4, Safi::Unicast) => {
                let count = self.ipv4_unicast.len();
                self.ipv4_unicast.clear();
                count
            }
            (Afi::Ipv6, Safi::Unicast) => {
                let count = self.ipv6_unicast.len();
                self.ipv6_unicast.clear();
                count
            }
            (Afi::LinkState, Safi::LinkState | Safi::LinkStateVpn) => {
                let count = self.link_state.len();
                self.link_state.clear();
                count
            }
            _ => 0,
        }
    }

    /// Drain all routes for a specific AFI/SAFI, returning them as (prefix, path_id) withdrawals.
    pub fn drain_afi_safi(&mut self, afi_safi: AfiSafi) -> Vec<(IpNetwork, Option<u32>)> {
        let table: Box<dyn Iterator<Item = (IpNetwork, Route)>> =
            match (afi_safi.afi, afi_safi.safi) {
                (Afi::Ipv4, Safi::Unicast) => Box::new(
                    self.ipv4_unicast
                        .drain()
                        .map(|(k, v)| (IpNetwork::V4(k), v)),
                ),
                (Afi::Ipv6, Safi::Unicast) => Box::new(
                    self.ipv6_unicast
                        .drain()
                        .map(|(k, v)| (IpNetwork::V6(k), v)),
                ),
                _ => return vec![],
            };

        let mut withdrawals = Vec::new();
        for (prefix, route) in table {
            for path in &route.paths {
                withdrawals.push((prefix, path.remote_path_id));
            }
        }
        withdrawals
    }

    /// Add or replace a path in a table. Matches by remote_path_id.
    fn upsert_path<K: Eq + Hash>(
        table: &mut HashMap<K, Route>,
        key: K,
        route_key: RouteKey,
        path: Arc<Path>,
    ) {
        if let Some(route) = table.get_mut(&key) {
            if let Some(existing) = route
                .paths
                .iter_mut()
                .find(|p| p.remote_path_id == path.remote_path_id)
            {
                *existing = path;
            } else {
                route.paths.push(path);
            }
        } else {
            table.insert(
                key,
                Route {
                    key: route_key,
                    paths: vec![path],
                },
            );
        }
    }

    /// Remove a path by remote_path_id. Removes the Route entry if no paths remain.
    fn remove_path<K: Eq + Hash>(
        table: &mut HashMap<K, Route>,
        key: &K,
        remote_path_id: Option<u32>,
    ) {
        if let Some(route) = table.get_mut(key) {
            route.paths.retain(|p| p.remote_path_id != remote_path_id);
            if route.paths.is_empty() {
                table.remove(key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType};
    use crate::net::Ipv4Net;
    use crate::test_helpers::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_peer_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    }

    fn test_bgp_id() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 1)
    }

    fn prefix_key(prefix: IpNetwork) -> RouteKey {
        RouteKey::Prefix(prefix)
    }

    #[test]
    fn test_new_adj_rib_in() {
        let rib_in = AdjRibIn::new();
        assert_eq!(rib_in.get_routes(None).len(), 0);
    }

    #[test]
    fn test_add_route() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();
        let path = create_test_path(test_peer_ip(), test_bgp_id());

        rib_in.add_route(prefix_key(prefix), path.clone());

        let routes = rib_in.get_routes(None);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].key, RouteKey::Prefix(prefix));
        assert_eq!(routes[0].paths[0].attrs, path.attrs);
    }

    #[test]
    fn test_add_multiple_routes() {
        let peer_ip = test_peer_ip();
        let mut rib_in = AdjRibIn::new();

        let prefix1 = create_test_prefix();
        let prefix2 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 24,
        });

        let path1 = create_test_path(peer_ip, test_bgp_id());
        let path2 = create_test_path(peer_ip, test_bgp_id());

        rib_in.add_route(prefix_key(prefix1), path1.clone());
        rib_in.add_route(prefix_key(prefix2), path2.clone());

        let mut routes = rib_in.get_routes(None);
        routes.sort_by_key(|r| format!("{:?}", r.key));

        let mut expected = [
            Route {
                key: RouteKey::Prefix(prefix1),
                paths: vec![path1],
            },
            Route {
                key: RouteKey::Prefix(prefix2),
                paths: vec![path2],
            },
        ];
        expected.sort_by_key(|r| format!("{:?}", r.key));

        assert_eq!(routes, expected);
    }

    #[test]
    fn test_add_route_overwrite() {
        let peer_ip = test_peer_ip();
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        let path1 = create_test_path(peer_ip, test_bgp_id());
        let path2 = create_test_path_with(peer_ip, test_bgp_id(), |p| {
            p.attrs_mut().as_path = vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 2,
                asn_list: vec![300, 400],
            }];
        });

        rib_in.add_route(prefix_key(prefix), path1);
        rib_in.add_route(prefix_key(prefix), Arc::clone(&path2));

        let routes = rib_in.get_routes(None);
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0].paths[0].as_path(),
            &vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 2,
                asn_list: vec![300, 400],
            }]
        );
    }

    #[test]
    fn test_remove_route() {
        let peer_ip = test_peer_ip();
        let mut rib_in = AdjRibIn::new();
        let prefix1 = create_test_prefix();
        let prefix2 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 24,
        });

        let path1 = create_test_path(peer_ip, test_bgp_id());
        let path2 = create_test_path(peer_ip, test_bgp_id());

        rib_in.add_route(prefix_key(prefix1), path1);
        rib_in.add_route(prefix_key(prefix2), path2.clone());

        rib_in.remove_route(&prefix_key(prefix1), None);

        let routes = rib_in.get_routes(None);
        assert_eq!(routes.len(), 1);
        assert_eq!(
            routes[0],
            Route {
                key: RouteKey::Prefix(prefix2),
                paths: vec![path2]
            }
        );
    }

    #[test]
    fn test_remove_nonexistent_route() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        rib_in.remove_route(&prefix_key(prefix), None);
        assert_eq!(rib_in.get_routes(None).len(), 0);
    }

    #[test]
    fn test_clear_afi_safi() {
        use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};

        let peer_ip = test_peer_ip();
        let mut rib_in = AdjRibIn::new();

        let ipv4_prefix = create_test_prefix();
        let ipv6_prefix = IpNetwork::V6(crate::net::Ipv6Net {
            address: std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            prefix_length: 64,
        });

        rib_in.add_route(
            prefix_key(ipv4_prefix),
            create_test_path(peer_ip, test_bgp_id()),
        );
        rib_in.add_route(
            prefix_key(ipv6_prefix),
            create_test_path(peer_ip, test_bgp_id()),
        );

        assert_eq!(rib_in.prefix_count(), 2);

        let count = rib_in.clear_afi_safi(AfiSafi::new(Afi::Ipv4, Safi::Unicast));
        assert_eq!(count, 1);
        assert_eq!(rib_in.prefix_count(), 1);

        let count = rib_in.clear_afi_safi(AfiSafi::new(Afi::Ipv6, Safi::Unicast));
        assert_eq!(count, 1);
        assert_eq!(rib_in.prefix_count(), 0);

        let count = rib_in.clear_afi_safi(AfiSafi::new(Afi::Ipv4, Safi::Unicast));
        assert_eq!(count, 0);
    }

    #[test]
    fn test_clear() {
        let peer_ip = test_peer_ip();
        let mut rib_in = AdjRibIn::new();

        rib_in.add_route(
            prefix_key(create_test_prefix()),
            create_test_path(peer_ip, test_bgp_id()),
        );
        rib_in.add_route(
            prefix_key(IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 1, 0, 0),
                prefix_length: 24,
            })),
            create_test_path(peer_ip, test_bgp_id()),
        );

        assert_eq!(rib_in.get_routes(None).len(), 2);

        rib_in.clear();
        assert_eq!(rib_in.get_routes(None).len(), 0);
    }

    #[test]
    fn test_addpath_multiple_paths_coexist() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        let path1 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
        });
        let path2 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(2);
            p.attrs_mut().as_path = vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 3,
                asn_list: vec![100, 200, 300],
            }];
        });

        rib_in.add_route(prefix_key(prefix), path1);
        rib_in.add_route(prefix_key(prefix), path2);

        let routes = rib_in.get_routes(None);
        assert_eq!(routes.len(), 1, "same prefix should be one Route");
        assert_eq!(routes[0].paths.len(), 2, "two paths should coexist");
    }

    #[test]
    fn test_addpath_replace_by_remote_path_id() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        let path1 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
            p.attrs_mut().med = Some(10);
        });
        let path1_updated = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
            p.attrs_mut().med = Some(20);
        });

        rib_in.add_route(prefix_key(prefix), path1);
        rib_in.add_route(prefix_key(prefix), path1_updated);

        let routes = rib_in.get_routes(None);
        assert_eq!(routes[0].paths.len(), 1, "same path_id should replace");
        assert_eq!(routes[0].paths[0].med(), Some(20));
    }

    #[test]
    fn test_addpath_withdraw_one_path() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        let path1 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
        });
        let path2 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(2);
        });

        rib_in.add_route(prefix_key(prefix), path1);
        rib_in.add_route(prefix_key(prefix), path2);
        assert_eq!(rib_in.get_routes(None)[0].paths.len(), 2);

        rib_in.remove_route(&prefix_key(prefix), Some(1));
        let routes = rib_in.get_routes(None);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].paths.len(), 1);
        assert_eq!(routes[0].paths[0].remote_path_id, Some(2));
    }

    #[test]
    fn test_addpath_withdraw_all_removes_entry() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        let path1 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.remote_path_id = Some(1);
        });

        rib_in.add_route(prefix_key(prefix), path1);
        rib_in.remove_route(&prefix_key(prefix), Some(1));

        assert_eq!(rib_in.prefix_count(), 0, "entry should be removed");
    }

    #[test]
    fn test_non_addpath() {
        let mut rib_in = AdjRibIn::new();
        let prefix = create_test_prefix();

        let path1 = create_test_path(test_peer_ip(), test_bgp_id());
        let path2 = create_test_path_with(test_peer_ip(), test_bgp_id(), |p| {
            p.attrs_mut().med = Some(50);
        });

        rib_in.add_route(prefix_key(prefix), path1);
        rib_in.add_route(prefix_key(prefix), path2);

        let routes = rib_in.get_routes(None);
        assert_eq!(routes[0].paths.len(), 1);
        assert_eq!(routes[0].paths[0].med(), Some(50));

        rib_in.remove_route(&prefix_key(prefix), None);
        assert_eq!(rib_in.prefix_count(), 0);
    }

    #[test]
    fn test_family_count() {
        use crate::bgp::bgpls_nlri::{
            build_ls_nlri, LsDescriptors, LsNlriType, LsProtocolId, NodeDescriptor,
        };

        let mut rib_in = AdjRibIn::new();

        // Add IPv4 route
        let prefix = create_test_prefix();
        let path = create_test_path(test_peer_ip(), test_bgp_id());
        rib_in.add_route(prefix_key(prefix), path);

        // Add LS route
        let nlri = build_ls_nlri(
            LsNlriType::Node,
            LsProtocolId::IsIsL1,
            0,
            LsDescriptors::Node {
                local_node: NodeDescriptor {
                    igp_router_id: Some(vec![1]),
                    ..NodeDescriptor::default()
                },
            },
            None,
        );
        let ls_path = create_test_path(test_peer_ip(), test_bgp_id());
        rib_in.add_route(RouteKey::LinkState(Box::new(nlri)), ls_path);

        let cases = vec![
            (Afi::Ipv4, Safi::Unicast, 1),
            (Afi::Ipv6, Safi::Unicast, 0),
            (Afi::LinkState, Safi::LinkState, 1),
        ];
        for (afi, safi, expected) in cases {
            let family = AfiSafi::new(afi, safi);
            assert_eq!(rib_in.family_count(&family), expected, "family={family}");
        }
        assert_eq!(rib_in.prefix_count(), 2);
    }
}
