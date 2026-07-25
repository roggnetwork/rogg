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

pub mod bgp;
pub mod bmp;
pub mod grpc;
pub mod log;
pub mod net;
pub mod peer;
pub mod policy;
pub mod rib;
pub mod rpki;
pub mod server;
pub mod table;
pub mod types;

#[cfg(test)]
pub(crate) mod test_helpers {
    use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, NextHopAddr, Origin};
    use crate::net::{IpNetwork, Ipv4Net};
    use crate::rib::path_id::PathIdAllocator;
    use crate::rib::{Path, PathAttrs, RouteSource};
    use crate::rpki::vrp::RpkiValidation;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    /// Sequential path ID allocator for tests. Starts at 1, increments.
    /// Tracks freed IDs so tests can assert free() was called.
    pub struct FakeAllocator {
        next: u32,
        pub freed: Vec<u32>,
    }

    impl FakeAllocator {
        pub fn new() -> Self {
            Self {
                next: 1,
                freed: Vec::new(),
            }
        }
    }

    impl PathIdAllocator for FakeAllocator {
        fn alloc(&mut self) -> u32 {
            let id = self.next;
            self.next += 1;
            id
        }
        fn free(&mut self, id: u32) {
            self.freed.push(id);
        }
        fn free_all(&mut self, ids: Vec<u32>) {
            self.freed.extend(&ids);
        }
    }

    pub fn create_test_path(peer_ip: IpAddr, bgp_id: Ipv4Addr) -> Arc<Path> {
        Arc::new(Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            rpki_state: RpkiValidation::NotFound,
            attrs: Arc::new(PathAttrs {
                origin: Origin::IGP,
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![100, 200],
                }],
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                source: RouteSource::Ebgp { peer_ip, bgp_id },
                local_pref: Some(100),
                med: Some(0),
                atomic_aggregate: false,
                aggregator: None,
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
                ls_attr: None,
            }),
        })
    }

    pub fn create_test_path_with(
        peer_ip: IpAddr,
        bgp_id: Ipv4Addr,
        f: impl FnOnce(&mut Path),
    ) -> Arc<Path> {
        let mut path = Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            rpki_state: RpkiValidation::NotFound,
            attrs: Arc::new(PathAttrs {
                origin: Origin::IGP,
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![100, 200],
                }],
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                source: RouteSource::Ebgp { peer_ip, bgp_id },
                local_pref: Some(100),
                med: Some(0),
                atomic_aggregate: false,
                aggregator: None,
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
                ls_attr: None,
            }),
        };
        f(&mut path);
        Arc::new(path)
    }

    pub fn create_test_prefix() -> IpNetwork {
        IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        })
    }

    pub fn create_test_prefix_n(i: u8) -> IpNetwork {
        IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, i, 0),
            prefix_length: 24,
        })
    }
}
