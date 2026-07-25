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

//! Policy integration tests - test actual route filtering behavior

mod utils;
pub use utils::*;

use std::net::Ipv4Addr;

use bgpgg::bgp::community;
use bgpgg::bgp::ext_community::from_rpki_state_community;
use bgpgg::grpc::proto::{
    add_route_request, defined_set_config,
    extended_community::{Community, Opaque},
    ActionsConfig, AddLsRouteRequest, AddRouteRequest, ConditionsConfig, DefinedSetConfig,
    ExtendedCommunity, ExtendedCommunitySetData, ListRoutesRequest, LsAttribute, LsNlri,
    LsNlriType, LsNodeAttribute, LsNodeDescriptor, LsProtocolId, MatchSetRef, RibType, Route,
    RpkiValidation, StatementConfig,
};
use bgpgg::net::{IpNetwork, Ipv4Net};
use bgpgg::rpki::vrp::{RpkiValidation as RpkiState, Vrp};
use conf::bgp::{Afi, BgpConfig, RpkiCacheConfig, Safi};
use utils::rtr::FakeTcpCache;

#[tokio::test]
async fn test_export_policy_prefix_match() {
    struct TestCase {
        desc: &'static str,
        blocked_prefixes: Vec<(&'static str, Option<&'static str>)>,
        announced: Vec<&'static str>,
        expected: Vec<&'static str>,
    }

    let cases = vec![
        TestCase {
            desc: "block single exact prefix",
            blocked_prefixes: vec![("10.1.0.0/24", None)],
            announced: vec!["10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24"],
            expected: vec!["10.0.0.0/24", "10.2.0.0/24"],
        },
        TestCase {
            desc: "block multiple prefixes",
            blocked_prefixes: vec![("10.1.0.0/24", None), ("10.2.0.0/24", None)],
            announced: vec!["10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24"],
            expected: vec!["10.0.0.0/24"],
        },
        TestCase {
            desc: "block with length range",
            blocked_prefixes: vec![("10.0.0.0/8", Some("24..32"))],
            announced: vec!["10.0.0.0/8", "10.1.0.0/24", "10.2.0.0/25"],
            expected: vec!["10.0.0.0/8"],
        },
    ];

    for tc in cases {
        let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

        // Apply export policy on server2
        apply_export_prefix_reject_policy(
            &server2,
            &server1.address.to_string(),
            "blocked",
            tc.blocked_prefixes,
        )
        .await;

        // Announce all routes
        for (i, prefix) in tc.announced.iter().enumerate() {
            announce_route(
                &server2,
                RouteParams::Ip(Box::new(IpRouteParams {
                    prefix: prefix.to_string(),
                    next_hop: format!("192.168.1.{}", i + 1),
                    ..Default::default()
                })),
            )
            .await;
        }

        // Build expected routes
        let peers = server1.client.get_peers().await.unwrap();
        let peer_addr = &peers[0].address;
        let expected: Vec<Route> = tc
            .expected
            .iter()
            .map(|prefix| {
                expected_route(
                    prefix,
                    PathParams {
                        peer_address: peer_addr.clone(),
                        ..PathParams::from_peer(&server2)
                    },
                )
            })
            .collect();

        // Verify routes propagate and stay stable
        poll_until_stable(
            || async {
                let routes = server1
                    .client
                    .list_routes(ListRoutesRequest::default())
                    .await
                    .unwrap();
                routes_match(&routes, &expected, ExpectPathId::Present)
            },
            Duration::from_millis(500),
            &format!("Test case failed: {}", tc.desc),
        )
        .await;
    }
}

#[tokio::test]
async fn test_export_policy_large_community_match() {
    use bgpgg::bgp::msg_update_types::LargeCommunity;
    use bgpgg::grpc::proto::{self, defined_set_config};

    let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

    // Add large-community-set
    server2
        .client
        .add_defined_set(
            DefinedSetConfig {
                set_type: "large-community-set".to_string(),
                name: "blocked-lcs".to_string(),
                config: Some(defined_set_config::Config::LargeCommunitySet(
                    proto::LargeCommunitySetData {
                        large_communities: vec![
                            "65536:100:200".to_string(),
                            "4200000000:1:2".to_string(),
                        ],
                    },
                )),
            },
            false,
        )
        .await
        .unwrap();

    // Create policy: reject routes with matching large communities
    server2
        .client
        .add_policy(
            "export-policy".to_string(),
            vec![
                StatementConfig {
                    conditions: Some(ConditionsConfig {
                        match_large_community_set: Some(proto::MatchSetRef {
                            set_name: "blocked-lcs".to_string(),
                            match_option: "any".to_string(),
                        }),
                        ..Default::default()
                    }),
                    actions: Some(ActionsConfig {
                        reject: Some(true),
                        ..Default::default()
                    }),
                },
                StatementConfig {
                    conditions: None,
                    actions: Some(ActionsConfig {
                        accept: Some(true),
                        ..Default::default()
                    }),
                },
            ],
        )
        .await
        .unwrap();

    // Assign to peer
    server2
        .client
        .set_policy_assignment(
            server1.address.to_string(),
            Afi::Ipv4 as u32,
            Safi::Unicast as u32,
            "export".to_string(),
            vec!["export-policy".to_string()],
            None,
        )
        .await
        .unwrap();

    // Announce route with blocked large community (should be rejected)
    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            large_communities: vec![LargeCommunity::new(65536, 100, 200)],
            ..Default::default()
        })),
    )
    .await;

    // Announce route with different large community (should propagate)
    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.2.0.0/24".to_string(),
            next_hop: "192.168.1.2".to_string(),
            large_communities: vec![LargeCommunity::new(65536, 999, 999)],
            ..Default::default()
        })),
    )
    .await;

    // Announce route with no large communities (should propagate)
    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.3.0.0/24".to_string(),
            next_hop: "192.168.1.3".to_string(),
            ..Default::default()
        })),
    )
    .await;

    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    let expected = vec![
        expected_route(
            "10.2.0.0/24",
            PathParams {
                large_communities: vec![proto::LargeCommunity {
                    global_admin: 65536,
                    local_data_1: 999,
                    local_data_2: 999,
                }],
                peer_address: peer_addr.clone(),
                ..PathParams::from_peer(&server2)
            },
        ),
        expected_route(
            "10.3.0.0/24",
            PathParams {
                peer_address: peer_addr.clone(),
                ..PathParams::from_peer(&server2)
            },
        ),
    ];

    poll_until_stable(
        || async {
            let routes = server1
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .unwrap();
            routes_match(&routes, &expected, ExpectPathId::Present)
        },
        Duration::from_millis(500),
        "Routes with blocked large communities should be rejected",
    )
    .await;
}

#[tokio::test]
async fn test_export_policy_ext_community_match() {
    use bgpgg::grpc::proto::{self, defined_set_config};

    let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

    // Add ext-community-set
    server2
        .client
        .add_defined_set(
            DefinedSetConfig {
                set_type: "ext-community-set".to_string(),
                name: "blocked-ecs".to_string(),
                config: Some(defined_set_config::Config::ExtCommunitySet(
                    proto::ExtendedCommunitySetData {
                        ext_communities: vec![
                            "rt:65000:100".to_string(),
                            "rt:192.168.1.1:200".to_string(),
                        ],
                    },
                )),
            },
            false,
        )
        .await
        .unwrap();

    // Create policy: reject routes with matching extended communities
    server2
        .client
        .add_policy(
            "export-policy".to_string(),
            vec![
                StatementConfig {
                    conditions: Some(ConditionsConfig {
                        match_ext_community_set: Some(proto::MatchSetRef {
                            set_name: "blocked-ecs".to_string(),
                            match_option: "any".to_string(),
                        }),
                        ..Default::default()
                    }),
                    actions: Some(ActionsConfig {
                        reject: Some(true),
                        ..Default::default()
                    }),
                },
                StatementConfig {
                    conditions: None,
                    actions: Some(ActionsConfig {
                        accept: Some(true),
                        ..Default::default()
                    }),
                },
            ],
        )
        .await
        .unwrap();

    // Assign to peer
    server2
        .client
        .set_policy_assignment(
            server1.address.to_string(),
            Afi::Ipv4 as u32,
            Safi::Unicast as u32,
            "export".to_string(),
            vec!["export-policy".to_string()],
            None,
        )
        .await
        .unwrap();

    // Announce route with blocked ext community (should be rejected)
    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            extended_communities: vec![0x0002FDE800000064u64], // rt:65000:100
            ..Default::default()
        })),
    )
    .await;

    // Announce route with different ext community (should propagate)
    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.2.0.0/24".to_string(),
            next_hop: "192.168.1.2".to_string(),
            extended_communities: vec![0x0002FDE8000003E7u64], // rt:65000:999
            ..Default::default()
        })),
    )
    .await;

    // Announce route with no ext communities (should propagate)
    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.3.0.0/24".to_string(),
            next_hop: "192.168.1.3".to_string(),
            ..Default::default()
        })),
    )
    .await;

    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;

    let expected = vec![
        expected_route(
            "10.2.0.0/24",
            PathParams {
                extended_communities: vec![proto::ExtendedCommunity {
                    community: Some(proto::extended_community::Community::TwoOctetAs(
                        proto::extended_community::TwoOctetAsSpecific {
                            is_transitive: true,
                            sub_type: 0x02,
                            asn: 65000,
                            local_admin: 999,
                        },
                    )),
                }],
                peer_address: peer_addr.clone(),
                ..PathParams::from_peer(&server2)
            },
        ),
        expected_route(
            "10.3.0.0/24",
            PathParams {
                peer_address: peer_addr.clone(),
                ..PathParams::from_peer(&server2)
            },
        ),
    ];

    poll_until_stable(
        || async {
            let routes = server1
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .unwrap();
            routes_match(&routes, &expected, ExpectPathId::Present)
        },
        Duration::from_millis(500),
        "Routes with blocked extended communities should be rejected",
    )
    .await;
}

/// Import policy matching on RPKI validation state:
/// - Reject Invalid routes
/// - Accept Valid and NotFound routes
#[tokio::test]
async fn test_import_policy_rpki_validation() {
    let mut cache = FakeTcpCache::listen().await;

    // server2 (AS 65002) -> server1 (AS 65001, with RPKI cache)
    let server1 = start_test_server(BgpConfig {
        asn: 65001,
        listen_addr: "127.0.0.1:0".to_string(),
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        rpki_caches: vec![RpkiCacheConfig {
            address: cache.address(),
            ..Default::default()
        }],
        ..Default::default()
    })
    .await;

    let server2 = start_test_server(BgpConfig::new(
        65002,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
    ))
    .await;

    let [server2, server1] = chain_servers([server2, server1], PeerConfig::default()).await;

    // Accept RPKI cache connection and provide VRPs
    cache.accept().await;
    cache.read_reset_query().await;

    // VRP 1: 10.0.0.0/8 max /24 AS 65002 -> 10.0.0.0/24 from AS 65002 is Valid
    // VRP 2: 172.16.0.0/12 max /24 AS 65099 -> 172.16.0.0/24 from AS 65002 is Invalid
    cache
        .send_vrps(&[
            Vrp {
                prefix: IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(10, 0, 0, 0),
                    prefix_length: 8,
                }),
                max_length: 24,
                origin_as: 65002,
            },
            Vrp {
                prefix: IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(172, 16, 0, 0),
                    prefix_length: 12,
                }),
                max_length: 24,
                origin_as: 65099,
            },
        ])
        .await;

    // Apply import policy on server1 for the peer from server2:
    // Statement 1: rpki-validation=invalid -> reject
    // Statement 2: rpki-validation=valid -> tag with community 65001:1, accept
    // Statement 3: rpki-validation=not-found -> tag with community 65001:2, accept
    let peer_addr = server2.address.to_string();
    server1
        .client
        .add_policy(
            "rpki-filter".to_string(),
            vec![
                StatementConfig {
                    conditions: Some(ConditionsConfig {
                        rpki_validation: Some(RpkiValidation::RpkiInvalid.into()),
                        ..Default::default()
                    }),
                    actions: Some(ActionsConfig {
                        reject: Some(true),
                        ..Default::default()
                    }),
                },
                StatementConfig {
                    conditions: Some(ConditionsConfig {
                        rpki_validation: Some(RpkiValidation::RpkiValid.into()),
                        ..Default::default()
                    }),
                    actions: Some(ActionsConfig {
                        accept: Some(true),
                        add_communities: vec!["65001:1".to_string()],
                        ..Default::default()
                    }),
                },
                StatementConfig {
                    conditions: Some(ConditionsConfig {
                        rpki_validation: Some(RpkiValidation::RpkiNotFound.into()),
                        ..Default::default()
                    }),
                    actions: Some(ActionsConfig {
                        accept: Some(true),
                        add_communities: vec!["65001:2".to_string()],
                        ..Default::default()
                    }),
                },
            ],
        )
        .await
        .unwrap();

    server1
        .client
        .set_policy_assignment(
            peer_addr.clone(),
            Afi::Ipv4 as u32,
            Safi::Unicast as u32,
            "import".to_string(),
            vec!["rpki-filter".to_string()],
            None,
        )
        .await
        .unwrap();

    // Announce routes from server2
    for prefix in ["10.0.0.0/24", "172.16.0.0/24", "192.168.1.0/24"] {
        announce_route(
            &server2,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: prefix.to_string(),
                next_hop: server2.address.to_string(),
                ..Default::default()
            })),
        )
        .await;
    }

    // Expected on server1:
    // - 10.0.0.0/24: Valid -> accepted with community 65001:1
    // - 172.16.0.0/24: Invalid -> rejected (absent)
    // - 192.168.1.0/24: NotFound -> accepted with community 65001:2
    let comm_valid = community::from_asn_value(65001, 1);
    let comm_not_found = community::from_asn_value(65001, 2);
    poll_rib(&[(
        &server1,
        vec![
            expected_route(
                "10.0.0.0/24",
                PathParams {
                    rpki_validation: RpkiValidation::RpkiValid as i32,
                    communities: vec![comm_valid],
                    ..PathParams::from_peer(&server2)
                },
            ),
            expected_route(
                "192.168.1.0/24",
                PathParams {
                    rpki_validation: RpkiValidation::RpkiNotFound as i32,
                    communities: vec![comm_not_found],
                    ..PathParams::from_peer(&server2)
                },
            ),
        ],
    )])
    .await;
}

fn rpki_state_ext_community(state: RpkiState) -> ExtendedCommunity {
    let ec = from_rpki_state_community(state.to_u8());
    let bytes = ec.to_be_bytes();
    ExtendedCommunity {
        community: Some(Community::Opaque(Opaque {
            is_transitive: false,
            value: bytes[2..].to_vec(),
        })),
    }
}

/// RFC 8097: SetRpkiState policy action sets rpki_state from matched RPKI state community.
/// Topology: server1 (AS 65001) -> server2 (AS 65001, iBGP with import policy)
/// server1 sends route with RPKI state community, server2 import policy matches and sets rpki_state.
#[tokio::test]
async fn test_rpki_state_community_set_policy() {
    let server1 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;
    let server2 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
    ))
    .await;
    let [server1, server2] = chain_servers([server1, server2], PeerConfig::default()).await;

    // Define ext community set for RPKI state valid
    let rpki_valid_ec = from_rpki_state_community(0);
    server2
        .client
        .add_defined_set(
            DefinedSetConfig {
                set_type: "ext-community".to_string(),
                name: "rpki-valid".to_string(),
                config: Some(defined_set_config::Config::ExtCommunitySet(
                    ExtendedCommunitySetData {
                        ext_communities: vec![format!("0x{:016x}", rpki_valid_ec)],
                    },
                )),
            },
            false,
        )
        .await
        .unwrap();

    // Import policy: match RPKI state valid community -> set rpki_state to valid
    server2
        .client
        .add_policy(
            "rpki-import".to_string(),
            vec![
                StatementConfig {
                    conditions: Some(ConditionsConfig {
                        match_ext_community_set: Some(MatchSetRef {
                            set_name: "rpki-valid".to_string(),
                            match_option: String::new(),
                        }),
                        ..Default::default()
                    }),
                    actions: Some(ActionsConfig {
                        set_rpki_state: Some(RpkiValidation::RpkiValid.into()),
                        accept: Some(true),
                        ..Default::default()
                    }),
                },
                StatementConfig {
                    conditions: None,
                    actions: Some(ActionsConfig {
                        accept: Some(true),
                        ..Default::default()
                    }),
                },
            ],
        )
        .await
        .unwrap();

    let peer_addr = server1.address.to_string();
    server2
        .client
        .set_policy_assignment(
            peer_addr,
            Afi::Ipv4 as u32,
            Safi::Unicast as u32,
            "import".to_string(),
            vec!["rpki-import".to_string()],
            None,
        )
        .await
        .unwrap();

    // Announce route from server1 with RPKI state valid community
    announce_route(
        &server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: server1.address.to_string(),
            extended_communities: vec![rpki_valid_ec],
            ..Default::default()
        })),
    )
    .await;

    // server2 should have rpki_state=valid from policy
    poll_rib(&[(
        &server2,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![],
                next_hop: server1.address.to_string(),
                peer_address: server1.address.to_string(),
                local_pref: Some(100),
                rpki_validation: RpkiValidation::RpkiValid as i32,
                extended_communities: vec![rpki_state_ext_community(RpkiState::Valid)],
                ..Default::default()
            },
        )],
    )])
    .await;
}

fn make_ls_node_nlri(as_number: u32, router_id: &[u8]) -> LsNlri {
    LsNlri {
        nlri_type: LsNlriType::LsNode as i32,
        protocol_id: LsProtocolId::LsDirect as i32,
        local_node: Some(LsNodeDescriptor {
            as_number: Some(as_number),
            igp_router_id: router_id.to_vec(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn make_ls_attr(name: &str) -> LsAttribute {
    LsAttribute {
        node: Some(LsNodeAttribute {
            name: Some(name.to_string()),
            ipv4_router_id: Some("10.0.0.1".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn ls_peer_config() -> PeerConfig {
    PeerConfig {
        afi_safis: vec![afi_safi_ipv4_unicast(), afi_safi_link_state()],
        ..Default::default()
    }
}

/// Add a reject-bgp-ls policy to server for the given peer and direction.
async fn apply_afi_safi_reject_policy(server: &TestServer, peer_addr: &str, direction: &str) {
    server
        .client
        .add_policy(
            "ls-deny".to_string(),
            vec![
                StatementConfig {
                    conditions: Some(ConditionsConfig {
                        afi_safi: Some("bgp-ls".to_string()),
                        ..Default::default()
                    }),
                    actions: Some(ActionsConfig {
                        reject: Some(true),
                        ..Default::default()
                    }),
                },
                StatementConfig {
                    conditions: None,
                    actions: Some(ActionsConfig {
                        accept: Some(true),
                        ..Default::default()
                    }),
                },
            ],
        )
        .await
        .unwrap();

    // Attach the deny policy to the BGP-LS family on the peer. With per-AF
    // runtime attachment, only BGP-LS routes traverse this policy; IP routes
    // see only the implicit RFC 8212 fallback (accept-all on iBGP, the
    // session type used by `setup_two_peered_servers`).
    server
        .client
        .set_policy_assignment(
            peer_addr.to_string(),
            Afi::LinkState as u32,
            Safi::LinkState as u32,
            direction.to_string(),
            vec!["ls-deny".to_string()],
            None,
        )
        .await
        .unwrap();
}

/// Import deny on afi-safi bgp-ls: LS route rejected, IP routes accepted on same session.
#[tokio::test]
async fn test_import_policy_deny_bgp_ls() {
    let (server1, server2) = setup_two_peered_servers(ls_peer_config()).await;

    // server1 rejects BGP-LS on import from server2
    apply_afi_safi_reject_policy(&server1, &server2.address.to_string(), "import").await;

    // server2 originates an IP route and an LS route
    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: server2.address.to_string(),
            ..Default::default()
        })),
    )
    .await;

    server2
        .client
        .add_route(AddRouteRequest {
            route: Some(add_route_request::Route::Ls(Box::new(AddLsRouteRequest {
                nlri: Some(make_ls_node_nlri(65002, &[10, 0, 0, 2])),
                attribute: Some(make_ls_attr("router2")),
                next_hop: None,
            }))),
        })
        .await
        .unwrap();

    // IP route should arrive at server1
    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;
    poll_rib(&[(
        &server1,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                peer_address: peer_addr.clone(),
                ..PathParams::from_peer(&server2)
            },
        )],
    )])
    .await;

    // LS route should NOT be in server1's RIB (rejected by import policy)
    let ls_routes = server1
        .client
        .list_routes(ListRoutesRequest {
            afi: Some(16388),
            safi: Some(71),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        ls_routes.is_empty(),
        "expected no LS routes on server1 (import deny), got {}",
        ls_routes.len()
    );
}

/// Export deny on afi-safi bgp-ls: LS route not propagated to peer.
#[tokio::test]
async fn test_export_policy_deny_bgp_ls() {
    let (server1, server2) = setup_two_peered_servers(ls_peer_config()).await;

    // server2 rejects BGP-LS on export to server1
    apply_afi_safi_reject_policy(&server2, &server1.address.to_string(), "export").await;

    // server2 originates an IP route and an LS route
    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: server2.address.to_string(),
            ..Default::default()
        })),
    )
    .await;

    server2
        .client
        .add_route(AddRouteRequest {
            route: Some(add_route_request::Route::Ls(Box::new(AddLsRouteRequest {
                nlri: Some(make_ls_node_nlri(65002, &[10, 0, 0, 2])),
                attribute: Some(make_ls_attr("router2")),
                next_hop: None,
            }))),
        })
        .await
        .unwrap();

    // IP route should arrive at server1
    let peers = server1.client.get_peers().await.unwrap();
    let peer_addr = &peers[0].address;
    poll_rib(&[(
        &server1,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                peer_address: peer_addr.clone(),
                ..PathParams::from_peer(&server2)
            },
        )],
    )])
    .await;

    // LS route should NOT be in server2's adj-rib-out toward server1
    let adj_out_ls = server2
        .client
        .list_routes(ListRoutesRequest {
            rib_type: Some(RibType::AdjOut as i32),
            peer_address: Some(server1.address.to_string()),
            afi: Some(16388),
            safi: Some(71),
        })
        .await
        .unwrap();
    assert!(
        adj_out_ls.is_empty(),
        "expected no LS routes in server2 adj-rib-out (export deny), got {}",
        adj_out_ls.len()
    );

    // And also not in server1's RIB
    let ls_routes = server1
        .client
        .list_routes(ListRoutesRequest {
            afi: Some(16388),
            safi: Some(71),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        ls_routes.is_empty(),
        "expected no LS routes on server1 (export deny), got {}",
        ls_routes.len()
    );
}

/// RFC 8212: hub announces a route. eBGP spoke (no policy) should not receive it.
/// iBGP spoke (no policy, accept-all fallback) should receive it.
///
/// No accept-all policies applied — testing raw RFC 8212 defaults.
#[tokio::test]
async fn test_default_export_policy() {
    let (hub, [ebgp_spoke, ibgp_spoke]) =
        setup_hub_spoke_servers(65001, [65002, 65001], PeerConfig::default()).await;

    announce_route(
        &hub,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Hub's adj-rib-out toward iBGP spoke should have the route (accept-all fallback)
    poll_until(
        || async { has_adj_out_route(&hub, &ibgp_spoke, "10.0.0.0/24").await },
        "hub adj-rib-out toward iBGP spoke should contain the route",
    )
    .await;

    // Hub's adj-rib-out toward eBGP spoke should be empty (reject-all fallback, RFC 8212)
    poll_while(
        || async { !has_adj_out_route(&hub, &ebgp_spoke, "10.0.0.0/24").await },
        Duration::from_millis(500),
        "hub adj-rib-out toward eBGP spoke should be empty (RFC 8212)",
    )
    .await;
}

/// RFC 8212: spoke announces a route. Hub should accept from iBGP spoke (accept-all fallback)
/// but reject from eBGP spoke (reject-all fallback).
#[tokio::test]
async fn test_default_import_policy() {
    let (hub, [ebgp_spoke, ibgp_spoke]) =
        setup_hub_spoke_servers(65001, [65002, 65001], PeerConfig::default()).await;

    // eBGP spoke needs explicit export policy to send routes (its default is reject-all).
    apply_export_accept_all(&ebgp_spoke, &hub.address.to_string()).await;

    // Both spokes announce a route
    announce_route(
        &ebgp_spoke,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.2.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    announce_route(
        &ibgp_spoke,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.2.0.0/24".to_string(),
            next_hop: "192.168.3.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Hub should have iBGP spoke's route (accept-all import fallback)
    poll_until(
        || async { has_route(&hub, "10.2.0.0/24").await },
        "hub should accept iBGP spoke's route (accept-all import fallback)",
    )
    .await;

    // Hub should NOT have eBGP spoke's route (reject-all import, RFC 8212)
    poll_while(
        || async { !has_route(&hub, "10.1.0.0/24").await },
        Duration::from_millis(500),
        "eBGP spoke route should be rejected by default import policy (RFC 8212)",
    )
    .await;
}
