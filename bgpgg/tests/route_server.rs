// Copyright 2026 bgpgg Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Route Server tests (RFC 7947)

mod utils;
pub use utils::*;

use bgpgg::bgp::community::{self, NO_ADVERTISE, NO_EXPORT, NO_EXPORT_SUBCONFED};
use bgpgg::bgp::ext_community::*;
use bgpgg::bgp::msg_update::{attr_flags, attr_type_code};
use bgpgg::bgp::msg_update_types::LargeCommunity as BgpLargeCommunity;
use bgpgg::grpc::proto::{
    self as proto,
    extended_community::{Community, TwoOctetAsSpecific},
    route, AddPathSendMode, BgpState, ExtendedCommunity, ListRoutesRequest, Origin, Route,
    SessionConfig, UnknownAttribute,
};
use std::net::Ipv4Addr;

/// Helper to configure a server as a route server (eBGP)
async fn setup_route_server(rs: &TestServer, clients: Vec<&TestServer>) {
    setup_rs(rs, clients, Default::default(), Default::default()).await;
}

/// Helper to configure a route server with ADD-PATH send enabled for all clients.
async fn setup_route_server_addpath(rs: &TestServer, clients: Vec<&TestServer>) {
    setup_rs(
        rs,
        clients,
        SessionConfig {
            add_path_send: Some(AddPathSendMode::AddPathSendAll.into()),
            ..Default::default()
        },
        SessionConfig {
            add_path_receive: Some(true),
            ..Default::default()
        },
    )
    .await;
}

async fn setup_rs(
    rs: &TestServer,
    clients: Vec<&TestServer>,
    rs_config: SessionConfig,
    client_config: SessionConfig,
) {
    for client in &clients {
        rs.add_peer_with_config(
            client,
            SessionConfig {
                rs_client: Some(true),
                asn: Some(client.asn),
                ..rs_config.clone()
            },
        )
        .await;
        client
            .add_peer_with_config(
                rs,
                SessionConfig {
                    enforce_first_as: Some(false),
                    ..client_config.clone()
                },
            )
            .await;

        // RFC 8212: eBGP peers need explicit accept-all policies
        if rs.asn != client.asn {
            apply_permit_all_routes(rs, client).await;
        }
    }

    let expected: Vec<_> = clients
        .iter()
        .map(|c| c.to_peer(BgpState::Established))
        .collect();
    poll_until(
        || async { verify_peers(rs, expected.clone()).await },
        "Waiting for route server peerings to establish",
    )
    .await;

    for client in clients {
        poll_until(
            || async { verify_peers(client, vec![rs.to_peer(BgpState::Established)]).await },
            "Waiting for client to establish with RS",
        )
        .await;
    }
}

/// RFC 7947 Section 2.3.2.1: Route servers with ADD-PATH send all paths to clients.
/// This prevents path hiding and allows clients to make their own filtering decisions.
#[tokio::test]
async fn test_rs_addpath_no_path_hiding() {
    let client1 = start_test_server(test_config(65001, 1)).await;
    let client2 = start_test_server(test_config(65002, 2)).await;
    let rs = start_test_server(test_config(65000, 3)).await;
    let client3 = start_test_server(test_config(65003, 4)).await;

    setup_route_server_addpath(&rs, vec![&client1, &client2, &client3]).await;

    // Client1 announces 10.0.0.0/24
    announce_route(
        &client1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client1.address.to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Client2 announces same prefix
    announce_route(
        &client2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client2.address.to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Client3 should receive BOTH paths (no path hiding!)
    poll_rib(&[(
        &client3,
        vec![Route {
            paths: vec![
                build_path(PathParams {
                    next_hop: client1.address.to_string(),
                    peer_address: rs.address.to_string(),
                    as_path: vec![as_sequence(vec![65001])],
                    local_pref: Some(100),
                    ..Default::default()
                }),
                build_path(PathParams {
                    next_hop: client2.address.to_string(),
                    peer_address: rs.address.to_string(),
                    as_path: vec![as_sequence(vec![65002])],
                    local_pref: Some(100),
                    ..Default::default()
                }),
            ],
            key: Some(route::Key::Prefix("10.0.0.0/24".to_string())),
        }],
    )])
    .await;
}

/// RFC 7947 Section 2.3.2: when RS-side export policy blocks the best path for a client,
/// route iteration tries the next path rather than sending nothing.
///
/// Topology: Client1(65001) ──┐
///           Client2(65002) ──┤── RS(65000) ── Client3(65003)
#[tokio::test]
async fn test_rs_no_add_path_no_path_hiding() {
    let client1 = start_test_server(test_config(65001, 1)).await;
    let client2 = start_test_server(test_config(65002, 2)).await;
    let rs = start_test_server(test_config(65000, 3)).await;
    let client3 = start_test_server(test_config(65003, 4)).await;

    setup_route_server(&rs, vec![&client1, &client2, &client3]).await;

    apply_export_neighbor_reject_policy(
        &rs,
        &client3.address.to_string(),
        "reject-client1",
        &client1.address.to_string(),
    )
    .await;

    // Client1 (IGP origin) is preferred over Client2 (Incomplete origin); policy blocks it for Client3.
    announce_route(
        &client1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client1.address.to_string(),
            ..Default::default()
        })),
    )
    .await;

    announce_route(
        &client2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: client2.address.to_string(),
            origin: Some(Origin::Incomplete),
            ..Default::default()
        })),
    )
    .await;

    // Client3 receives Client2's path via route iteration.
    poll_route_exists(
        &client3,
        expected_route(
            "10.0.0.0/24",
            PathParams {
                next_hop: client2.address.to_string(),
                peer_address: rs.address.to_string(),
                as_path: vec![as_sequence(vec![65002])],
                origin: Some(Origin::Incomplete),
                local_pref: Some(100),
                ..Default::default()
            },
        ),
    )
    .await;
}

/// Validation: Peer cannot be both rr-client and rs-client simultaneously.
#[tokio::test]
async fn test_rs_rr_mutual_exclusion() {
    let server = start_test_server(test_config(65000, 1)).await;
    let client = start_test_server(test_config(65000, 2)).await;

    // Try to configure peer as both RR client and RS client (should fail)
    let config = SessionConfig {
        rr_client: Some(true),
        rs_client: Some(true),
        ..Default::default()
    };

    let result = server
        .client
        .add_peer(client.address.to_string(), Some(config))
        .await;
    assert!(
        result.is_err(),
        "Should reject peer with both rr_client and rs_client enabled"
    );
}

/// Validation: RS client peer cannot have add-path-receive enabled on the RS side.
/// RFC 7947 2.3.2.2.2: route server enforces send-only ADD-PATH mode with clients.
#[tokio::test]
async fn test_rs_addpath_receive_rejected() {
    let server = start_test_server(test_config(65000, 1)).await;
    let client = start_test_server(test_config(65001, 2)).await;

    let result = server
        .client
        .add_peer(
            client.address.to_string(),
            Some(SessionConfig {
                rs_client: Some(true),
                add_path_receive: Some(true),
                ..Default::default()
            }),
        )
        .await;
    assert!(
        result.is_err(),
        "Should reject rs-client peer with add_path_receive enabled"
    );
}

/// RFC 7947 Section 2.2: Route server attribute transparency.
///
/// Client1(AS65001) -- RS(AS65000) -- Client2(AS65002)
///
/// For each case: Client1 announces a route with specific attributes, Client2
/// must receive them unmodified. AS_PATH and NEXT_HOP transparency (2.2.1,
/// 2.2.2.1) are verified by every case via the common base expected path.
#[tokio::test]
async fn test_rs_attribute_transparency() {
    struct Case {
        route: IpRouteParams,
        expected: PathParams,
    }

    // Default AS_PATH when the case doesn't override it: client1 prepends its own ASN.
    let client1_as_path = vec![as_sequence(vec![65001])];

    let test_cases: Vec<Case> = vec![
        // 2.2.1 + 2.2.2.1: NEXT_HOP and AS_PATH preserved without RS modification.
        // RS must not prepend its ASN (65000) to AS_PATH, must not alter NEXT_HOP.
        Case {
            route: IpRouteParams {
                as_path: vec![as_sequence(vec![65099])],
                ..Default::default()
            },
            expected: PathParams {
                // client1 (65001) prepends its own ASN; RS (65000) must not prepend
                as_path: vec![as_sequence(vec![65001, 65099])],
                ..Default::default()
            },
        },
        // 2.2.3: MED propagated unchanged
        Case {
            route: IpRouteParams {
                med: Some(42),
                ..Default::default()
            },
            expected: PathParams {
                as_path: client1_as_path.clone(),
                med: Some(42),
                ..Default::default()
            },
        },
        // 2.2.4: Standard communities (RFC 1997) preserved
        Case {
            route: IpRouteParams {
                communities: vec![community::from_asn_value(65001, 100)],
                ..Default::default()
            },
            expected: PathParams {
                as_path: client1_as_path.clone(),
                communities: vec![community::from_asn_value(65001, 100)],
                ..Default::default()
            },
        },
        // 2.2.4: Extended communities (RFC 4360) preserved.
        // Non-transitive ext community preservation via RS is tested separately in
        // test_rs_unknown_attr_transparency (requires FakePeer injection).
        Case {
            route: IpRouteParams {
                extended_communities: vec![from_two_octet_as(SUBTYPE_ROUTE_TARGET, 65001, 100)],
                ..Default::default()
            },
            expected: PathParams {
                as_path: client1_as_path.clone(),
                extended_communities: vec![ExtendedCommunity {
                    community: Some(Community::TwoOctetAs(TwoOctetAsSpecific {
                        is_transitive: true,
                        sub_type: SUBTYPE_ROUTE_TARGET as u32,
                        asn: 65001,
                        local_admin: 100,
                    })),
                }],
                ..Default::default()
            },
        },
        // 2.2.4: Large communities (RFC 8092) preserved
        Case {
            route: IpRouteParams {
                large_communities: vec![BgpLargeCommunity::new(65001, 1, 100)],
                ..Default::default()
            },
            expected: PathParams {
                as_path: client1_as_path.clone(),
                large_communities: vec![proto::LargeCommunity {
                    global_admin: 65001,
                    local_data_1: 1,
                    local_data_2: 100,
                }],
                ..Default::default()
            },
        },
        // 2.2.4: All community types preserved simultaneously
        Case {
            route: IpRouteParams {
                communities: vec![
                    community::from_asn_value(65001, 100),
                    community::from_asn_value(65001, 200),
                ],
                extended_communities: vec![from_two_octet_as(SUBTYPE_ROUTE_TARGET, 65001, 100)],
                large_communities: vec![BgpLargeCommunity::new(65001, 1, 100)],
                ..Default::default()
            },
            expected: PathParams {
                as_path: client1_as_path.clone(),
                communities: vec![
                    community::from_asn_value(65001, 100),
                    community::from_asn_value(65001, 200),
                ],
                extended_communities: vec![ExtendedCommunity {
                    community: Some(Community::TwoOctetAs(TwoOctetAsSpecific {
                        is_transitive: true,
                        sub_type: SUBTYPE_ROUTE_TARGET as u32,
                        asn: 65001,
                        local_admin: 100,
                    })),
                }],
                large_communities: vec![proto::LargeCommunity {
                    global_admin: 65001,
                    local_data_1: 1,
                    local_data_2: 100,
                }],
                ..Default::default()
            },
        },
    ];

    for case in test_cases {
        let client1 = start_test_server(test_config(65001, 1)).await;
        let rs = start_test_server(test_config(65000, 2)).await;
        let client2 = start_test_server(test_config(65002, 3)).await;

        setup_route_server(&rs, vec![&client1, &client2]).await;

        announce_route(
            &client1,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: client1.address.to_string(),
                ..case.route
            })),
        )
        .await;

        poll_route_exists(
            &client2,
            expected_route(
                "10.0.0.0/24",
                PathParams {
                    next_hop: client1.address.to_string(), // RS must not modify next hop
                    peer_address: rs.address.to_string(),
                    local_pref: Some(100),
                    origin: Some(Origin::Igp),
                    ..case.expected
                },
            ),
        )
        .await;
    }
}

/// RFC 7947 Section 2.2: RS preserves unknown optional attributes (transitive and
/// non-transitive). Normal eBGP drops non-transitive unknown attrs; RS must not.
///
/// Uses FakePeer to inject raw unknown attributes that have no gRPC representation.
///
/// FakePeer(AS65001, 127.0.0.5) -- RS(AS65000) -- Client2(AS65002)
#[tokio::test]
async fn test_rs_unknown_attr_transparency() {
    let rs = start_test_server(test_config(65000, 2)).await;
    let client2 = start_test_server(test_config(65002, 3)).await;

    setup_route_server(&rs, vec![&client2]).await;

    // 127.0.0.5 avoids conflict with client2 (127.0.0.3)
    rs.client
        .add_peer(
            "127.0.0.5".to_string(),
            Some(SessionConfig {
                rs_client: Some(true),
                passive_mode: Some(true),
                asn: Some(65001),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // RFC 8212: eBGP FakePeer needs explicit accept-all policies
    apply_permit_all(&rs, "127.0.0.5").await;

    let mut fake = FakePeer::connect_and_handshake(
        Some("127.0.0.5"),
        &rs,
        65001,
        Ipv4Addr::new(1, 1, 1, 1),
        None,
    )
    .await;

    fake.send_raw(&build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            // AS_SEQUENCE(2), count=1, AS=65001 (2-byte: 0xFDE9)
            &build_attr_bytes(
                attr_flags::TRANSITIVE,
                attr_type_code::AS_PATH,
                4,
                &[0x02, 0x01, 0xFD, 0xE9],
            ),
            &attr_next_hop(Ipv4Addr::new(127, 0, 0, 5)),
            &build_attr_bytes(
                attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                200,
                4,
                &[0xde, 0xad, 0xbe, 0xef],
            ),
            &build_attr_bytes(attr_flags::OPTIONAL, 201, 2, &[0xca, 0xfe]),
        ],
        &[24, 10, 0, 0],
        None,
    ))
    .await;

    poll_route_exists(
        &client2,
        expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![as_sequence(vec![65001])],
                next_hop: "127.0.0.5".to_string(),
                peer_address: rs.address.to_string(),
                local_pref: Some(100),
                origin: Some(Origin::Igp),
                unknown_attributes: vec![
                    UnknownAttribute {
                        attr_type: 200,
                        // Transitive unknown attrs get PARTIAL bit set when forwarded (RFC 4271)
                        flags: (attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::PARTIAL)
                            as u32,
                        value: vec![0xde, 0xad, 0xbe, 0xef],
                    },
                    UnknownAttribute {
                        attr_type: 201,
                        flags: attr_flags::OPTIONAL as u32,
                        value: vec![0xca, 0xfe],
                    },
                ],
                ..Default::default()
            },
        ),
    )
    .await;
}

/// RFC 7947 Section 2.2.4 + RFC 1997: RS does not re-advertise routes carrying
/// well-known communities to RS clients.
///
/// FakePeer simulates a peer that sends a route with a well-known community to the RS.
/// Even though a conforming peer would not send NO_EXPORT routes to an eBGP neighbor,
/// the RS must refuse to re-advertise them regardless.
///
/// FakePeer(AS65001, 127.0.0.5) -- RS(AS65000) -- Client2(AS65002)
#[tokio::test]
async fn test_rs_well_known_communities_block_propagation() {
    struct Case {
        name: &'static str,
        community: u32,
    }

    let cases = vec![
        Case {
            name: "NO_EXPORT",
            community: NO_EXPORT,
        },
        Case {
            name: "NO_ADVERTISE",
            community: NO_ADVERTISE,
        },
        Case {
            name: "NO_EXPORT_SUBCONFED",
            community: NO_EXPORT_SUBCONFED,
        },
    ];

    for case in cases {
        let rs = start_test_server(test_config(65000, 2)).await;
        let client2 = start_test_server(test_config(65002, 3)).await;

        setup_route_server(&rs, vec![&client2]).await;

        rs.client
            .add_peer(
                "127.0.0.5".to_string(),
                Some(SessionConfig {
                    rs_client: Some(true),
                    passive_mode: Some(true),
                    asn: Some(65001),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();

        // RFC 8212: eBGP FakePeer needs explicit accept-all policies
        apply_import_accept_all(&rs, "127.0.0.5").await;
        apply_export_accept_all(&rs, "127.0.0.5").await;

        let mut fake = FakePeer::connect_and_handshake(
            Some("127.0.0.5"),
            &rs,
            65001,
            Ipv4Addr::new(5, 5, 5, 5),
            None,
        )
        .await;

        fake.send_raw(&build_raw_update(
            &[],
            &[
                &attr_origin_igp(),
                &attr_as_path_2byte(vec![65001]),
                &attr_next_hop(Ipv4Addr::new(127, 0, 0, 5)),
                &build_attr_bytes(
                    attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                    attr_type_code::COMMUNITIES,
                    4,
                    &case.community.to_be_bytes(),
                ),
            ],
            &[24, 10, 0, 0],
            None,
        ))
        .await;

        // Probe route (no community) sent after — used as sync point via TCP ordering.
        fake.send_raw(&build_raw_update(
            &[],
            &[
                &attr_origin_igp(),
                &attr_as_path_2byte(vec![65001]),
                &attr_next_hop(Ipv4Addr::new(127, 0, 0, 5)),
            ],
            &[24, 10, 1, 0],
            None,
        ))
        .await;

        poll_route_exists(
            &client2,
            expected_route(
                "10.1.0.0/24",
                PathParams {
                    as_path: vec![as_sequence(vec![65001])],
                    next_hop: "127.0.0.5".to_string(),
                    peer_address: rs.address.to_string(),
                    local_pref: Some(100),
                    origin: Some(Origin::Igp),
                    ..Default::default()
                },
            ),
        )
        .await;

        let name = case.name;
        assert!(
            !client2
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .unwrap()
                .iter()
                .any(|r| route_has_prefix(r, "10.0.0.0/24")),
            "case '{name}': community route should not be forwarded to RS client",
        );
    }
}
