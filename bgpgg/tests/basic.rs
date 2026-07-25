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

mod utils;
pub use utils::*;

use bgpgg::bgp::msg_update::PathAttrValue;
use bgpgg::bgp::msg_update_types::{attr_flags, attr_type_code, NextHopAddr};
use bgpgg::grpc::proto::{
    remove_route_request, route, BgpState, ListRoutesRequest, Origin, RemoveRouteRequest, RibType,
    Route, SessionConfig,
};
use conf::bgp::BgpConfig;
use conf::language_bgp::OriginateRoute;
use std::net::{Ipv4Addr, Ipv6Addr};

#[tokio::test]
async fn test_announce_withdraw() {
    let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

    // Server2 announces a route to Server1
    announce_and_verify_route(
        &server2,
        &[&server1],
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
        PathParams::from_peer(&server2),
    )
    .await;

    // Server2 withdraws the route
    server2
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix("10.0.0.0/24".to_string())),
        })
        .await
        .expect("Failed to withdraw route");

    // Poll for withdrawal and verify peers are still established
    poll_route_withdrawal(&[&server1]).await;
    // Active-active: all peers have configured=true
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established)],).await);
    assert!(verify_peers(&server2, vec![server1.to_peer(BgpState::Established)],).await);
}

#[tokio::test]
async fn test_announce_withdraw_mesh() {
    let (server1, server2, server3) = setup_three_meshed_servers(PeerConfig::default()).await;

    // Server1 announces a route to both server2 and server3
    announce_and_verify_route(
        &server1,
        &[&server2, &server3],
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
        PathParams::from_peer(&server1),
    )
    .await;

    // Server1 withdraws the route
    server1
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix("10.1.0.0/24".to_string())),
        })
        .await
        .expect("Failed to withdraw route from server 1");

    // Poll for withdrawal and verify peers are still established
    // Active-active: all peers have configured=true
    poll_route_withdrawal(&[&server2, &server3]).await;
    assert!(
        verify_peers(
            &server1,
            vec![
                server2.to_peer(BgpState::Established),
                server3.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![
                server1.to_peer(BgpState::Established),
                server3.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server3,
            vec![
                server1.to_peer(BgpState::Established),
                server2.to_peer(BgpState::Established),
            ],
        )
        .await
    );
}

#[tokio::test]
async fn test_announce_withdraw_four_node_mesh() {
    let (server1, server2, server3, server4) =
        setup_four_meshed_servers(PeerConfig::default()).await;

    // Server1 announces a route
    announce_route(
        &server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Expected route for convergence check
    let expected_route = vec![expected_route(
        "10.1.0.0/24",
        PathParams::from_peer(&server1),
    )];
    let recv_1 = ExpectedStats {
        min_update_received: Some(1),
        ..Default::default()
    };
    let sent_1 = ExpectedStats {
        min_update_sent: Some(1),
        ..Default::default()
    };
    wait_convergence(
        &[
            (&server2, expected_route.clone()),
            (&server3, expected_route.clone()),
            (&server4, expected_route.clone()),
        ],
        &[
            // Each server receives UPDATE from all peers
            (&server2, &server1, recv_1),
            (&server2, &server3, recv_1),
            (&server2, &server4, recv_1),
            (&server3, &server1, recv_1),
            (&server3, &server2, recv_1),
            (&server3, &server4, recv_1),
            (&server4, &server1, recv_1),
            (&server4, &server2, recv_1),
            (&server4, &server3, recv_1),
            // Each server sends UPDATE to non-originating peers
            (&server2, &server3, sent_1),
            (&server2, &server4, sent_1),
            (&server3, &server2, sent_1),
            (&server3, &server4, sent_1),
            (&server4, &server2, sent_1),
            (&server4, &server3, sent_1),
        ],
    )
    .await;

    // Server1 withdraws the route
    server1
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix("10.1.0.0/24".to_string())),
        })
        .await
        .expect("Failed to withdraw route from server 1");

    // Poll for withdrawal with extended timeout (40s) for full mesh path hunting
    poll_until_with_timeout(
        || async {
            for server in [&server2, &server3, &server4] {
                let Ok(routes) = server
                    .client
                    .list_routes(ListRoutesRequest::default())
                    .await
                else {
                    return false;
                };
                if !routes.is_empty() {
                    return false;
                }
            }
            true
        },
        "Timeout waiting for route withdrawal",
        Duration::from_secs(40),
    )
    .await;
    // Active-active: all peers have configured=true
    assert!(
        verify_peers(
            &server1,
            vec![
                server2.to_peer(BgpState::Established),
                server3.to_peer(BgpState::Established),
                server4.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server2,
            vec![
                server1.to_peer(BgpState::Established),
                server3.to_peer(BgpState::Established),
                server4.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server3,
            vec![
                server1.to_peer(BgpState::Established),
                server2.to_peer(BgpState::Established),
                server4.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(
        verify_peers(
            &server4,
            vec![
                server1.to_peer(BgpState::Established),
                server2.to_peer(BgpState::Established),
                server3.to_peer(BgpState::Established),
            ],
        )
        .await
    );
}

#[tokio::test]
async fn test_ibgp_split_horizon() {
    // Linear topology: A--B--C (all same ASN for iBGP)
    // Tests that routes learned via iBGP are not advertised to other iBGP peers
    // iBGP: all same ASN
    let [server1, server2, server3] = chain_servers(
        [
            start_test_server(BgpConfig::new(
                65001,
                "127.0.0.1:0",
                Ipv4Addr::new(1, 1, 1, 1),
                90,
            ))
            .await,
            start_test_server(BgpConfig::new(
                65001,
                "127.0.0.2:0",
                Ipv4Addr::new(2, 2, 2, 2),
                90,
            ))
            .await,
            start_test_server(BgpConfig::new(
                65001,
                "127.0.0.3:0",
                Ipv4Addr::new(3, 3, 3, 3),
                90,
            ))
            .await,
        ],
        PeerConfig::default(),
    )
    .await;

    // Server1 announces a route
    announce_route(
        &server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Server2 should receive the route from Server1
    // Server3 should NOT receive the route (iBGP split horizon)
    // iBGP: NEXT_HOP preserved (not rewritten)
    poll_rib(&[
        (
            &server2,
            vec![expected_route(
                "10.1.0.0/24",
                PathParams {
                    as_path: vec![], // Empty AS_PATH for locally originated route in iBGP
                    next_hop: "192.168.1.1".to_string(), // iBGP: NEXT_HOP preserved
                    peer_address: server1.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                },
            )],
        ),
        (&server3, vec![]), // Server3 should have no routes due to split horizon
    ])
    .await;

    // Verify all peers are still established
    // Active-active peering: all peers have configured=true
    // Active-active: all peers have configured=true
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established)],).await);
    assert!(
        verify_peers(
            &server2,
            vec![
                server1.to_peer(BgpState::Established),
                server3.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(verify_peers(&server3, vec![server2.to_peer(BgpState::Established)],).await);
}

#[tokio::test]
async fn test_as_loop_prevention() {
    // Topology: AS1_A -> AS2 -> AS1_B (different speakers in AS1)
    // Test that when AS1_A announces a route, it propagates to AS2,
    // but when AS2 tries to send it to AS1_B, AS1_B rejects it due to AS loop detection
    let [server1_a, server2, server1_b] = chain_servers(
        [
            start_test_server(BgpConfig::new(
                65001,
                "127.0.0.1:0",
                Ipv4Addr::new(1, 1, 1, 1),
                90,
            ))
            .await,
            start_test_server(BgpConfig::new(
                65002,
                "127.0.0.2:0",
                Ipv4Addr::new(2, 2, 2, 2),
                90,
            ))
            .await,
            start_test_server(BgpConfig::new(
                65001,
                "127.0.0.3:0",
                Ipv4Addr::new(3, 3, 3, 3),
                90,
            ))
            .await, // Same AS as server1_a
        ],
        PeerConfig::default(),
    )
    .await;

    // Server1_A announces a route to server2
    announce_and_verify_route(
        &server1_a,
        &[&server2],
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
        PathParams::from_peer(&server1_a),
    )
    .await;

    // Wait for server1_b to receive UPDATE from server2
    // This proves server2 sent it, and we can then verify server1_b rejected it
    poll_until(
        || async {
            let (_, stats) = server1_b
                .client
                .get_peer(server2.address.to_string())
                .await
                .expect("Failed to get peer");
            stats.is_some_and(|s| s.update_received == 1)
        },
        "Timeout waiting for server1_b to receive UPDATE from server2",
    )
    .await;

    // Server1_B should have NO routes in its RIB (rejected due to AS loop prevention)
    // The route from server2 was received but rejected because AS_PATH would be [65002, 65001]
    // which contains server1_b's own ASN (65001)
    let routes = server1_b
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .expect("Failed to get routes from server 1_B");
    assert_eq!(
        routes.len(),
        0,
        "Server1_B should have no routes due to AS loop prevention"
    );

    // Verify all peers are still established
    // chain_servers: server1_a -> server2 -> server1_b
    assert!(verify_peers(&server1_a, vec![server2.to_peer(BgpState::Established)],).await);
    assert!(
        verify_peers(
            &server2,
            vec![
                server1_a.to_peer(BgpState::Established),
                server1_b.to_peer(BgpState::Established),
            ],
        )
        .await
    );
    assert!(verify_peers(&server1_b, vec![server2.to_peer(BgpState::Established)],).await);
}

#[tokio::test]
async fn test_ipv6_route_exchange() {
    let (server1, server2) = setup_two_peered_servers(PeerConfig {
        afi_safis: vec![afi_safi_ipv4_unicast(), afi_safi_ipv6_unicast()],
        ..PeerConfig::default()
    })
    .await;

    // Server2 announces both IPv4 and IPv6 routes to Server1 via gRPC
    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "2001:db8::/32".to_string(),
            next_hop: "2001:db8::1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Poll for both IPv4 and IPv6 routes to appear in Server1's RIB
    // eBGP: IPv4 next hop rewritten to sender's address
    // Cross-family (IPv6 route over IPv4 session): IPv6 next hop preserved
    poll_rib(&[(
        &server1,
        vec![
            expected_route("10.0.0.0/24", PathParams::from_peer(&server2)),
            expected_route(
                "2001:db8::/32",
                PathParams {
                    next_hop: "2001:db8::1".to_string(), // IPv6 next hop preserved
                    ..PathParams::from_peer(&server2)
                },
            ),
        ],
    )])
    .await;

    // Server2 withdraws both routes
    server2
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix("10.0.0.0/24".to_string())),
        })
        .await
        .expect("Failed to withdraw IPv4 route");

    server2
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix(
                "2001:db8::/32".to_string(),
            )),
        })
        .await
        .expect("Failed to withdraw IPv6 route");

    // Poll for withdrawal and verify peers are still established
    poll_route_withdrawal(&[&server1]).await;
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established)],).await);
    assert!(verify_peers(&server2, vec![server1.to_peer(BgpState::Established)],).await);
}

#[tokio::test]
async fn test_ipv6_nexthop_rewrite() {
    let server1 = start_test_server(BgpConfig::new(
        65001,
        "[::ffff:127.0.0.1]:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    let server2 = start_test_server(BgpConfig::new(
        65002,
        "[::ffff:127.0.0.2]:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
    ))
    .await;

    let [server1, server2] = chain_servers(
        [server1, server2],
        PeerConfig {
            afi_safis: vec![afi_safi_ipv4_unicast(), afi_safi_ipv6_unicast()],
            ..PeerConfig::default()
        },
    )
    .await;

    // Server2 announces IPv6 route with explicit next-hop
    announce_and_verify_route(
        &server2,
        &[&server1],
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "2001:db8::/32".to_string(),
            next_hop: "2001:db8::1".to_string(),
            ..Default::default()
        })),
        PathParams::from_peer(&server2),
    )
    .await;

    // Withdraw the route
    server2
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix(
                "2001:db8::/32".to_string(),
            )),
        })
        .await
        .expect("Failed to withdraw IPv6 route");

    poll_route_withdrawal(&[&server1]).await;
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established)],).await);
    assert!(verify_peers(&server2, vec![server1.to_peer(BgpState::Established)],).await);
}
#[tokio::test]
async fn test_route_advertised_when_peer_becomes_established() {
    let server = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // Add a passive peer so FakePeer connection is accepted
    server
        .client
        .add_peer(
            "127.0.0.1".to_string(),
            Some(SessionConfig {
                passive_mode: Some(true),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // RFC 8212: eBGP peers need explicit accept-all policies
    apply_export_accept_all(&server, "127.0.0.1").await;

    // FakePeer connects and completes OPEN handshake (reaches OpenConfirm)
    let mut fake_peer = FakePeer::connect(None, &server).await;
    fake_peer
        .handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 90)
        .await;

    // Announce route while peer is still in OpenConfirm (not Established)
    announce_route(
        &server,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Complete handshake to reach Established (send KEEPALIVE)
    fake_peer.handshake_keepalive().await;

    // Read UPDATE message - route should be automatically sent when peer became Established
    let update = fake_peer.read_update().await;
    let nlri = update.nlri_prefixes();
    assert_eq!(nlri.len(), 1, "Expected one route announcement");
    assert_eq!(
        nlri[0].to_string(),
        "10.0.0.0/24",
        "Expected 10.0.0.0/24 to be announced"
    );
}

/// Two peers announce the same prefix to a middle server.
/// The middle server's loc-rib should store both paths (one per peer).
#[tokio::test]
async fn test_loc_rib_stores_multiple_paths() {
    // S1(65001) <-> S2(65002) <-> S3(65003)
    let [server1, server2, server3] = chain_servers(
        [
            start_test_server(test_config(65001, 1)).await,
            start_test_server(test_config(65002, 2)).await,
            start_test_server(test_config(65003, 3)).await,
        ],
        PeerConfig::default(),
    )
    .await;

    // Both announce 10.0.0.0/24
    for server in [&server1, &server3] {
        announce_route(
            server,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.168.1.1".to_string(),
                ..Default::default()
            })),
        )
        .await;
    }

    // S2 should have 2 paths for the same prefix (one from each peer)
    poll_rib(&[(
        &server2,
        vec![Route {
            paths: vec![
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65001])],
                    next_hop: server1.address.to_string(),
                    peer_address: server1.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65003])],
                    next_hop: server3.address.to_string(),
                    peer_address: server3.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
            ],
            key: Some(route::Key::Prefix("10.0.0.0/24".to_string())),
        }],
    )])
    .await;
}

/// When the best path changes for a non-ADD-PATH peer, the adj-rib-out should
/// not accumulate stale entries from the previous best path (which had a
/// different local_path_id).
///
/// Topology: s1(65001) <-> hub(65010) <-> s2(65002), hub <-> downstream(65020)
///
/// Both s1 and s2 originate 10.0.0.0/24. Hub picks best and exports to
/// downstream. When s1 withdraws, best changes to s2's path. Hub's adj-rib-out
/// toward downstream should have exactly 1 path, not stale entries.
#[tokio::test]
async fn test_adj_rib_out_no_stale_on_best_change() {
    let [server1, hub, server2] = chain_servers(
        [
            start_test_server(test_config(65001, 1)).await,
            start_test_server(test_config(65010, 3)).await,
            start_test_server(test_config(65002, 2)).await,
        ],
        PeerConfig::default(),
    )
    .await;

    let downstream = start_test_server(test_config(65020, 4)).await;
    hub.add_peer(&downstream).await;
    downstream.add_peer(&hub).await;

    // RFC 8212: eBGP peers need explicit accept-all policies
    apply_permit_all_routes(&hub, &downstream).await;

    poll_until(
        || async { verify_peers(&downstream, vec![hub.to_peer(BgpState::Established)]).await },
        "downstream not established",
    )
    .await;

    // Both originate the same prefix
    for (server, hop) in [(&server1, "192.168.1.1"), (&server2, "192.168.2.1")] {
        announce_route(
            server,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: hop.to_string(),
                ..Default::default()
            })),
        )
        .await;
    }

    // Wait for hub to export best to downstream
    let ds_addr = downstream.address.to_string();
    poll_until(
        || async {
            hub.client
                .list_routes(ListRoutesRequest {
                    rib_type: Some(RibType::AdjOut as i32),
                    peer_address: Some(ds_addr.clone()),
                    ..Default::default()
                })
                .await
                .is_ok_and(|routes| routes.iter().any(|r| route_has_prefix(r, "10.0.0.0/24")))
        },
        "adj-rib-out toward downstream should have route",
    )
    .await;

    // s1 withdraws -> best changes to s2's path (different local_path_id)
    server1
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix("10.0.0.0/24".to_string())),
        })
        .await
        .unwrap();

    // Wait for downstream to see s2's path
    poll_until(
        || async {
            downstream
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| {
                    routes.iter().any(|r| {
                        route_has_prefix(r, "10.0.0.0/24")
                            && r.paths.first().is_some_and(|p| {
                                p.as_path.iter().any(|seg| seg.asns.contains(&65002))
                            })
                    })
                })
        },
        "downstream should receive s2's route",
    )
    .await;

    // Key assertion: exactly 1 path, no stale entries
    let adj_out = hub
        .client
        .list_routes(ListRoutesRequest {
            rib_type: Some(RibType::AdjOut as i32),
            peer_address: Some(ds_addr.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
    let route = adj_out
        .iter()
        .find(|r| route_has_prefix(r, "10.0.0.0/24"))
        .expect("route should exist in adj-rib-out");
    assert_eq!(
        route.paths.len(),
        1,
        "adj-rib-out should have 1 path, not stale entries"
    );
}

/// Test next-hop-self: B rewrites NEXT_HOP to its own address before advertising
/// iBGP-learned routes to peer C. Without it, C sees the original eBGP NEXT_HOP.
///
/// Topology: A(65001) --eBGP-- B(65002) --iBGP-- C(65002)
/// A announces 10.0.0.0/24; B has next_hop_self toward C.
#[tokio::test]
async fn test_next_hop_self() {
    struct TestCase {
        name: &'static str,
        next_hop_self: bool,
    }

    let test_cases = [
        TestCase {
            name: "with next_hop_self: C sees B's address",
            next_hop_self: true,
        },
        TestCase {
            name: "without next_hop_self: C sees A's original address",
            next_hop_self: false,
        },
    ];

    for tc in test_cases {
        let server_a = start_test_server(test_config(65001, 1)).await;
        let server_b = start_test_server(test_config(65002, 2)).await;
        let server_c = start_test_server(test_config(65002, 3)).await;

        // A <-> B: standard eBGP
        server_a.add_peer(&server_b).await;
        server_b.add_peer(&server_a).await;

        // RFC 8212: eBGP peers need explicit accept-all policies
        apply_permit_all_routes(&server_a, &server_b).await;

        // B -> C: iBGP with optional next_hop_self
        server_b
            .add_peer_with_config(
                &server_c,
                SessionConfig {
                    next_hop_self: if tc.next_hop_self { Some(true) } else { None },
                    ..Default::default()
                },
            )
            .await;
        server_c.add_peer(&server_b).await;

        poll_until(
            || async {
                verify_peers(&server_a, vec![server_b.to_peer(BgpState::Established)]).await
                    && verify_peers(
                        &server_b,
                        vec![
                            server_a.to_peer(BgpState::Established),
                            server_c.to_peer(BgpState::Established),
                        ],
                    )
                    .await
                    && verify_peers(&server_c, vec![server_b.to_peer(BgpState::Established)]).await
            },
            &format!("{}: timeout waiting for topology to establish", tc.name),
        )
        .await;

        // A announces 10.0.0.0/24
        announce_route(
            &server_a,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.168.1.1".to_string(),
                ..Default::default()
            })),
        )
        .await;

        let expected_next_hop = if tc.next_hop_self {
            server_b.address.to_string() // B rewrites to its own address
        } else {
            server_a.address.to_string() // C sees A's address (iBGP preserves NH)
        };

        poll_rib(&[(
            &server_c,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    as_path: vec![as_sequence(vec![65001])],
                    next_hop: expected_next_hop,
                    peer_address: server_b.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                },
            )],
        )])
        .await;
    }
}

// ---- GTSM TTL security (RFC 5082) ----

// Happy path: both peers set ttl_min=255. Over loopback, TTL is not decremented,
// so packets arrive with TTL=255 >= 255 and the session establishes normally.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
#[tokio::test]
async fn test_gtsm_matching_both_peers() {
    let server1 = start_test_server(test_config(65001, 1)).await;
    let server2 = start_test_server(test_config(65002, 2)).await;
    peer_servers_with_config(
        &server1,
        &server2,
        SessionConfig {
            ttl_min: Some(255),
            ..Default::default()
        },
    )
    .await;
}

// Rejection path: server1 sets ttl_min=255 (IP_MINTTL=255), server2 uses default
// TTL (64 on Linux). Over loopback the kernel does not decrement TTL, so server1
// receives packets with TTL=64 < 255 and drops them. The session never establishes.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
#[tokio::test]
async fn test_gtsm_rejects_low_ttl() {
    let server1 = start_test_server(test_config(65001, 1)).await;
    let server2 = start_test_server(test_config(65002, 2)).await;

    // Passive so only server2 -> server1 TCP path exists; GTSM is applied
    // on accept before any BGP messages.
    server1
        .add_peer_with_config(
            &server2,
            SessionConfig {
                ttl_min: Some(255),
                passive_mode: Some(true),
                ..Default::default()
            },
        )
        .await;
    server2.add_peer(&server1).await;

    poll_while(
        || async {
            match server1.client.get_peers().await {
                Ok(peers) => peers
                    .iter()
                    .all(|p| p.state != BgpState::Established as i32),
                Err(_) => true,
            }
        },
        Duration::from_secs(5),
        "Session should not establish when peer sends with low TTL",
    )
    .await;
}

// Interop: verify that the listener sends SYN-ACKs with TTL=255 so that a
// FakePeer that sets IP_MINTTL=255 before connect() can complete the TCP
// handshake. This is the behavior used by other BGP implementations that
// enforce TTL security from the outset.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
#[tokio::test]
async fn test_gtsm_incoming_connection() {
    // Server configured with a passive GTSM peer at 127.0.0.1.
    // The key property under test: listener must send SYN-ACKs with TTL=255.
    let server = setup_server_with_passive_peer().await;

    // connect_with_min_ttl sets IP_MINTTL=255 before connect(), simulating a
    // remote peer that enforces GTSM from the start. The connect() succeeds
    // only if the listener sends SYN-ACK with TTL >= 255.
    let mut fake_peer = FakePeer::connect_with_min_ttl(None, &server, 255).await;

    // Complete the BGP handshake and verify session reaches Established.
    fake_peer
        .handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    fake_peer.handshake_keepalive().await;

    poll_peers(&server, vec![fake_peer.to_peer(BgpState::Established)]).await;
}

// ---- TCP MD5 authentication (RFC 2385) ----
// Requires CAP_NET_ADMIN (root on Linux): make test-md5

#[tokio::test]
async fn test_tcp_md5_matching_keys() {
    let key_path = write_key_file("match", b"shared-bgp-secret");

    let server1 = start_test_server(test_config(65001, 1)).await;
    let server2 = start_test_server(test_config(65002, 2)).await;
    peer_servers_with_config(
        &server1,
        &server2,
        SessionConfig {
            md5_key_file: Some(key_path.clone()),
            ..Default::default()
        },
    )
    .await;

    std::fs::remove_file(&key_path).ok();
}

// Test that a peer expecting MD5 rejects unsigned packets.
// Server1 expects MD5 auth, server2 sends without MD5 -> server1 drops packets.
#[tokio::test]
async fn test_tcp_md5_rejects_unsigned() {
    let key_a = write_key_file("md5-unsigned", b"server1-key");

    let server1 = start_test_server(test_config(65001, 1)).await;
    let server2 = start_test_server(test_config(65002, 2)).await;

    // Server1 expects MD5 authentication, passive so it only listens.
    server1
        .add_peer_with_config(
            &server2,
            SessionConfig {
                md5_key_file: Some(key_a.clone()),
                passive_mode: Some(true),
                ..Default::default()
            },
        )
        .await;

    // Wait for server1's peer to be configured (and SADB entry installed on BSD)
    // before server2 starts connecting.
    poll_until(
        || async {
            server1
                .client
                .get_peers()
                .await
                .is_ok_and(|peers| !peers.is_empty())
        },
        "server1 peer should be configured",
    )
    .await;

    // Server2 does NOT use MD5 - sends unsigned packets
    server2.add_peer(&server1).await;

    // Server1 should drop unsigned packets from server2, preventing establishment.
    poll_while(
        || async {
            match server1.client.get_peers().await {
                Ok(peers) => peers
                    .iter()
                    .all(|p| p.state != BgpState::Established as i32),
                Err(_) => true,
            }
        },
        Duration::from_secs(5),
        "Session should not establish when peer sends unsigned packets",
    )
    .await;

    std::fs::remove_file(&key_a).ok();
}

// Test that mismatched MD5 keys prevent session establishment.
//
// Linux only: BSD TCP-MD5 requires SPI=0x1000 and is per-host only, so we cannot test
// mismatched keys on a single machine (both servers share the same SADB and one key
// overwrites the other). From tcp(4):
//   "This entry must have an SPI of 0x1000 and can therefore only be specified
//    on a per-host basis at this time."
#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_tcp_md5_mismatching_keys() {
    let key_a = write_key_file("mismatch-a", b"server1-key");
    let key_b = write_key_file("mismatch-b", b"server2-key");

    let server1 = start_test_server(test_config(65001, 1)).await;
    let server2 = start_test_server(test_config(65002, 2)).await;

    server1
        .add_peer_with_config(
            &server2,
            SessionConfig {
                md5_key_file: Some(key_a.clone()),
                ..Default::default()
            },
        )
        .await;
    server2
        .add_peer_with_config(
            &server1,
            SessionConfig {
                md5_key_file: Some(key_b.clone()),
                ..Default::default()
            },
        )
        .await;

    // The kernel drops TCP segments with an incorrect MD5 digest.
    poll_while(
        || async {
            match server1.client.get_peers().await {
                Ok(peers) => peers
                    .iter()
                    .all(|p| p.state != BgpState::Established as i32),
                Err(_) => true,
            }
        },
        Duration::from_secs(5),
        "Session should not establish when MD5 keys do not match",
    )
    .await;

    std::fs::remove_file(&key_a).ok();
    std::fs::remove_file(&key_b).ok();
}

/// Build raw MP_REACH_NLRI attribute with 32-byte IPv6 next-hop (global + link-local).
fn attr_mp_reach_ipv6_with_link_local(
    global: Ipv6Addr,
    link_local: Ipv6Addr,
    prefix_len: u8,
    prefix_bytes: &[u8],
) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&2u16.to_be_bytes()); // AFI = IPv6
    value.push(1); // SAFI = Unicast
    value.push(32); // Next hop length = 32 (global + link-local)
    value.extend_from_slice(&global.octets());
    value.extend_from_slice(&link_local.octets());
    value.push(0); // Reserved
    value.push(prefix_len);
    value.extend_from_slice(prefix_bytes);

    // Flags: Optional, non-transitive, extended-length not needed for small payloads
    let mut attr = vec![
        attr_flags::OPTIONAL,
        attr_type_code::MP_REACH_NLRI,
        value.len() as u8,
    ];
    attr.extend_from_slice(&value);
    attr
}

/// RFC 2545: 32-byte IPv6 next-hop (global + link-local) end-to-end.
/// FakePeer1 (eBGP) sends UPDATE with 32-byte next-hop -> server stores link_local_next_hop
/// in RIB -> server propagates to FakePeer2 (iBGP) -> verify 32-byte encoding on wire.
#[tokio::test]
async fn test_ipv6_link_local_nexthop() {
    let server = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    let v4_v6 = vec![afi_safi_ipv4_unicast(), afi_safi_ipv6_unicast()];

    // Add eBGP peer (FakePeer1) that will inject the 32-byte next-hop
    server
        .client
        .add_peer(
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                afi_safis: v4_v6.clone(),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
    apply_permit_all(&server, "127.0.0.2").await;

    // Add iBGP peer (FakePeer2) that will receive the propagated route
    server
        .client
        .add_peer(
            "127.0.0.3".to_string(),
            Some(SessionConfig {
                asn: Some(65001),
                afi_safis: v4_v6,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // FakePeer1 (eBGP) connects
    let mut fake1 = FakePeer::connect_and_handshake(
        Some("127.0.0.2"),
        &server,
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
        Some(vec![
            build_multiprotocol_capability_ipv6_unicast(),
            build_capability_4byte_asn(65002),
        ]),
    )
    .await;

    // FakePeer2 (iBGP) connects
    let mut fake2 = FakePeer::connect_and_handshake(
        Some("127.0.0.3"),
        &server,
        65001,
        Ipv4Addr::new(3, 3, 3, 3),
        Some(vec![
            build_multiprotocol_capability_ipv6_unicast(),
            build_capability_4byte_asn(65001),
        ]),
    )
    .await;

    // FakePeer1 sends UPDATE with 32-byte IPv6 next-hop: global 2001:db8::1 + link-local fe80::1
    let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let mp_reach =
        attr_mp_reach_ipv6_with_link_local(global, link_local, 32, &[0x20, 0x01, 0x0d, 0xb8]);
    let update = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_4byte(vec![65002]),
            &mp_reach,
        ],
        &[],
        None,
    );
    fake1.send_raw(&update).await;

    // Receive: verify server's RIB has the route with link-local next-hop
    poll_rib(&[(
        &server,
        vec![expected_route(
            "2001:db8::/32",
            PathParams {
                next_hop: "2001:db8::1".to_string(),
                link_local_next_hop: Some("fe80::1".to_string()),
                peer_address: "127.0.0.2".to_string(),
                as_path: vec![as_sequence(vec![65002])],
                local_pref: Some(100),
                ..Default::default()
            },
        )],
    )])
    .await;

    // Send: verify FakePeer2 receives 32-byte next-hop on the wire
    let received = fake2.read_update().await;
    let mp_reach_attr = received
        .path_attributes()
        .iter()
        .find_map(|attr| match &attr.value {
            PathAttrValue::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("expected MP_REACH_NLRI in propagated UPDATE");

    assert_eq!(
        mp_reach_attr.next_hop,
        NextHopAddr::Ipv6WithLinkLocal(global, link_local),
        "iBGP propagation should preserve 32-byte next-hop with link-local"
    );
}

#[tokio::test]
async fn test_originate_propagates_at_startup() {
    // Server1 has a valid `originate` entry plus a bogus one. The bogus
    // entry must be skipped (warn-and-continue) and the valid one must
    // propagate to server2 over iBGP without any runtime add_route call.
    let mut config1 = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 90);
    config1.originate.push(OriginateRoute {
        prefix: "not-a-prefix".to_string(),
        nexthop: "192.168.1.1".to_string(),
    });
    config1.originate.push(OriginateRoute {
        prefix: "10.99.0.0/24".to_string(),
        nexthop: "192.168.1.1".to_string(),
    });
    let config2 = BgpConfig::new(65001, "127.0.0.2:0", Ipv4Addr::new(2, 2, 2, 2), 90);

    let [server1, server2] = chain_servers(
        [
            start_test_server(config1).await,
            start_test_server(config2).await,
        ],
        PeerConfig::default(),
    )
    .await;

    poll_rib(&[(
        &server2,
        vec![expected_route(
            "10.99.0.0/24",
            PathParams {
                as_path: vec![],
                next_hop: "192.168.1.1".to_string(),
                peer_address: server1.address.to_string(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            },
        )],
    )])
    .await;

    assert!(has_route(&server1, "10.99.0.0/24").await);
    assert!(!has_route(&server1, "not-a-prefix").await);
}
