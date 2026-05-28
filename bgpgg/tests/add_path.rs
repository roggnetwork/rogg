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

mod utils;
pub use utils::*;

use bgpgg::grpc::proto::{
    remove_route_request, route, AddPathSendMode, BgpState, ListRoutesRequest, Origin,
    RemoveRouteRequest, ResetType, RibType, Route, SessionConfig,
};
use conf::bgp::BgpConfig;
use std::net::Ipv4Addr;

/// ADD-PATH config: send all paths + receive path IDs
fn addpath_config() -> SessionConfig {
    SessionConfig {
        add_path_send: Some(AddPathSendMode::AddPathSendAll.into()),
        add_path_receive: Some(true),
        ..Default::default()
    }
}

/// Sets up the common ADD-PATH test topology:
///
///   S1(65001) ---\
///                 +---> S3(hub_asn) ---[ADD-PATH send]---> S4(addpath_peer_asn)
///   S2(65002) ---/                           |
///                                            +----[normal]---> S5(65005)
///
/// S1 and S2 originate routes. S3 collects and forwards to S4 (ADD-PATH) and S5 (normal).
/// When hub_asn == addpath_peer_asn, S3->S4 is iBGP; otherwise eBGP.
/// Returns (s1, s2, s3, s4, s5) with all sessions Established.
async fn setup_addpath_topology(
    hub_asn: u32,
    addpath_peer_asn: u32,
) -> (TestServer, TestServer, TestServer, TestServer, TestServer) {
    let server1 = start_test_server(test_config(65001, 1)).await;
    let server2 = start_test_server(test_config(65002, 2)).await;
    let server3 = start_test_server(test_config(hub_asn, 3)).await;
    let server4 = start_test_server(test_config(addpath_peer_asn, 4)).await;
    let server5 = start_test_server(test_config(65005, 5)).await;

    peer_servers(&server1, &server3).await;
    peer_servers(&server2, &server3).await;
    peer_servers_with_config(&server3, &server4, addpath_config()).await;
    peer_servers(&server3, &server5).await;

    (server1, server2, server3, server4, server5)
}

/// S1 and S2 announce 10.0.0.0/24, validates:
/// - S3 loc-rib has both paths (one from each originator)
/// - S4 (ADD-PATH) receives both paths with distinct path_ids
/// - S5 (normal) receives only the best path (S1 wins by lower BGP ID)
async fn send_and_validate_addpath_routes(
    server1: &TestServer,
    server2: &TestServer,
    server3: &TestServer,
    server4: &TestServer,
    server5: &TestServer,
) {
    let server3_addr = server3.address.to_string();
    for (server, next_hop) in [(server1, "192.168.1.1"), (server2, "192.168.2.1")] {
        announce_route(
            server,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: next_hop.to_string(),
                ..Default::default()
            })),
        )
        .await;
    }

    // S3 loc-rib: both paths from S1 and S2
    poll_rib(&[(
        server3,
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
                    as_path: vec![as_sequence(vec![65002])],
                    next_hop: server2.address.to_string(),
                    peer_address: server2.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
            ],
            key: Some(route::Key::Prefix("10.0.0.0/24".to_string())),
        }],
    )])
    .await;

    // S4 (ADD-PATH): both paths with distinct path_ids, next_hop=S3 (eBGP rewrite)
    let two_paths = expected_routes(&server3_addr, vec![vec![65003, 65001], vec![65003, 65002]]);
    poll_rib_addpath(&[(server4, two_paths)]).await;

    // S5 (normal): only best path (S1 wins by lower BGP ID 1.1.1.1)
    poll_rib(&[(
        server5,
        expected_routes(&server3_addr, vec![vec![65003, 65001]]),
    )])
    .await;
}

/// Expected rib: 10.0.0.0/24 with one or more paths, all from the same peer/next_hop.
fn expected_routes(peer_addr: &str, as_paths: Vec<Vec<u32>>) -> Vec<Route> {
    vec![Route {
        paths: as_paths
            .into_iter()
            .map(|as_path| {
                build_path(PathParams {
                    as_path: vec![as_sequence(as_path)],
                    next_hop: peer_addr.to_string(),
                    peer_address: peer_addr.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                })
            })
            .collect(),
        key: Some(route::Key::Prefix("10.0.0.0/24".to_string())),
    }]
}

/// S1 and S2 announce same prefix to S3. Validates ADD-PATH (S4 gets both paths)
/// vs normal (S5 gets only best).
#[tokio::test]
async fn test_addpath_multiple_paths() {
    let (server1, server2, server3, server4, server5) = setup_addpath_topology(65003, 65004).await;
    send_and_validate_addpath_routes(&server1, &server2, &server3, &server4, &server5).await;
}

/// Both announce, then S1 withdraws. S4 (ADD-PATH) should drop to 1 path,
/// S5 (normal) should still have 1 path.
#[tokio::test]
async fn test_addpath_withdraw() {
    let (server1, server2, server3, server4, server5) = setup_addpath_topology(65003, 65004).await;
    let server3_addr = server3.address.to_string();

    send_and_validate_addpath_routes(&server1, &server2, &server3, &server4, &server5).await;

    server1
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix("10.0.0.0/24".to_string())),
        })
        .await
        .unwrap();

    // S4 (ADD-PATH) should drop to 1 path (S2's)
    let s2_only = expected_routes(&server3_addr, vec![vec![65003, 65002]]);
    poll_rib_addpath(&[(&server4, s2_only.clone())]).await;

    // S5 (normal) should have S2's path (now the only and best)
    poll_rib(&[(&server5, s2_only)]).await;
}

/// Both announce, then S3 removes peer S1. S4 (ADD-PATH) should drop to 1 path (S2's).
#[tokio::test]
async fn test_addpath_peer_disconnect() {
    let (server1, server2, server3, server4, server5) = setup_addpath_topology(65003, 65004).await;
    let server3_addr = server3.address.to_string();

    send_and_validate_addpath_routes(&server1, &server2, &server3, &server4, &server5).await;

    server3.remove_peer(&server1).await;

    // S4 should drop to 1 path (S2's)
    poll_rib_addpath(&[(
        &server4,
        expected_routes(&server3_addr, vec![vec![65003, 65002]]),
    )])
    .await;
}

/// Sets up an iBGP route reflector with ADD-PATH and two clients:
///
///   Client1(BGP ID 2.2.2.2) --+
///                              +--> RR(BGP ID 1.1.1.1)
///   Client2(BGP ID 3.3.3.3) --+
///
/// All ASN 65001, rr_client + ADD-PATH on all peerings.
/// Returns (rr, client1, client2) with all sessions Established.
async fn setup_rr_addpath_topology() -> (TestServer, TestServer, TestServer) {
    let rr = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;
    let client1 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
    ))
    .await;
    let client2 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.3:0",
        Ipv4Addr::new(3, 3, 3, 3),
        90,
    ))
    .await;

    let rr_config = SessionConfig {
        rr_client: Some(true),
        add_path_send: Some(AddPathSendMode::AddPathSendAll.into()),
        add_path_receive: Some(true),
        ..Default::default()
    };
    rr.add_peer_with_config(&client1, rr_config.clone()).await;
    rr.add_peer_with_config(&client2, rr_config).await;
    client1.add_peer_with_config(&rr, addpath_config()).await;
    client2.add_peer_with_config(&rr, addpath_config()).await;

    poll_until(
        || async {
            rr.client.get_peers().await.is_ok_and(|peers| {
                peers
                    .iter()
                    .filter(|p| p.state == BgpState::Established as i32)
                    .count()
                    == 2
            })
        },
        "Timeout waiting for RR peers to reach Established",
    )
    .await;

    (rr, client1, client2)
}

/// Create a server + FakePeer with ADD-PATH iBGP session in Established state.
/// FakePeer listens, server connects out. Both are ASN 65001.
/// If gr_restart_time is Some, GR is enabled with that restart time.
///
///   Server --[iBGP + ADD-PATH recv]--> FakePeer
async fn setup_fakepeer_addpath(
    server_bgp_id: Ipv4Addr,
    fake_bgp_id: Ipv4Addr,
    gr_restart_time: Option<u32>,
) -> (TestServer, FakePeer) {
    let server = start_test_server(BgpConfig::new(65001, "127.0.0.1:0", server_bgp_id, 90)).await;
    let mut fake = FakePeer::new("127.0.0.2:0", 65001).await;
    server
        .client
        .add_peer(
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                port: Some(fake.port() as u32),
                add_path_receive: Some(true),
                graceful_restart: gr_restart_time.map(|secs| {
                    bgpgg::grpc::proto::GracefulRestartConfig {
                        enabled: Some(true),
                        restart_time_secs: Some(secs),
                    }
                }),
                idle_hold_time_secs: gr_restart_time.map(|_| 0),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    let mut caps = vec![
        build_multiprotocol_capability_ipv4_unicast(),
        build_addpath_capability_ipv4_unicast(),
    ];
    if let Some(secs) = gr_restart_time {
        caps.push(build_gr_capability(secs as u16, false));
    }

    fake.accept_and_handshake(65001, fake_bgp_id, Some(caps))
        .await;

    poll_until(
        || async {
            server.client.get_peers().await.is_ok_and(|peers| {
                peers
                    .iter()
                    .any(|p| p.state == BgpState::Established as i32)
            })
        },
        "Timeout waiting for Established",
    )
    .await;

    (server, fake)
}

/// Drop TCP to trigger GR, then reconnect with R=1 and re-establish.
async fn gr_reconnect(fake: &mut FakePeer, gr_restart_time: u16) {
    drop(fake.stream.take());

    fake.accept().await;
    fake.read_open().await;
    let open = build_raw_open(
        65001,
        300,
        u32::from(Ipv4Addr::new(2, 2, 2, 2)),
        RawOpenOptions {
            capabilities: Some(vec![
                build_multiprotocol_capability_ipv4_unicast(),
                build_addpath_capability_ipv4_unicast(),
                build_gr_capability(gr_restart_time, true),
            ]),
            ..Default::default()
        },
    );
    fake.send_raw(&open).await;
    fake.send_keepalive().await;
    fake.read_keepalive().await;
}

/// Build ADD-PATH NLRI bytes: 4-byte path_id + prefix_len + prefix_bytes
fn addpath_nlri(path_id: u32, prefix_bytes: &[u8]) -> Vec<u8> {
    let mut nlri = path_id.to_be_bytes().to_vec();
    nlri.extend_from_slice(prefix_bytes);
    nlri
}

/// Sender-side: RR must not reflect a client's own path back to that client.
/// Checks RR's adj-rib-out toward Client1.
#[tokio::test]
async fn test_addpath_rr_no_reflect_to_originator() {
    let (rr, client1, client2) = setup_rr_addpath_topology().await;
    let client1_addr = client1.address.to_string();

    for (server, next_hop) in [(&client1, "192.168.1.1"), (&client2, "192.168.2.1")] {
        announce_route(
            server,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: next_hop.to_string(),
                ..Default::default()
            })),
        )
        .await;
    }

    // Should only have Client2's path, not Client1's own reflected back
    poll_until_stable(
        || async {
            rr.client
                .list_routes(ListRoutesRequest {
                    rib_type: Some(RibType::AdjOut as i32),
                    peer_address: Some(client1_addr.clone()),
                    ..Default::default()
                })
                .await
                .is_ok_and(|routes| {
                    routes.iter().any(|r| {
                        route_has_prefix(r, "10.0.0.0/24")
                            && r.paths.len() == 1
                            && r.paths[0].next_hop == "192.168.2.1"
                    })
                })
        },
        Duration::from_secs(2),
        "RR adj-rib-out toward Client1 should have exactly 1 path (Client2's, next_hop 192.168.2.1)",
    )
    .await;
}

/// Per-path withdrawal must not remove other paths from the same ADD-PATH peer.
/// FakePeer sends two paths (path_id=1, path_id=2), then withdraws path_id=1.
/// path_id=2 must survive.
///
/// Also tests implicit replacement: re-announcing the same path_id with different
/// attributes must replace in-place (1 path, not 2).
#[tokio::test]
async fn test_addpath_per_path_withdrawal() {
    let (server, mut fake) = setup_fakepeer_addpath(
        Ipv4Addr::new(1, 1, 1, 1), // server BGP ID
        Ipv4Addr::new(2, 2, 2, 2), // fake BGP ID
        None,
    )
    .await;

    // Path 1: next_hop=192.168.1.1
    let update1 = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 1, 1)),
            &attr_local_pref(100),
        ],
        &addpath_nlri(1, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update1).await;

    // Path 2: next_hop=192.168.2.1
    let update2 = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 2, 1)),
            &attr_local_pref(100),
        ],
        &addpath_nlri(2, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update2).await;

    let fake_addr = "127.0.0.2".to_string();
    let ibgp_path = |next_hop: &str| {
        build_path(PathParams {
            next_hop: next_hop.to_string(),
            peer_address: fake_addr.clone(),
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            ..Default::default()
        })
    };

    // Both paths in loc-rib
    poll_rib_addpath(&[(
        &server,
        vec![Route {
            paths: vec![ibgp_path("192.168.1.1"), ibgp_path("192.168.2.1")],
            key: Some(route::Key::Prefix("10.0.0.0/24".to_string())),
        }],
    )])
    .await;

    // Withdraw path_id=1 only
    let withdraw = build_raw_update(&addpath_nlri(1, &[24, 10, 0, 0]), &[], &[], None);
    fake.send_raw(&withdraw).await;

    // path_id=2 (next_hop=192.168.2.1) must survive
    poll_until_stable(
        || async {
            let expected = vec![Route {
                paths: vec![ibgp_path("192.168.2.1")],
                key: Some(route::Key::Prefix("10.0.0.0/24".to_string())),
            }];
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes_match(&routes, &expected, ExpectPathId::Distinct))
        },
        Duration::from_secs(2),
        "path_id=2 was removed by withdrawal of path_id=1",
    )
    .await;

    // Implicit replacement: re-announce path_id=2 with different next_hop.
    // Must replace in-place (still 1 path), not append (would be 2 paths).
    let update_replace = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 3, 1)),
            &attr_local_pref(100),
        ],
        &addpath_nlri(2, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update_replace).await;

    poll_until_stable(
        || async {
            let expected = vec![Route {
                paths: vec![ibgp_path("192.168.3.1")],
                key: Some(route::Key::Prefix("10.0.0.0/24".to_string())),
            }];
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes_match(&routes, &expected, ExpectPathId::Distinct))
        },
        Duration::from_secs(2),
        "path_id=2 was not replaced in-place (wrong path count or attrs)",
    )
    .await;
}

/// Receiver-side: ORIGINATOR_ID loop rejection must not withdraw other paths from same peer.
/// FakePeer sends valid path (path_id=1), then looped path (path_id=2). Valid must survive.
#[tokio::test]
async fn test_originator_id_rejection_preserves_other_paths() {
    let (server, mut fake) = setup_fakepeer_addpath(
        Ipv4Addr::new(2, 2, 2, 2), // server BGP ID
        Ipv4Addr::new(3, 3, 3, 3), // fake BGP ID
        None,
    )
    .await;

    // Valid path: ORIGINATOR_ID=3.3.3.3 (not ours)
    let update_valid = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 2, 1)),
            &attr_local_pref(100),
            &attr_originator_id(Ipv4Addr::new(3, 3, 3, 3)),
        ],
        &addpath_nlri(1, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update_valid).await;

    poll_until_stable(
        || async {
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes.iter().any(|r| route_has_prefix(r, "10.0.0.0/24")))
        },
        Duration::from_secs(1),
        "Timeout waiting for valid path to stabilize",
    )
    .await;

    // Looped path: ORIGINATOR_ID=2.2.2.2 (matches server's BGP ID)
    let update_looped = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 1, 1)),
            &attr_local_pref(100),
            &attr_originator_id(Ipv4Addr::new(2, 2, 2, 2)),
        ],
        &addpath_nlri(2, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update_looped).await;

    // Valid path must survive the looped path's rejection
    poll_while(
        || async {
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes.iter().any(|r| route_has_prefix(r, "10.0.0.0/24")))
        },
        Duration::from_secs(2),
        "Valid path was removed by ORIGINATOR_ID loop rejection of another path",
    )
    .await;
}

/// Soft reset out must withdraw stale ADD-PATH entries.
///
/// 1. S1 and S2 announce 10.0.0.0/24 to S3
/// 2. S3 forwards both paths to S4 (2 paths via ADD-PATH)
/// 3. Apply export policy on S3->S4 rejecting 10.0.0.0/24
/// 4. Soft reset out S3->S4
/// 5. S4 should have 0 paths (both withdrawn)
#[tokio::test]
async fn test_addpath_soft_reset_withdraws_stale_paths() {
    let (server1, server2, server3, server4, _server5) = setup_addpath_topology(65003, 65004).await;
    let server4_addr = server4.address.to_string();

    send_and_validate_addpath_routes(&server1, &server2, &server3, &server4, &_server5).await;

    // Apply export policy on S3 -> S4 that rejects 10.0.0.0/24
    apply_export_prefix_reject_policy(
        &server3,
        &server4_addr,
        "block-10",
        vec![("10.0.0.0/24", None)],
    )
    .await;

    // Trigger soft reset out on S3 -> S4
    server3
        .client
        .reset_peer(server4_addr.clone(), ResetType::SoftOut, None, None)
        .await
        .unwrap();

    // S4 should have no routes after the soft reset (policy rejects 10.0.0.0/24)
    poll_until(
        || async {
            server4
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes.is_empty())
        },
        "S4 should have 0 routes after soft reset out with export policy rejecting 10.0.0.0/24",
    )
    .await;

    // Also verify S3's adj-rib-out toward S4 is empty
    poll_until(
        || async {
            server3
                .client
                .list_routes(ListRoutesRequest {
                    rib_type: Some(RibType::AdjOut as i32),
                    peer_address: Some(server4_addr.clone()),
                    ..Default::default()
                })
                .await
                .is_ok_and(|routes| routes.is_empty())
        },
        "S3 adj-rib-out toward S4 should be empty after soft reset with reject policy",
    )
    .await;
}

/// GR + ADD-PATH: stale paths must be marked per path_id and recovered individually.
///
/// FakePeer sends two paths for 10.0.0.0/24, then disconnects (GR).
/// Peer reconnects and resends only one path.
/// After EOR, the un-resent path should be swept while the resent one survives.
#[tokio::test]
async fn test_addpath_graceful_restart_stale_sweep() {
    let (server, mut fake) = setup_fakepeer_addpath(
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(2, 2, 2, 2),
        Some(120),
    )
    .await;

    let ibgp_path = |next_hop: &str| {
        build_path(PathParams {
            next_hop: next_hop.to_string(),
            peer_address: "127.0.0.2".to_string(),
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            ..Default::default()
        })
    };

    // Send two paths for 10.0.0.0/24
    let update1 = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 1, 1)),
            &attr_local_pref(100),
        ],
        &addpath_nlri(1, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update1).await;

    let update2 = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 2, 1)),
            &attr_local_pref(100),
        ],
        &addpath_nlri(2, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update2).await;

    poll_rib_addpath(&[(
        &server,
        vec![Route {
            paths: vec![ibgp_path("192.168.1.1"), ibgp_path("192.168.2.1")],
            key: Some(route::Key::Prefix("10.0.0.0/24".to_string())),
        }],
    )])
    .await;

    gr_reconnect(&mut fake, 120).await;

    // Resend only path_id=1, then EOR (path_id=2 should be swept)
    fake.send_raw(&update1).await;
    let eor = build_raw_update(&[], &[], &[], None);
    fake.send_raw(&eor).await;

    poll_until_stable(
        || async {
            let expected = vec![Route {
                paths: vec![ibgp_path("192.168.1.1")],
                key: Some(route::Key::Prefix("10.0.0.0/24".to_string())),
            }];
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes_match(&routes, &expected, ExpectPathId::Distinct))
        },
        Duration::from_secs(2),
        "Only path_id=1 should survive after GR stale sweep",
    )
    .await;
}

/// ADD-PATH must be negotiated per AFI/SAFI: path_id only on the AFI that was negotiated.
/// Tests both directions: ADD-PATH for IPv4-only and IPv6-only.
#[tokio::test]
async fn test_addpath_per_afi_safi_negotiation() {
    let cases = [
        (
            "ipv4_only",
            build_addpath_capability_ipv4_unicast(),
            true,  // v4 has path_id
            false, // v6 does not
        ),
        (
            "ipv6_only",
            build_addpath_capability_ipv6_unicast(),
            false, // v4 does not
            true,  // v6 has path_id
        ),
    ];

    for (name, addpath_cap, expect_v4_path_id, expect_v6_path_id) in cases {
        let server = start_test_server(BgpConfig::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            90,
        ))
        .await;
        let mut fake = FakePeer::new("127.0.0.2:0", 65001).await;

        server
            .client
            .add_peer(
                "127.0.0.2".to_string(),
                Some(SessionConfig {
                    port: Some(fake.port() as u32),
                    add_path_send: Some(AddPathSendMode::AddPathSendAll.into()),
                    add_path_receive: Some(true),
                    afi_safis: vec![afi_safi_ipv4_unicast(), afi_safi_ipv6_unicast()],
                    ..Default::default()
                }),
            )
            .await
            .unwrap();

        // FakePeer: MP for both v4+v6, ADD-PATH for one AFI only
        fake.accept_and_handshake(
            65001,
            Ipv4Addr::new(2, 2, 2, 2),
            Some(vec![
                build_multiprotocol_capability_ipv4_unicast(),
                build_multiprotocol_capability_ipv6_unicast(),
                addpath_cap,
            ]),
        )
        .await;

        poll_until(
            || async {
                server.client.get_peers().await.is_ok_and(|peers| {
                    peers
                        .iter()
                        .any(|p| p.state == BgpState::Established as i32)
                })
            },
            "Timeout waiting for Established",
        )
        .await;

        announce_route(
            &server,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.168.1.1".to_string(),
                ..Default::default()
            })),
        )
        .await;
        announce_route(
            &server,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: "2001:db8::/32".to_string(),
                next_hop: "2001:db8::1".to_string(),
                ..Default::default()
            })),
        )
        .await;

        // v4 and v6 arrive in separate UPDATEs (different address families)
        let update_a = fake.read_update().await;
        let update_b = fake.read_update().await;

        for nlri in update_a.nlri_list().iter().chain(&update_b.nlri_list()) {
            if matches!(nlri.prefix, bgpgg::net::IpNetwork::V4(_)) {
                assert_eq!(
                    nlri.path_id.is_some(),
                    expect_v4_path_id,
                    "{name}: IPv4 path_id"
                );
            } else {
                assert_eq!(
                    nlri.path_id.is_some(),
                    expect_v6_path_id,
                    "{name}: IPv6 path_id"
                );
            }
        }
    }
}

/// GR + ADD-PATH: peer resends identical path after restart, stale flag must be cleared.
#[tokio::test]
async fn test_addpath_graceful_restart_identical_readvertise() {
    let (server, mut fake) = setup_fakepeer_addpath(
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(2, 2, 2, 2),
        Some(120),
    )
    .await;

    let update = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(192, 168, 1, 1)),
            &attr_local_pref(100),
        ],
        &addpath_nlri(1, &[24, 10, 0, 0]),
        None,
    );
    fake.send_raw(&update).await;

    poll_until(
        || async {
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes.len() == 1 && routes[0].paths.len() == 1)
        },
        "route should appear in RIB",
    )
    .await;

    gr_reconnect(&mut fake, 120).await;

    // Resend identical path (same path_id=1, same attrs), then EOR
    fake.send_raw(&update).await;
    let eor = build_raw_update(&[], &[], &[], None);
    fake.send_raw(&eor).await;

    poll_until_stable(
        || async {
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes.len() == 1 && routes[0].paths.len() == 1)
        },
        Duration::from_secs(2),
        "Identical re-advertised path should survive stale sweep",
    )
    .await;
}

/// iBGP ADD-PATH: S3->S4 is iBGP (same ASN). Verifies iBGP export rules apply:
/// - next_hop preserved (S1/S2 addresses, not rewritten to S3)
/// - AS_PATH not prepended on iBGP hop (just [65001] / [65002], no 65003)
/// - LOCAL_PREF included
#[tokio::test]
async fn test_addpath_ibgp() {
    let (server1, server2, _server3, server4, _server5) =
        setup_addpath_topology(65003, 65003).await;

    for (server, next_hop) in [(&server1, "192.168.1.1"), (&server2, "192.168.2.1")] {
        announce_route(
            server,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: next_hop.to_string(),
                ..Default::default()
            })),
        )
        .await;
    }

    // S4 (iBGP ADD-PATH): both paths, next_hop preserved from eBGP learn (S1/S2 addresses),
    // no AS prepend on S3->S4 iBGP hop
    let server1_addr = server1.address.to_string();
    let server2_addr = server2.address.to_string();
    poll_rib_addpath(&[(
        &server4,
        vec![Route {
            paths: vec![
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65001])],
                    next_hop: server1_addr.clone(),
                    peer_address: _server3.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                }),
                build_path(PathParams {
                    as_path: vec![as_sequence(vec![65002])],
                    next_hop: server2_addr.clone(),
                    peer_address: _server3.address.to_string(),
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
