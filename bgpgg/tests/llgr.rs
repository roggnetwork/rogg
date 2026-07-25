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

//! Tests for Long-Lived Graceful Restart (RFC 9494)

mod utils;
pub use utils::*;

use bgpgg::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use bgpgg::grpc::proto::{
    AfiSafi as ProtoAfiSafi, BgpState, GracefulRestartConfig, ListRoutesRequest,
    LlgrConfig as ProtoLlgrConfig, SessionConfig,
};
use conf::bgp::LlgrConfig;
use std::net::Ipv4Addr;

const LLGR_STALE: u32 = 0xFFFF0006;
const NO_LLGR: u32 = 0xFFFF0007;

/// Helper: create a server with a passive peer configured for GR + LLGR.
/// idle_hold_time=0 ensures peer re-accepts connections immediately after disconnect.
async fn setup_llgr_server(
    gr_restart_time: u16,
    llgr_stale_time: u32,
    peer_ip: &str,
) -> TestServer {
    let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
    let mut config = test_config(65001, 1);
    config
        .insert_peer(conf::bgp::PeerConfig {
            address: peer_ip.to_string(),
            passive_mode: true,
            idle_hold_time_secs: Some(0),
            graceful_restart: conf::bgp::GracefulRestartConfig {
                enabled: true,
                restart_time: gr_restart_time,
            },
            llgr: Some(LlgrConfig {
                enabled: true,
                stale_time: Some(llgr_stale_time),
                afi_safis: Some(vec![ipv4_unicast]),
            }),
            ..Default::default()
        })
        .unwrap();
    start_test_server(config).await
}

/// Helper: create server + handshake FakePeer with GR+LLGR.
async fn setup_llgr(gr_restart_time: u16, llgr_stale_time: u32) -> (TestServer, FakePeer) {
    let server = setup_llgr_server(gr_restart_time, llgr_stale_time, "127.0.0.2").await;
    let fake = FakePeer::connect_and_handshake_llgr(
        Some("127.0.0.2"),
        &server,
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
        gr_restart_time,
        llgr_stale_time,
    )
    .await;
    poll_peer_established(&server, "127.0.0.2").await;
    apply_import_accept_all(&server, "127.0.0.2").await;
    (server, fake)
}

/// Helper: announce 10.0.0.0/24 from a FakePeer and wait for it to appear.
async fn announce_default_route(server: &TestServer, fake: &mut FakePeer, next_hop: Ipv4Addr) {
    let update = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(next_hop),
            &attr_local_pref(100),
        ],
        &[24, 10, 0, 0],
        None,
    );
    fake.send_raw(&update).await;

    poll_until(
        || async {
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes.iter().any(|r| route_has_prefix(r, "10.0.0.0/24")))
        },
        "Timeout waiting for route 10.0.0.0/24 to appear",
    )
    .await;
}

/// Helper: wait for a route to have LLGR_STALE community on server.
async fn poll_llgr_stale(server: &TestServer, prefix: &str) {
    let prefix = prefix.to_string();
    poll_until(
        || async {
            let Ok(routes) = server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
            else {
                return false;
            };
            routes.iter().any(|r| {
                route_has_prefix(r, &prefix)
                    && r.paths.iter().any(|p| p.communities.contains(&LLGR_STALE))
            })
        },
        &format!("Timeout waiting for {prefix} to have LLGR_STALE community"),
    )
    .await;
}

/// Helper: wait for all routes to be swept from a server, with timeout.
async fn poll_routes_swept(server: &TestServer, msg: &str, timeout: Duration) {
    poll_until_with_timeout(
        || async {
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes.is_empty())
        },
        msg,
        timeout,
    )
    .await;
}

/// RFC 9494 Section 4.5: LLGR capability without GR capability MUST be ignored.
/// FakePeer sends OPEN with LLGR cap (code 71) but no GR cap (code 64).
/// After FakePeer drops, route is swept immediately (no LLGR retention).
#[tokio::test]
async fn test_llgr_ignored_without_gr() {
    let mut config = test_config(65001, 1);
    add_passive_peer(&mut config, "127.0.0.2");
    let server = start_test_server(config).await;

    // FakePeer connects with LLGR capability but NO GR capability
    let llgr_cap = build_llgr_capability(false, 30);
    let mut fake = FakePeer::connect_and_handshake(
        Some("127.0.0.2"),
        &server,
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
        Some(vec![llgr_cap]),
    )
    .await;

    poll_peers(&server, vec![fake.to_peer(BgpState::Established)]).await;
    apply_import_accept_all(&server, "127.0.0.2").await;

    announce_default_route(&server, &mut fake, Ipv4Addr::new(127, 0, 0, 2)).await;

    // Drop TCP - no GR negotiated (LLGR without GR is ignored)
    drop(fake);

    poll_routes_swept(
        &server,
        "Route should be withdrawn immediately without LLGR retention",
        Duration::from_secs(2),
    )
    .await;
}

/// LLST=0 AFI/SAFI is swept immediately at GR expiry, not entering LLGR phase.
#[tokio::test]
async fn test_llgr_zero_stale_time() {
    let (server, mut fake) = setup_llgr(1, 0).await;
    announce_default_route(&server, &mut fake, Ipv4Addr::new(127, 0, 0, 2)).await;

    drop(fake);

    // GR timer (1s) fires, LLST=0 -> no LLGR phase -> route swept
    poll_routes_swept(
        &server,
        "Route should be withdrawn after GR timer (no LLGR phase for LLST=0)",
        Duration::from_secs(5),
    )
    .await;
}

/// LLGR_STALE tagged on clean routes, NO_LLGR routes swept at GR->LLGR transition.
#[tokio::test]
async fn test_llgr_stale_community() {
    let (server, mut fake) = setup_llgr(1, 10).await;

    // Announce prefix A (clean) - 10.0.0.0/24
    let update_a = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(127, 0, 0, 2)),
            &attr_local_pref(100),
        ],
        &[24, 10, 0, 0],
        None,
    );
    fake.send_raw(&update_a).await;

    // Announce prefix B (NO_LLGR community) - 10.1.0.0/24
    let update_b = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(127, 0, 0, 2)),
            &attr_local_pref(100),
            &attr_communities(&[NO_LLGR]),
        ],
        &[24, 10, 1, 0],
        None,
    );
    fake.send_raw(&update_b).await;

    poll_until(
        || async {
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes.len() == 2)
        },
        "Timeout waiting for both routes to appear",
    )
    .await;

    // Drop TCP -> GR phase, then LLGR transition
    drop(fake);

    // Prefix A should get LLGR_STALE community
    poll_llgr_stale(&server, "10.0.0.0/24").await;

    // Prefix B (NO_LLGR) should be swept
    poll_until(
        || async {
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| !routes.iter().any(|r| route_has_prefix(r, "10.1.0.0/24")))
        },
        "NO_LLGR route 10.1.0.0/24 should be swept",
    )
    .await;
}

/// LLGR_STALE routes are NOT propagated to peers without LLGR capability.
///
///   FakePeer (GR+LLGR) ---> S1 (GR+LLGR) <--GR only--> S2 (GR only)
///
/// After FakePeer drops, S1 tags route LLGR_STALE and withdraws it from S2.
#[tokio::test]
async fn test_llgr_not_propagated_to_non_llgr_peer() {
    let gr_config = Some(GracefulRestartConfig {
        enabled: Some(true),
        restart_time_secs: Some(120),
    });

    let server1 = start_test_server(test_config(65001, 1)).await;
    let server2 = start_test_server(test_config(65002, 2)).await;

    // S1 <-> S2 with GR only (S2 doesn't support LLGR)
    peer_servers_with_config(
        &server1,
        &server2,
        SessionConfig {
            graceful_restart: gr_config,
            ..Default::default()
        },
    )
    .await;

    // Add passive FakePeer to S1 with GR+LLGR
    server1
        .client
        .add_peer(
            "127.0.0.3".to_string(),
            Some(SessionConfig {
                passive_mode: Some(true),
                graceful_restart: Some(GracefulRestartConfig {
                    enabled: Some(true),
                    restart_time_secs: Some(1),
                }),
                llgr: Some(ProtoLlgrConfig {
                    enabled: Some(true),
                    stale_time_secs: Some(30),
                    afi_safis: vec![ProtoAfiSafi { afi: 1, safi: 1 }],
                }),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    let mut fake = FakePeer::connect_and_handshake_llgr(
        Some("127.0.0.3"),
        &server1,
        65003,
        Ipv4Addr::new(3, 3, 3, 3),
        1,
        30,
    )
    .await;
    poll_peer_established(&server1, "127.0.0.3").await;
    apply_import_accept_all(&server1, "127.0.0.3").await;
    announce_default_route(&server1, &mut fake, Ipv4Addr::new(127, 0, 0, 3)).await;

    // S2 should receive the route from S1
    poll_until(
        || async {
            server2
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes.iter().any(|r| route_has_prefix(r, "10.0.0.0/24")))
        },
        "Timeout waiting for route to propagate to S2",
    )
    .await;

    // FakePeer drops -> LLGR phase on S1
    drop(fake);

    // S2 (non-LLGR peer): route should be withdrawn
    poll_until(
        || async {
            server2
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| !routes.iter().any(|r| route_has_prefix(r, "10.0.0.0/24")))
        },
        "LLGR_STALE route should be withdrawn from non-LLGR peer S2",
    )
    .await;

    // S1 should still have the route with LLGR_STALE
    poll_llgr_stale(&server1, "10.0.0.0/24").await;
}

/// LLST timer sweeps routes after expiry.
#[tokio::test]
async fn test_llgr_timer_expiry() {
    let (server, mut fake) = setup_llgr(1, 1).await;
    announce_default_route(&server, &mut fake, Ipv4Addr::new(127, 0, 0, 2)).await;

    let start = std::time::Instant::now();

    // Drop TCP -> GR phase (1s), then LLGR phase (1s)
    drop(fake);

    // Route should be tagged LLGR_STALE after GR timer
    poll_llgr_stale(&server, "10.0.0.0/24").await;

    // Route should be swept after LLST expires (total ~2s from drop)
    poll_routes_swept(
        &server,
        "Route should be swept after LLST expires",
        Duration::from_secs(5),
    )
    .await;

    // Sanity: shouldn't be swept too early
    assert!(
        start.elapsed() >= Duration::from_secs(1),
        "Route swept too early - LLGR timer should have been active"
    );
}

/// EoR cancels LLGR timer, LLGR_STALE community removed on re-advertisement.
#[tokio::test]
async fn test_llgr_peer_recovery() {
    let (server, mut fake) = setup_llgr(1, 30).await;
    announce_default_route(&server, &mut fake, Ipv4Addr::new(127, 0, 0, 2)).await;

    // Drop TCP -> GR (1s) -> LLGR phase
    drop(fake.stream.take());

    poll_llgr_stale(&server, "10.0.0.0/24").await;

    // Wait for peer to be ready to accept connections again
    poll_peer_not_established(&server, "127.0.0.2").await;

    // FakePeer reconnects
    let mut fake2 = FakePeer::connect_and_handshake_llgr(
        Some("127.0.0.2"),
        &server,
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
        1,
        30,
    )
    .await;
    poll_peer_established(&server, "127.0.0.2").await;

    // Re-announce the route (without LLGR_STALE - fresh route)
    let update = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(127, 0, 0, 2)),
            &attr_local_pref(100),
        ],
        &[24, 10, 0, 0],
        None,
    );
    fake2.send_raw(&update).await;

    // Send EoR
    let eor = build_raw_update(&[], &[], &[], None);
    fake2.send_raw(&eor).await;

    // Route should be present WITHOUT LLGR_STALE community
    poll_until(
        || async {
            let Ok(routes) = server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
            else {
                return false;
            };
            routes.iter().any(|r| {
                route_has_prefix(r, "10.0.0.0/24")
                    && r.paths.iter().all(|p| !p.communities.contains(&LLGR_STALE))
            })
        },
        "Route should be present without LLGR_STALE after recovery",
    )
    .await;

    // Route must stay (not swept by timer - EoR cancelled it)
    poll_while(
        || async {
            server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| routes.iter().any(|r| route_has_prefix(r, "10.0.0.0/24")))
        },
        Duration::from_secs(2),
        "Route should remain after recovery (timer cancelled)",
    )
    .await;
}

/// RFC 9494 Section 4.2: immediate sweep on reconnect when F-bit/cap conditions not met.
/// Three sub-cases: f_bit_zero, afi_safi_absent, no_llgr_cap.
#[tokio::test]
async fn test_llgr_sweep_on_reconnect() {
    struct TestCase {
        name: &'static str,
        reconnect_caps: Vec<Vec<u8>>,
    }

    let cases = vec![
        TestCase {
            name: "f_bit_zero",
            reconnect_caps: vec![
                build_multiprotocol_capability_ipv4_unicast(),
                build_gr_capability(1, false),
                build_llgr_capability(false, 30),
            ],
        },
        TestCase {
            name: "afi_safi_absent",
            reconnect_caps: vec![
                build_multiprotocol_capability_ipv4_unicast(),
                build_gr_capability(1, false),
                // LLGR for IPv6 unicast only (not IPv4)
                {
                    let mut cap = vec![71u8, 7];
                    cap.push(0);
                    cap.push(2); // AFI=2 (IPv6)
                    cap.push(1); // SAFI=1
                    cap.push(0x80); // F-bit set
                    cap.push(0);
                    cap.push(0);
                    cap.push(30);
                    cap
                },
            ],
        },
        TestCase {
            name: "no_llgr_cap",
            reconnect_caps: vec![
                build_multiprotocol_capability_ipv4_unicast(),
                build_gr_capability(1, true),
                // GR present but no LLGR capability
            ],
        },
    ];

    for tc in cases {
        let (server, mut fake) = setup_llgr(1, 30).await;
        announce_default_route(&server, &mut fake, Ipv4Addr::new(127, 0, 0, 2)).await;

        // Drop TCP -> GR (1s) -> LLGR phase with 30s timer
        drop(fake.stream.take());

        poll_llgr_stale(&server, "10.0.0.0/24").await;

        // Wait for peer to leave Established before reconnecting
        poll_peer_not_established(&server, "127.0.0.2").await;

        // Reconnect with different capabilities
        let _fake2 = FakePeer::connect_and_handshake(
            Some("127.0.0.2"),
            &server,
            65002,
            Ipv4Addr::new(2, 2, 2, 2),
            Some(tc.reconnect_caps.clone()),
        )
        .await;

        poll_peer_established(&server, "127.0.0.2").await;

        // Route should be swept immediately (not retained for 30s LLST)
        poll_routes_swept(
            &server,
            &format!(
                "{}: stale route should be swept immediately on reconnect",
                tc.name
            ),
            Duration::from_secs(5),
        )
        .await;
    }
}

/// RFC 9494 Section 4.3: incoming LLGR_STALE routes forwarded to LLGR peers,
/// filtered from non-LLGR peers.
///
///   FakePeer --LLGR_STALE route--> S1 (LLGR) ---> S2 (LLGR)    receives route
///                                      \---------> S3 (GR only)  route filtered
#[tokio::test]
async fn test_llgr_stale_received_from_peer() {
    let gr_config = Some(GracefulRestartConfig {
        enabled: Some(true),
        restart_time_secs: Some(120),
    });
    let llgr_config = Some(ProtoLlgrConfig {
        enabled: Some(true),
        stale_time_secs: Some(30),
        afi_safis: vec![ProtoAfiSafi { afi: 1, safi: 1 }],
    });

    let server1 = start_test_server(test_config(65001, 1)).await;
    let server2 = start_test_server(test_config(65002, 2)).await;
    let server3 = start_test_server(test_config(65003, 3)).await;

    // S1 <-> S2 with LLGR on both sides
    peer_servers_with_config(
        &server1,
        &server2,
        SessionConfig {
            graceful_restart: gr_config,
            llgr: llgr_config.clone(),
            ..Default::default()
        },
    )
    .await;

    // S1 <-> S3 with GR only (no LLGR)
    peer_servers_with_config(
        &server1,
        &server3,
        SessionConfig {
            graceful_restart: gr_config,
            ..Default::default()
        },
    )
    .await;

    // Add passive FakePeer to S1 with GR+LLGR
    server1
        .client
        .add_peer(
            "127.0.0.4".to_string(),
            Some(SessionConfig {
                passive_mode: Some(true),
                graceful_restart: Some(GracefulRestartConfig {
                    enabled: Some(true),
                    restart_time_secs: Some(120),
                }),
                llgr: llgr_config,
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    let mut fake = FakePeer::connect_and_handshake_llgr(
        Some("127.0.0.4"),
        &server1,
        65004,
        Ipv4Addr::new(4, 4, 4, 4),
        120,
        30,
    )
    .await;
    poll_peer_established(&server1, "127.0.0.4").await;
    apply_import_accept_all(&server1, "127.0.0.4").await;

    let update = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(127, 0, 0, 4)),
            &attr_local_pref(100),
            &attr_communities(&[LLGR_STALE]),
        ],
        &[24, 10, 0, 0],
        None,
    );
    fake.send_raw(&update).await;

    // S1 should store route with LLGR_STALE
    poll_llgr_stale(&server1, "10.0.0.0/24").await;

    // S2 (LLGR-capable) should receive route with LLGR_STALE
    poll_until(
        || async {
            let Ok(routes) = server2
                .client
                .list_routes(ListRoutesRequest::default())
                .await
            else {
                return false;
            };
            routes.iter().any(|r| {
                route_has_prefix(r, "10.0.0.0/24")
                    && r.paths.iter().any(|p| p.communities.contains(&LLGR_STALE))
            })
        },
        "S2 (LLGR) should receive route with LLGR_STALE community",
    )
    .await;

    // S3 (non-LLGR) should NOT have the route
    poll_while(
        || async {
            server3
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .is_ok_and(|routes| !routes.iter().any(|r| route_has_prefix(r, "10.0.0.0/24")))
        },
        Duration::from_secs(2),
        "S3 (non-LLGR) should not receive LLGR_STALE route",
    )
    .await;
}

/// RFC 9494 Section 4.2: GR restart_time=0 with nonzero LLST skips GR phase.
/// LLGR_STALE should be tagged immediately after disconnect.
#[tokio::test]
async fn test_llgr_restart_time_zero() {
    let (server, mut fake) = setup_llgr(0, 1).await;
    announce_default_route(&server, &mut fake, Ipv4Addr::new(127, 0, 0, 2)).await;

    // Drop TCP -> GR phase has zero duration -> immediate LLGR transition
    drop(fake);

    // Route should be tagged LLGR_STALE promptly (no GR wait)
    poll_until_with_timeout(
        || async {
            let Ok(routes) = server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
            else {
                return false;
            };
            routes.iter().any(|r| {
                route_has_prefix(r, "10.0.0.0/24")
                    && r.paths.iter().any(|p| p.communities.contains(&LLGR_STALE))
            })
        },
        "Route should be tagged LLGR_STALE immediately (restart_time=0)",
        Duration::from_secs(2),
    )
    .await;

    // Route should be swept after LLST (1s) expires
    poll_routes_swept(
        &server,
        "Route should be swept after LLST expires",
        Duration::from_secs(5),
    )
    .await;
}

/// RFC 9494 Section 4.2: LLGR timer MUST NOT be reset on consecutive restart.
#[tokio::test]
async fn test_llgr_consecutive_restart() {
    let (server, mut fake) = setup_llgr(1, 2).await;
    announce_default_route(&server, &mut fake, Ipv4Addr::new(127, 0, 0, 2)).await;

    // Drop TCP -> GR (1s) -> LLGR phase (2s timer starts)
    drop(fake.stream.take());

    // Wait for LLGR phase to start
    poll_llgr_stale(&server, "10.0.0.0/24").await;

    // Wait ~1s into LLGR phase, then reconnect briefly and drop again
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Wait for peer to leave Established before reconnecting
    poll_peer_not_established(&server, "127.0.0.2").await;

    // Second connection + immediate drop (consecutive restart)
    let mut fake2 = FakePeer::connect(Some("127.0.0.2"), &server).await;
    fake2.read_open().await;
    fake2
        .send_open_with_llgr(65002, Ipv4Addr::new(2, 2, 2, 2), 90, 1, 2)
        .await;
    fake2.asn = 65002;
    fake2.send_keepalive().await;
    fake2.read_keepalive().await;

    // Drop again without sending EoR (consecutive restart)
    drop(fake2.stream.take());

    // The LLGR timer MUST NOT be restarted. Original deadline is ~3s from first drop
    // (1s GR + 2s LLST). If timer was reset, route would linger until ~6s+.
    // Original deadline is ~3s (1s GR + 2s LLST). If timer was reset on
    // reconnect, route would linger ~6s+. Timeout catches that.
    poll_routes_swept(
        &server,
        "Route should be swept at original LLST deadline, not reset",
        Duration::from_secs(5),
    )
    .await;
}
