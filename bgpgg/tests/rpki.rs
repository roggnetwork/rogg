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

use bgpgg::bgp::ext_community::from_rpki_state_community;
use bgpgg::grpc::proto::{
    extended_community::{Community, Opaque},
    ExtendedCommunity, Route, RpkiValidation, SessionConfig,
};
use bgpgg::net::{IpNetwork, Ipv4Net, Ipv6Net};
use bgpgg::rpki::rtr::ErrorCode;
use bgpgg::rpki::vrp::{RpkiValidation as RpkiState, Vrp};
use conf::bgp::{BgpConfig, RpkiCacheConfig, TransportType};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncWrite};
use utils::rtr::{FakeCache, FakeSshCache, FakeTcpCache};

fn vrp4(a: u8, b: u8, c: u8, d: u8, prefix_length: u8, max_length: u8, origin_as: u32) -> Vrp {
    Vrp {
        prefix: IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(a, b, c, d),
            prefix_length,
        }),
        max_length,
        origin_as,
    }
}

fn vrp6(addr: Ipv6Addr, prefix_length: u8, max_length: u8, origin_as: u32) -> Vrp {
    Vrp {
        prefix: IpNetwork::V6(Ipv6Net {
            address: addr,
            prefix_length,
        }),
        max_length,
        origin_as,
    }
}

/// Build an expected IPv4 route with rpki_validation state from a given peer.
fn rpki_v4_route(prefix: &str, state: RpkiValidation, peer: &TestServer) -> Route {
    expected_route(
        prefix,
        PathParams {
            rpki_validation: state as i32,
            ..PathParams::from_peer(peer)
        },
    )
}

/// Build an expected IPv6 route with rpki_validation state from a given peer.
fn rpki_v6_route(prefix: &str, state: RpkiValidation, next_hop: &str, peer: &TestServer) -> Route {
    expected_route(
        prefix,
        PathParams {
            rpki_validation: state as i32,
            next_hop: next_hop.to_string(),
            ..PathParams::from_peer(peer)
        },
    )
}

/// Start a server with RPKI caches and a single peer, chained together.
async fn setup_rpki_peer(
    rpki_caches: Vec<RpkiCacheConfig>,
    peer_asn: u32,
) -> (TestServer, TestServer) {
    let server1 = start_test_server(BgpConfig {
        asn: 65001,
        listen_addr: "127.0.0.1:0".to_string(),
        router_id: Ipv4Addr::new(1, 1, 1, 1),
        rpki_caches,
        ..Default::default()
    })
    .await;
    let server2 = start_test_server(BgpConfig::new(
        peer_asn,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
    ))
    .await;
    let [server2, server1] = chain_servers(
        [server2, server1],
        PeerConfig {
            afi_safis: vec![afi_safi_ipv4_unicast(), afi_safi_ipv6_unicast()],
            ..Default::default()
        },
    )
    .await;
    (server1, server2)
}

/// Announce a route from `from` and verify it arrives at `on` with the given RPKI state.
async fn announce_and_verify_rpki(
    from: &TestServer,
    on: &TestServer,
    prefix: &str,
    state: RpkiValidation,
) {
    announce_route(
        from,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: prefix.to_string(),
            next_hop: from.address.to_string(),
            ..Default::default()
        })),
    )
    .await;
    poll_rib(&[(on, vec![rpki_v4_route(prefix, state, from)])]).await;
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

/// Shared validation body: inject VRPs, announce routes, verify Valid/Invalid/NotFound.
async fn verify_basic_validation<S: AsyncRead + AsyncWrite + Unpin>(
    cache: &mut FakeCache<S>,
    server1: &TestServer,
    server2: &TestServer,
    server3: &TestServer,
) {
    cache.read_reset_query().await;

    // VRP: 10.0.0.0/8 max /24 AS 65002
    cache.send_vrps(&[vrp4(10, 0, 0, 0, 8, 24, 65002)]).await;

    // Announce routes:
    //   10.0.0.0/24 from AS 65002 -> Valid (VRP covers, origin matches)
    //   192.168.1.0/24 from AS 65002 -> NotFound (no VRP covers this prefix)
    //   10.1.0.0/24 from AS 65099 -> Invalid (VRP covers, origin AS mismatch)
    for (server, prefix) in [
        (server2, "10.0.0.0/24"),
        (server2, "192.168.1.0/24"),
        (server3, "10.1.0.0/24"),
    ] {
        announce_route(
            server,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: prefix.to_string(),
                next_hop: server.address.to_string(),
                ..Default::default()
            })),
        )
        .await;
    }

    poll_rib(&[(
        server1,
        vec![
            rpki_v4_route("10.0.0.0/24", RpkiValidation::RpkiValid, server2),
            rpki_v4_route("192.168.1.0/24", RpkiValidation::RpkiNotFound, server2),
            rpki_v4_route("10.1.0.0/24", RpkiValidation::RpkiInvalid, server3),
        ],
    )])
    .await;
}

/// Basic validation state over TCP transport.
#[tokio::test]
async fn test_rpki_basic_validation_tcp() {
    let mut cache = FakeTcpCache::listen().await;
    let [server2, server1, server3] = chain_servers(
        [
            start_test_server(BgpConfig::new(
                65002,
                "127.0.0.2:0",
                Ipv4Addr::new(2, 2, 2, 2),
                90,
            ))
            .await,
            start_test_server(BgpConfig {
                asn: 65001,
                listen_addr: "127.0.0.1:0".to_string(),
                router_id: Ipv4Addr::new(1, 1, 1, 1),
                rpki_caches: vec![RpkiCacheConfig {
                    address: cache.address(),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .await,
            start_test_server(BgpConfig::new(
                65099,
                "127.0.0.3:0",
                Ipv4Addr::new(3, 3, 3, 3),
                90,
            ))
            .await,
        ],
        PeerConfig::default(),
    )
    .await;
    cache.accept().await;
    verify_basic_validation(&mut cache.cache, &server1, &server2, &server3).await;
}

/// Basic validation state over SSH transport.
#[tokio::test]
async fn test_rpki_basic_validation_ssh() {
    let mut cache = FakeSshCache::listen().await;
    let [server2, server1, server3] = chain_servers(
        [
            start_test_server(BgpConfig::new(
                65002,
                "127.0.0.2:0",
                Ipv4Addr::new(2, 2, 2, 2),
                90,
            ))
            .await,
            start_test_server(BgpConfig {
                asn: 65001,
                listen_addr: "127.0.0.1:0".to_string(),
                router_id: Ipv4Addr::new(1, 1, 1, 1),
                rpki_caches: vec![RpkiCacheConfig {
                    address: cache.address().to_string(),
                    transport: TransportType::Ssh,
                    ssh_username: Some("test".to_string()),
                    ssh_private_key_file: Some(cache.client_key_path().to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            })
            .await,
            start_test_server(BgpConfig::new(
                65099,
                "127.0.0.3:0",
                Ipv4Addr::new(3, 3, 3, 3),
                90,
            ))
            .await,
        ],
        PeerConfig::default(),
    )
    .await;
    cache.accept().await;
    verify_basic_validation(&mut cache.cache, &server1, &server2, &server3).await;
}

/// RFC 8097: RPKI state extended community send and eBGP stripping.
#[tokio::test]
async fn test_rpki_state_community_send_and_strip() {
    let mut cache = FakeTcpCache::listen().await;

    let validator = start_test_server(BgpConfig {
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
    let receiver = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
    ))
    .await;
    let downstream = start_test_server(BgpConfig::new(
        65003,
        "127.0.0.3:0",
        Ipv4Addr::new(3, 3, 3, 3),
        90,
    ))
    .await;

    // validator <-> receiver (iBGP): send_rpki_community on this link
    peer_servers_with_config(
        &validator,
        &receiver,
        SessionConfig {
            send_rpki_community: Some(true),
            ..Default::default()
        },
    )
    .await;

    // validator <-> downstream (eBGP): default config
    peer_servers(&validator, &downstream).await;

    // Accept RPKI cache and provide VRPs
    cache.accept().await;
    cache.read_reset_query().await;
    cache.send_vrps(&[vrp4(10, 0, 0, 0, 8, 24, 65001)]).await;

    // Validator announces its own route: 10.0.0.0/24 (Valid per VRP, origin AS matches)
    announce_route(
        &validator,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: validator.address.to_string(),
            ..Default::default()
        })),
    )
    .await;

    poll_rib(&[
        (
            &receiver,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    next_hop: validator.address.to_string(),
                    peer_address: validator.address.to_string(),
                    local_pref: Some(100),
                    extended_communities: vec![rpki_state_ext_community(RpkiState::NotFound)],
                    ..Default::default()
                },
            )],
        ),
        (
            &downstream,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    as_path: vec![as_sequence(vec![65001])],
                    next_hop: validator.address.to_string(),
                    peer_address: validator.address.to_string(),
                    local_pref: Some(100),
                    extended_communities: vec![],
                    ..Default::default()
                },
            )],
        ),
    ])
    .await;
}

/// gRPC: GetRpkiValidation returns correct state and covering VRPs.
#[tokio::test]
async fn test_rpki_grpc_get_validation() {
    let mut cache = FakeTcpCache::listen().await;
    let server = start_test_server(BgpConfig {
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

    cache.accept().await;
    cache.read_reset_query().await;

    // Inject VRP: 10.0.0.0/8 max /24 AS 65002
    cache.send_vrps(&[vrp4(10, 0, 0, 0, 8, 24, 65002)]).await;

    // Wait for VRPs to be applied
    poll_until(
        || async {
            let resp = server.client.list_rpki_caches().await.unwrap();
            resp.total_vrp_count > 0
        },
        "VRPs not applied to server",
    )
    .await;

    // Valid: prefix covered, origin matches
    let resp = server
        .client
        .get_rpki_validation("10.0.0.0/24".to_string(), 65002)
        .await
        .unwrap();
    assert_eq!(resp.validation, RpkiValidation::RpkiValid as i32);
    assert_eq!(resp.covering_vrps.len(), 1);
    assert_eq!(resp.covering_vrps[0].prefix, "10.0.0.0/8");
    assert_eq!(resp.covering_vrps[0].max_length, 24);
    assert_eq!(resp.covering_vrps[0].origin_as, 65002);

    // Invalid: prefix covered, origin mismatch
    let resp = server
        .client
        .get_rpki_validation("10.1.0.0/24".to_string(), 65099)
        .await
        .unwrap();
    assert_eq!(resp.validation, RpkiValidation::RpkiInvalid as i32);
    assert!(!resp.covering_vrps.is_empty());

    // NotFound: no covering VRPs
    let resp = server
        .client
        .get_rpki_validation("192.168.1.0/24".to_string(), 65002)
        .await
        .unwrap();
    assert_eq!(resp.validation, RpkiValidation::RpkiNotFound as i32);
    assert!(resp.covering_vrps.is_empty());
}

/// VRP update re-evaluation.
/// Routes start NotFound, then VRPs arrive making them Valid,
/// then VRPs are withdrawn making them NotFound again.
#[tokio::test]
async fn test_rpki_vrp_update_reevaluation() {
    let mut cache = FakeTcpCache::listen().await;
    let (server1, server2) = setup_rpki_peer(
        vec![RpkiCacheConfig {
            address: cache.address(),
            ..Default::default()
        }],
        65002,
    )
    .await;

    // Accept cache, send empty VRP set so cache session is established
    cache.accept().await;
    cache.read_reset_query().await;
    cache.send_vrps(&[]).await;

    // Announce routes before any VRPs exist -> all NotFound.
    // Includes 10.0.0.0/8 (exact VRP prefix) to verify subtree inclusivity
    // in the re-evaluation path.
    for prefix in ["10.0.0.0/8", "10.0.0.0/24", "10.1.0.0/24"] {
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

    poll_rib(&[(
        &server1,
        vec![
            rpki_v4_route("10.0.0.0/8", RpkiValidation::RpkiNotFound, &server2),
            rpki_v4_route("10.0.0.0/24", RpkiValidation::RpkiNotFound, &server2),
            rpki_v4_route("10.1.0.0/24", RpkiValidation::RpkiNotFound, &server2),
        ],
    )])
    .await;

    // Inject VRP: 10.0.0.0/8 max /24 AS 65002 -> all three routes become Valid
    let vrp = vrp4(10, 0, 0, 0, 8, 24, 65002);
    cache.send_notify().await;
    cache.read_serial_query().await;
    cache.send_vrps(std::slice::from_ref(&vrp)).await;

    poll_rib(&[(
        &server1,
        vec![
            rpki_v4_route("10.0.0.0/8", RpkiValidation::RpkiValid, &server2),
            rpki_v4_route("10.0.0.0/24", RpkiValidation::RpkiValid, &server2),
            rpki_v4_route("10.1.0.0/24", RpkiValidation::RpkiValid, &server2),
        ],
    )])
    .await;

    // Withdraw VRPs -> routes go back to NotFound
    cache.send_notify().await;
    cache.read_serial_query().await;
    cache.send_vrp_withdrawals(std::slice::from_ref(&vrp)).await;

    poll_rib(&[(
        &server1,
        vec![
            rpki_v4_route("10.0.0.0/8", RpkiValidation::RpkiNotFound, &server2),
            rpki_v4_route("10.0.0.0/24", RpkiValidation::RpkiNotFound, &server2),
            rpki_v4_route("10.1.0.0/24", RpkiValidation::RpkiNotFound, &server2),
        ],
    )])
    .await;
}

/// Multi-cache merge.
/// Two FakeCaches at same preference, each provides different VRPs.
/// Verify both VRP sets merged for validation.
/// Kill one cache, verify its VRPs removed but other's still work.
#[tokio::test]
async fn test_rpki_multi_cache_merge() {
    let mut cache_a = FakeTcpCache::listen().await;
    let mut cache_b = FakeTcpCache::listen().await;
    let (server1, server2) = setup_rpki_peer(
        vec![
            RpkiCacheConfig {
                address: cache_a.address(),
                ..Default::default()
            },
            RpkiCacheConfig {
                address: cache_b.address(),
                ..Default::default()
            },
        ],
        65002,
    )
    .await;

    // Both caches connect with different VRP sets
    cache_a.accept().await;
    cache_b.accept().await;
    cache_a.read_reset_query().await;
    cache_a.send_vrps(&[vrp4(10, 0, 0, 0, 8, 24, 65002)]).await;
    cache_b.read_reset_query().await;
    cache_b
        .send_vrps(&[vrp4(192, 168, 0, 0, 16, 24, 65002)])
        .await;

    // Announce routes: both should be Valid from merged VRP sets
    for prefix in ["10.0.0.0/24", "192.168.1.0/24"] {
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

    poll_rib(&[(
        &server1,
        vec![
            rpki_v4_route("10.0.0.0/24", RpkiValidation::RpkiValid, &server2),
            rpki_v4_route("192.168.1.0/24", RpkiValidation::RpkiValid, &server2),
        ],
    )])
    .await;

    // Kill cache A -> its VRPs removed, cache B's still present
    server1
        .client
        .remove_rpki_cache(cache_a.address())
        .await
        .unwrap();

    poll_rib(&[(
        &server1,
        vec![
            rpki_v4_route("10.0.0.0/24", RpkiValidation::RpkiNotFound, &server2),
            rpki_v4_route("192.168.1.0/24", RpkiValidation::RpkiValid, &server2),
        ],
    )])
    .await;
}

/// Cache reset mid-session.
/// FakeCache sends Cache Reset. Verify CacheSession does full re-sync
/// (sends Reset Query) and VRPs are correct after re-sync.
#[tokio::test]
async fn test_rpki_cache_reset() {
    let mut cache = FakeTcpCache::listen().await;
    let (server1, server2) = setup_rpki_peer(
        vec![RpkiCacheConfig {
            address: cache.address(),
            ..Default::default()
        }],
        65002,
    )
    .await;

    cache.accept().await;
    cache.read_reset_query().await;
    cache.send_vrps(&[vrp4(10, 0, 0, 0, 8, 24, 65002)]).await;

    announce_and_verify_rpki(&server2, &server1, "10.0.0.0/24", RpkiValidation::RpkiValid).await;

    // Send Cache Reset -> CacheSession sends Reset Query on same connection
    cache.send_cache_reset().await;
    cache.read_reset_query().await;

    // Re-sync with different VRPs -- 192.168.0.0/16 instead of 10.0.0.0/8
    cache
        .send_vrps(&[vrp4(192, 168, 0, 0, 16, 24, 65002)])
        .await;

    // Announce a route covered by the new VRPs
    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "192.168.1.0/24".to_string(),
            next_hop: server2.address.to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Old route lost coverage, new route is covered
    poll_rib(&[(
        &server1,
        vec![
            rpki_v4_route("10.0.0.0/24", RpkiValidation::RpkiNotFound, &server2),
            rpki_v4_route("192.168.1.0/24", RpkiValidation::RpkiValid, &server2),
        ],
    )])
    .await;
}

/// Cache preference failover and recovery.
/// Preferred cache (preference=0) syncs, validates routes. Preferred cache
/// disconnects, fallback (preference=1) activates. Then preferred reconnects,
/// fallback is killed.
#[tokio::test]
async fn test_rpki_cache_failover() {
    let mut preferred = FakeTcpCache::listen().await;
    let mut fallback = FakeTcpCache::listen().await;
    let (server1, server2) = setup_rpki_peer(
        vec![
            RpkiCacheConfig {
                address: preferred.address(),
                preference: 0,
                expire_interval: Some(2),
                ..Default::default()
            },
            RpkiCacheConfig {
                address: fallback.address(),
                preference: 1,
                ..Default::default()
            },
        ],
        65002,
    )
    .await;

    // Only preferred (preference=0) connects at startup
    let vrp = vrp4(10, 0, 0, 0, 8, 24, 65002);
    preferred.accept().await;
    preferred.read_reset_query().await;
    preferred.send_vrps(std::slice::from_ref(&vrp)).await;

    announce_and_verify_rpki(&server2, &server1, "10.0.0.0/24", RpkiValidation::RpkiValid).await;

    // Disconnect preferred -> fallback activates with same VRPs
    preferred.disconnect();
    fallback.accept().await;
    fallback.read_reset_query().await;
    fallback.send_vrps(std::slice::from_ref(&vrp)).await;

    // Routes stay Valid through fallback (longer timeout for expire_interval=2s)
    poll_rib_with_timeout(
        &[(
            &server1,
            vec![rpki_v4_route(
                "10.0.0.0/24",
                RpkiValidation::RpkiValid,
                &server2,
            )],
        )],
        Duration::from_secs(15),
    )
    .await;

    // Preferred comes back (Serial Query -- session state preserved)
    preferred.accept().await;
    preferred.read_serial_query().await;
    preferred.send_vrps(&[vrp]).await;

    // Routes stay valid, preferred reactivated, fallback killed
    poll_rib(&[(
        &server1,
        vec![rpki_v4_route(
            "10.0.0.0/24",
            RpkiValidation::RpkiValid,
            &server2,
        )],
    )])
    .await;

    poll_until(
        || async {
            let resp = server1.client.list_rpki_caches().await.unwrap();
            resp.caches
                .iter()
                .any(|c| c.address == preferred.address() && c.vrp_count > 0)
        },
        "preferred cache did not reactivate",
    )
    .await;
}

/// RFC 8210 Section 8.4: Cache responds with No Data Available error.
/// Session stays open, router retries on next refresh.
#[tokio::test]
async fn test_rpki_no_data_available() {
    let mut cache = FakeTcpCache::listen().await;
    let (server1, server2) = setup_rpki_peer(
        vec![RpkiCacheConfig {
            address: cache.address(),
            ..Default::default()
        }],
        65002,
    )
    .await;

    cache.accept().await;
    cache.read_reset_query().await;

    // Cache says "no data available" instead of responding with VRPs
    cache.send_error(ErrorCode::NoDataAvailable).await;

    // Announce route -- should be NotFound (no VRPs)
    announce_and_verify_rpki(
        &server2,
        &server1,
        "10.0.0.0/24",
        RpkiValidation::RpkiNotFound,
    )
    .await;

    // Session should stay alive. Send notify to trigger Serial Query,
    // but session was reset so it sends Reset Query.
    cache.send_notify().await;
    cache.read_reset_query().await;

    // Now provide VRPs -- route should become Valid
    cache.send_vrps(&[vrp4(10, 0, 0, 0, 8, 24, 65002)]).await;

    poll_rib(&[(
        &server1,
        vec![rpki_v4_route(
            "10.0.0.0/24",
            RpkiValidation::RpkiValid,
            &server2,
        )],
    )])
    .await;
}

/// RFC 8210 Section 5.1: Session ID mismatch in Cache Response.
/// Router must flush all data and reset.
#[tokio::test]
async fn test_rpki_session_id_mismatch() {
    let mut cache = FakeTcpCache::listen().await;
    let (server1, server2) = setup_rpki_peer(
        vec![RpkiCacheConfig {
            address: cache.address(),
            ..Default::default()
        }],
        65002,
    )
    .await;

    // Initial sync with valid VRPs
    cache.accept().await;
    cache.read_reset_query().await;
    cache.send_vrps(&[vrp4(10, 0, 0, 0, 8, 24, 65002)]).await;

    announce_and_verify_rpki(&server2, &server1, "10.0.0.0/24", RpkiValidation::RpkiValid).await;

    // Trigger incremental sync but respond with wrong session ID.
    // Router should detect mismatch, flush data, and reconnect.
    cache.send_notify().await;
    cache.read_serial_query().await;
    cache.send_cache_response(999).await;

    // Session will reconnect with Reset Query after detecting mismatch
    cache.accept().await;
    cache.read_reset_query().await;

    // Re-sync with different VRPs to confirm old data was flushed
    cache
        .send_vrps(&[vrp4(192, 168, 0, 0, 16, 24, 65002)])
        .await;

    // Old VRP gone (10.0.0.0/8), new VRP active (192.168.0.0/16)
    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "192.168.1.0/24".to_string(),
            next_hop: server2.address.to_string(),
            ..Default::default()
        })),
    )
    .await;

    poll_rib(&[(
        &server1,
        vec![
            rpki_v4_route("10.0.0.0/24", RpkiValidation::RpkiNotFound, &server2),
            rpki_v4_route("192.168.1.0/24", RpkiValidation::RpkiValid, &server2),
        ],
    )])
    .await;
}

/// IPv6 VRP validation: Valid, Invalid, NotFound with IPv6 prefixes and max_length.
#[tokio::test]
async fn test_rpki_ipv6_validation() {
    let mut cache = FakeTcpCache::listen().await;
    let (server1, server2) = setup_rpki_peer(
        vec![RpkiCacheConfig {
            address: cache.address(),
            ..Default::default()
        }],
        65002,
    )
    .await;

    cache.accept().await;
    cache.read_reset_query().await;

    // VRP: 2001:db8::/32 max /48 AS 65002
    let addr = "2001:db8::".parse::<Ipv6Addr>().unwrap();
    cache.send_vrps(&[vrp6(addr, 32, 48, 65002)]).await;

    // 2001:db8:1::/48 from AS 65002 -> Valid (covered, origin matches)
    // 2001:db8:ff:1::/64 from AS 65002 -> Invalid (prefix len exceeds max_length)
    // 2001:a00::/24 from AS 65002 -> NotFound (no covering VRP)
    let next_hop_v6 = "2001:db8::2".to_string();
    for prefix in ["2001:db8:1::/48", "2001:db8:ff:1::/64", "2001:a00::/24"] {
        announce_route(
            &server2,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: prefix.to_string(),
                next_hop: next_hop_v6.clone(),
                ..Default::default()
            })),
        )
        .await;
    }

    poll_rib(&[(
        &server1,
        vec![
            rpki_v6_route(
                "2001:a00::/24",
                RpkiValidation::RpkiNotFound,
                &next_hop_v6,
                &server2,
            ),
            rpki_v6_route(
                "2001:db8:1::/48",
                RpkiValidation::RpkiValid,
                &next_hop_v6,
                &server2,
            ),
            rpki_v6_route(
                "2001:db8:ff:1::/64",
                RpkiValidation::RpkiInvalid,
                &next_hop_v6,
                &server2,
            ),
        ],
    )])
    .await;
}
