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

//! Basic management operation tests

mod utils;
pub use utils::*;

use bgpgg::grpc::proto::{
    add_route_request, remove_route_request, route, AddIpRouteRequest, AddLsRouteRequest,
    AddRouteRequest, AddRpkiCacheRequest, AdminState, AfiSafi as ProtoAfiSafi, BgpState,
    GracefulRestartConfig, ListRoutesRequest, LlgrConfig as ProtoLlgrConfig, LsAttribute, LsNlri,
    LsNlriType, LsNodeAttribute, LsNodeDescriptor, LsProtocolId, Origin, RemoveRouteRequest,
    RibType, Route, SessionConfig,
};
use conf::bgp::BgpConfig;
use conf::language_bgp::OriginateRoute;
use std::net::Ipv4Addr;
use tokio::net::TcpListener;

#[tokio::test]
async fn test_add_peer_failure() {
    let mut config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 90);
    // Active state exits instantly.
    config.connect_retry_secs = 0;
    let server1 = start_test_server(config).await;

    // Initially no peers
    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 0);

    // Start a listener that accepts then immediately closes connections
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let reject_port = listener.local_addr().unwrap().port();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = listener.accept().await;
        let _ = accepted_tx.send(());
    });

    // Add peer pointing at the rejecting listener
    // Use long idle_hold_time so peer stays in Idle after failure instead of retrying
    let result = server1
        .client
        .add_peer(
            "127.0.0.1".to_string(),
            Some(SessionConfig {
                port: Some(reject_port as u32),
                idle_hold_time_secs: Some(3600),
                ..Default::default()
            }),
        )
        .await;
    assert!(result.is_ok());

    // Wait for TCP connection to be accepted (proves peer left initial Idle)
    accepted_rx.await.unwrap();

    // Now safe to poll for Idle - we're past initial Idle
    poll_until_stable(
        || async {
            let peers = server1.client.get_peers().await.unwrap();
            peers
                .first()
                .is_some_and(|p| p.state == BgpState::Idle as i32)
        },
        Duration::from_millis(500),
        "Peer should stay in Idle after connection failure",
    )
    .await;
}

#[tokio::test]
async fn test_add_peer_success() {
    let server1 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;
    let server2 = start_test_server(BgpConfig::new(
        65002,
        "127.0.0.1:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
    ))
    .await;

    // Add peer via gRPC - bidirectional peering
    server1.add_peer(&server2).await;
    server2.add_peer(&server1).await;

    // Wait for peering to establish
    poll_until(
        || async {
            verify_peers(&server1, vec![server2.to_peer(BgpState::Established)]).await
                && verify_peers(&server2, vec![server1.to_peer(BgpState::Established)]).await
        },
        "Timeout waiting for peers to establish",
    )
    .await;

    let peer_addr = server2.address.to_string();
    let conf = server1.read_conf();
    assert!(
        !conf.peers.iter().any(|p| p.address == peer_addr),
        "rogg.conf must NOT contain new peer until SaveConfig; got {:?}",
        conf.peers.iter().map(|p| &p.address).collect::<Vec<_>>()
    );

    server1.save_config().await.unwrap();
    let conf = server1.read_conf();
    assert!(
        conf.peers.iter().any(|p| p.address == peer_addr),
        "rogg.conf peers should include {} after save_config; got {:?}",
        peer_addr,
        conf.peers.iter().map(|p| &p.address).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn test_remove_peer_not_found() {
    let server1 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // Remove non-existent peer
    let result = server1.client.remove_peer("192.168.1.1".to_string()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_remove_peer_success() {
    let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;
    let peer_addr = server2.address.to_string();

    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    let conf = server1.read_conf();
    assert!(
        !conf.peers.iter().any(|p| p.address == peer_addr),
        "rogg.conf must NOT contain peer until SaveConfig; got {:?}",
        conf.peers.iter().map(|p| &p.address).collect::<Vec<_>>()
    );

    server1.save_config().await.unwrap();
    let conf = server1.read_conf();
    assert!(
        conf.peers.iter().any(|p| p.address == peer_addr),
        "rogg.conf should contain peer after save"
    );

    server1.remove_peer(&server2).await;
    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 0);
    let conf = server1.read_conf();
    assert!(
        conf.peers.iter().any(|p| p.address == peer_addr),
        "rogg.conf still contains peer until next SaveConfig"
    );

    server1.save_config().await.unwrap();
    let conf = server1.read_conf();
    assert!(
        !conf.peers.iter().any(|p| p.address == peer_addr),
        "rogg.conf should not contain peer after save"
    );
}

#[tokio::test]
async fn test_get_peers_empty() {
    let server1 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 0);
}

#[tokio::test]
async fn test_get_peers_with_peers() {
    let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

    let peers = server1.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].address, server2.address.to_string());
    assert_eq!(peers[0].asn, server2.asn);
    assert_eq!(peers[0].state, BgpState::Established as i32);
}

#[tokio::test]
async fn test_get_peer_not_found() {
    let server1 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    let result = server1.client.get_peer("192.168.1.1".to_string()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_get_peer_success() {
    let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

    let (peer_opt, stats_opt) = server1
        .client
        .get_peer(server2.address.to_string())
        .await
        .unwrap();

    let peer = peer_opt.unwrap();
    assert_eq!(peer.address, server2.address.to_string());
    assert_eq!(peer.asn, server2.asn);
    assert_eq!(peer.state, BgpState::Established as i32);

    // Verify statistics exist
    let stats = stats_opt.unwrap();
    assert!(stats.open_sent > 0);
    assert!(stats.open_received > 0);
}

#[tokio::test]
async fn test_get_routes_empty() {
    let server1 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    let routes = server1
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    assert_eq!(routes.len(), 0);
}

#[tokio::test]
async fn test_announce_withdraw_route() {
    let server1 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // Announce route first
    announce_route(
        &server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Verify route exists
    let routes = server1
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    assert_eq!(routes.len(), 1);

    // Withdraw route
    let result = server1
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix("10.0.0.0/24".to_string())),
        })
        .await;
    assert!(result.is_ok());

    // Route should be gone
    let routes = server1
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    assert_eq!(routes.len(), 0);
}

#[tokio::test]
async fn test_withdraw_nonexistent_route() {
    let server1 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;

    // Withdraw route that was never announced (should succeed - idempotent)
    let result = server1
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix("10.0.0.0/24".to_string())),
        })
        .await;
    assert!(result.is_ok());

    // Routes should still be empty
    let routes = server1
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    assert_eq!(routes.len(), 0);
}

#[tokio::test]
async fn test_disable_enable_peer() {
    // Use short idle_hold_time to speed up reconnection after disable/enable
    let config = PeerConfig {
        idle_hold_time_secs: Some(1),
        ..Default::default()
    };
    let (server1, server2) = setup_two_peered_servers(config).await;

    // Disable peer
    server1
        .client
        .disable_peer(server2.address.to_string())
        .await
        .unwrap();

    // Peer should go to Idle with admin_state Down
    poll_until(
        || async {
            let peers = server1.client.get_peers().await.unwrap();
            peers.len() == 1
                && peers[0].state == BgpState::Idle as i32
                && peers[0].admin_state == AdminState::Down as i32
        },
        "Peer should be Idle with admin_state Down",
    )
    .await;

    // Disable persists across SaveConfig: rogg.conf records admin_down = true.
    server1.save_config().await.unwrap();
    let conf = server1.read_conf();
    let saved = conf
        .peers
        .iter()
        .find(|p| p.address == server2.address.to_string())
        .expect("peer in saved config");
    assert!(saved.admin_down, "rogg.conf must record admin_down = true");

    // Enable peer
    server1
        .client
        .enable_peer(server2.address.to_string())
        .await
        .unwrap();

    // Peer should reconnect and reach Established with admin_state Up
    // Use longer timeout to account for damping and retries
    poll_until_with_timeout(
        || async {
            let peers1 = server1.client.get_peers().await.unwrap();
            let peers2 = server2.client.get_peers().await.unwrap();
            eprintln!(
                "DEBUG: server1 peer: {:?}",
                peers1.first().map(|p| (p.state, p.admin_state))
            );
            eprintln!(
                "DEBUG: server2 peer: {:?}",
                peers2.first().map(|p| (p.state, p.admin_state))
            );
            peers1.len() == 1
                && peers1[0].state == BgpState::Established as i32
                && peers1[0].admin_state == AdminState::Up as i32
        },
        "Peer should be Established with admin_state Up",
        Duration::from_secs(30),
    )
    .await;

    // Enable persists too: rogg.conf clears admin_down.
    server1.save_config().await.unwrap();
    let conf = server1.read_conf();
    let saved = conf
        .peers
        .iter()
        .find(|p| p.address == server2.address.to_string())
        .expect("peer in saved config");
    assert!(
        !saved.admin_down,
        "rogg.conf must clear admin_down on enable"
    );
}

#[tokio::test]
async fn test_add_bmp_server() {
    let server = start_test_server(test_config(65001, 1)).await;

    let servers = server.client.get_bmp_servers().await.unwrap();
    assert_eq!(servers.len(), 0);

    let result = server
        .client
        .add_bmp_server("127.0.0.1:11019".to_string(), None)
        .await;
    assert!(result.is_ok());

    let result = server
        .client
        .add_bmp_server("127.0.0.1:11020".to_string(), None)
        .await;
    assert!(result.is_ok());

    let servers = server.client.get_bmp_servers().await.unwrap();
    assert_eq!(servers.len(), 2);
    assert!(servers.contains(&"127.0.0.1:11019".to_string()));
    assert!(servers.contains(&"127.0.0.1:11020".to_string()));
}

#[tokio::test]
async fn test_remove_bmp_server() {
    let server = start_test_server(test_config(65001, 1)).await;

    server
        .client
        .add_bmp_server("127.0.0.1:11019".to_string(), None)
        .await
        .unwrap();

    let servers = server.client.get_bmp_servers().await.unwrap();
    assert_eq!(servers.len(), 1);

    let result = server
        .client
        .remove_bmp_server("127.0.0.1:11019".to_string())
        .await;
    assert!(result.is_ok());

    let servers = server.client.get_bmp_servers().await.unwrap();
    assert_eq!(servers.len(), 0);
}

#[tokio::test]
async fn test_get_bmp_servers_empty() {
    let server = start_test_server(test_config(65001, 1)).await;

    let servers = server.client.get_bmp_servers().await.unwrap();
    assert_eq!(servers.len(), 0);
}

#[tokio::test]
async fn test_add_route_stream() {
    let server = start_test_server(test_config(65001, 1)).await;

    // Initially no routes
    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    assert_eq!(routes.len(), 0);

    // Create multiple routes
    let routes_to_add = vec![
        AddRouteRequest {
            route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.168.1.1".to_string(),
                origin: Origin::Igp as i32,
                ..Default::default()
            }))),
        },
        AddRouteRequest {
            route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                prefix: "10.0.1.0/24".to_string(),
                next_hop: "192.168.1.2".to_string(),
                origin: Origin::Igp as i32,
                ..Default::default()
            }))),
        },
        AddRouteRequest {
            route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                prefix: "10.0.2.0/24".to_string(),
                next_hop: "192.168.1.3".to_string(),
                origin: Origin::Igp as i32,
                ..Default::default()
            }))),
        },
    ];

    // Add routes using streaming API
    let count = server.client.add_route_stream(routes_to_add).await.unwrap();

    // Should have added 3 routes
    assert_eq!(count, 3);

    // Verify routes are in RIB
    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    assert_eq!(routes.len(), 3);
}

#[tokio::test]
async fn test_add_route_stream_with_invalid_route() {
    let server = start_test_server(test_config(65001, 1)).await;

    // Create routes with one invalid prefix
    let routes_to_add = vec![
        AddRouteRequest {
            route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.168.1.1".to_string(),
                origin: Origin::Igp as i32,
                ..Default::default()
            }))),
        },
        AddRouteRequest {
            route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                prefix: "invalid-prefix".to_string(),
                next_hop: "192.168.1.2".to_string(),
                origin: Origin::Igp as i32,
                ..Default::default()
            }))),
        },
        AddRouteRequest {
            route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                prefix: "10.0.2.0/24".to_string(),
                next_hop: "192.168.1.3".to_string(),
                origin: Origin::Igp as i32,
                ..Default::default()
            }))),
        },
    ];

    // Add routes using streaming API
    let count = server.client.add_route_stream(routes_to_add).await.unwrap();

    // Should have added 2 routes (invalid one skipped)
    assert_eq!(count, 2);

    // Verify only valid routes are in RIB
    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    assert_eq!(routes.len(), 2);
}

async fn test_list_routes_impl(use_stream: bool) {
    let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

    // Server2 announces routes to Server1 (empty AS_PATH = local routes)
    let server2_addr = server2.address.to_string();
    for i in 0..5 {
        announce_route(
            &server2,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: format!("10.{}.0.0/24", i),
                next_hop: server2_addr.clone(),
                as_path: vec![], // Empty AS_PATH - local route,
                ..Default::default()
            })),
        )
        .await;
    }

    // Server1 also announces local routes
    for i in 10..15 {
        announce_route(
            &server1,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: format!("10.{}.0.0/24", i),
                next_hop: "192.168.1.1".to_string(),
                ..Default::default()
            })),
        )
        .await;
    }

    // Wait for routes to propagate
    poll_until(
        || async {
            let routes = server1
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .unwrap();
            routes.len() == 10
        },
        "Timeout waiting for 10 routes in server1",
    )
    .await;

    // Test 1: GLOBAL - Should see all routes (5 from peer + 5 local)
    let global_routes = if use_stream {
        server1
            .client
            .list_routes_stream(ListRoutesRequest::default())
            .await
            .unwrap()
    } else {
        server1
            .client
            .list_routes(ListRoutesRequest::default())
            .await
            .unwrap()
    };
    assert_eq!(global_routes.len(), 10);

    // Test 2: ADJ_IN - Should only see routes received from server2
    let adj_in_req = ListRoutesRequest {
        rib_type: Some(RibType::AdjIn as i32),
        peer_address: Some(server2.address.to_string()),
        ..Default::default()
    };
    let adj_in_routes = if use_stream {
        server1
            .client
            .list_routes_stream(adj_in_req.clone())
            .await
            .unwrap()
    } else {
        server1
            .client
            .list_routes(adj_in_req.clone())
            .await
            .unwrap()
    };

    // Export policy prepends server2's ASN: [] -> [65002]
    // eBGP: no LOCAL_PREF
    let expected_adj_in: Vec<Route> = (0..5)
        .map(|i| {
            expected_route(
                &format!("10.{}.0.0/24", i),
                PathParams {
                    local_pref: None, // eBGP - no LOCAL_PREF
                    ..PathParams::from_peer(&server2)
                },
            )
        })
        .collect();

    assert!(routes_match(
        &adj_in_routes,
        &expected_adj_in,
        ExpectPathId::Ignore
    ));

    // Test 3: ADJ_OUT - Should see routes that server1 would send to server2
    let adj_out_req = ListRoutesRequest {
        rib_type: Some(RibType::AdjOut as i32),
        peer_address: Some(server2.address.to_string()),
        ..Default::default()
    };
    let adj_out_routes = if use_stream {
        server1
            .client
            .list_routes_stream(adj_out_req.clone())
            .await
            .unwrap()
    } else {
        server1
            .client
            .list_routes(adj_out_req.clone())
            .await
            .unwrap()
    };

    // Export policy prepends server1's ASN: [] -> [65001]
    // eBGP: no LOCAL_PREF, NEXT_HOP rewritten to local session address
    let expected_adj_out: Vec<Route> = (10..15)
        .map(|i| {
            expected_route(
                &format!("10.{}.0.0/24", i),
                PathParams {
                    peer_address: "127.0.0.1".to_string(),
                    local_pref: None, // eBGP - no LOCAL_PREF
                    ..PathParams::from_peer(&server1)
                },
            )
        })
        .collect();

    assert!(routes_match(
        &adj_out_routes,
        &expected_adj_out,
        ExpectPathId::Present
    ));
}

#[tokio::test]
async fn test_list_routes() {
    test_list_routes_impl(false).await;
}

#[tokio::test]
async fn test_list_routes_stream() {
    test_list_routes_impl(true).await;
}

#[tokio::test]
async fn test_list_peers_stream() {
    let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

    let peers = server1.client.get_peers_stream().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert!(verify_peers(&server1, vec![server2.to_peer(BgpState::Established)]).await);
}

#[tokio::test]
async fn test_get_running_config() {
    // Verifies the GetRunningConfig RPC renders the daemon's current state
    // (server-level settings + live peers from self.peers) as parseable
    // rogg.conf text.
    let server = start_test_server(BgpConfig::new(
        65042,
        "127.0.0.1:0",
        Ipv4Addr::new(10, 0, 0, 1),
        90,
    ))
    .await;

    server
        .client
        .add_peer(
            "10.0.0.5".to_string(),
            Some(SessionConfig {
                asn: Some(65099),
                port: Some(179),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    let text = server.client.get_running_config().await.unwrap();

    // Server-level fields + peer block (address is the block header).
    assert!(text.contains("service bgp {"), "missing service: {}", text);
    assert!(text.contains("asn 65042"), "missing asn: {}", text);
    assert!(
        text.contains("router-id 10.0.0.1"),
        "missing router-id: {}",
        text
    );
    assert!(text.contains("hold-time 90"), "missing hold-time: {}", text);
    assert!(
        text.contains("peer 10.0.0.5 {"),
        "missing peer block: {}",
        text
    );
    assert!(
        text.contains("remote-as 65099"),
        "missing remote-as: {}",
        text
    );

    // Round-trip: output must reparse into an equivalent BgpConfig.
    let reparsed = BgpConfig::from_conf_str(&text).unwrap();
    assert_eq!(reparsed.asn, 65042);
    assert_eq!(reparsed.router_id, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(reparsed.hold_time_secs, 90);
    assert_eq!(reparsed.peers.len(), 1);
    let saved = reparsed.peers.first().unwrap();
    assert_eq!(saved.address, "10.0.0.5");
    assert_eq!(saved.asn, Some(65099));
}

#[tokio::test]
async fn test_get_server_info() {
    let server = start_test_server(test_config(65001, 1)).await;

    // Initially should have 0 routes
    verify_server_info(&server, Ipv4Addr::new(127, 0, 0, 1), server.bgp_port, 0).await;

    // Add some routes
    for i in 0..5 {
        announce_route(
            &server,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: format!("10.{}.0.0/24", i),
                next_hop: "192.168.1.1".to_string(),
                ..Default::default()
            })),
        )
        .await;
    }

    // Should now have 5 routes
    verify_server_info(&server, Ipv4Addr::new(127, 0, 0, 1), server.bgp_port, 5).await;

    // Remove 2 routes
    server
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix("10.0.0.0/24".to_string())),
        })
        .await
        .unwrap();
    server
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix("10.1.0.0/24".to_string())),
        })
        .await
        .unwrap();

    // Should now have 3 routes
    verify_server_info(&server, Ipv4Addr::new(127, 0, 0, 1), server.bgp_port, 3).await;
}

#[tokio::test]
async fn test_extended_community_roundtrip() {
    use bgpgg::bgp::ext_community::*;
    use bgpgg::grpc::proto::extended_community::Community;
    use bgpgg::grpc::proto_community::u64_to_proto_extcomm;

    let server = start_test_server(BgpConfig::new(
        64512,
        "127.0.0.1:0",
        Ipv4Addr::new(127, 0, 0, 1),
        90,
    ))
    .await;

    // Create route with extended communities using helper functions
    let ext_comms_u64 = [
        from_two_octet_as(2, 65000, 100), // RT:65000:100
        from_ipv4(2, u32::from(Ipv4Addr::new(192, 168, 1, 1)), 200), // RT:192.168.1.1:200
        from_four_octet_as(3, 4200000000, 300), // RO:4200000000:300
    ];
    let ext_comms: Vec<_> = ext_comms_u64
        .iter()
        .map(|ec| u64_to_proto_extcomm(*ec))
        .collect();

    server
        .client
        .add_route(AddRouteRequest {
            route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.0.2.1".to_string(),
                origin: Origin::Igp as i32,
                local_pref: Some(100),
                extended_communities: ext_comms.clone(),
                ..Default::default()
            }))),
        })
        .await
        .unwrap();

    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].paths.len(), 1);

    let returned_ext_comms = &routes[0].paths[0].extended_communities;
    assert_eq!(returned_ext_comms.len(), 3);

    // Verify first ext comm (two-octet AS)
    let first = &returned_ext_comms[0].community;
    match first {
        Some(Community::TwoOctetAs(ec)) => {
            assert!(ec.is_transitive);
            assert_eq!(ec.sub_type, 2);
            assert_eq!(ec.asn, 65000);
            assert_eq!(ec.local_admin, 100);
        }
        _ => panic!("Expected TwoOctetAs"),
    }

    // Verify second ext comm (IPv4)
    let second = &returned_ext_comms[1].community;
    match second {
        Some(Community::Ipv4Address(ec)) => {
            assert!(ec.is_transitive);
            assert_eq!(ec.sub_type, 2);
            assert_eq!(ec.address, "192.168.1.1");
            assert_eq!(ec.local_admin, 200);
        }
        _ => panic!("Expected Ipv4Address"),
    }

    // Verify third ext comm (four-octet AS)
    let third = &returned_ext_comms[2].community;
    match third {
        Some(Community::FourOctetAs(ec)) => {
            assert!(ec.is_transitive);
            assert_eq!(ec.sub_type, 3);
            assert_eq!(ec.asn, 4200000000);
            assert_eq!(ec.local_admin, 300);
        }
        _ => panic!("Expected FourOctetAs"),
    }
}

#[tokio::test]
async fn test_add_route_with_invalid_prefix_length() {
    let server = start_test_server(test_config(65001, 1)).await;

    // Test IPv4 with prefix length > 32
    let result = server
        .client
        .add_route(AddRouteRequest {
            route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                prefix: "1.1.1.0/123".to_string(),
                next_hop: "192.0.2.1".to_string(),
                origin: Origin::Igp as i32,
                ..Default::default()
            }))),
        })
        .await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("IPv4 prefix length 123 exceeds 32"));

    // Test IPv4 with prefix length = 33
    let result = server
        .client
        .add_route(AddRouteRequest {
            route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                prefix: "10.0.0.0/33".to_string(),
                next_hop: "192.0.2.1".to_string(),
                origin: Origin::Igp as i32,
                ..Default::default()
            }))),
        })
        .await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("IPv4 prefix length 33 exceeds 32"));

    // Test IPv6 with prefix length > 128
    let result = server
        .client
        .add_route(AddRouteRequest {
            route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                prefix: "2001:db8::/200".to_string(),
                next_hop: "2001:db8::1".to_string(),
                origin: Origin::Igp as i32,
                ..Default::default()
            }))),
        })
        .await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("IPv6 prefix length 200 exceeds 128"));

    // Verify no routes were added
    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    assert_eq!(routes.len(), 0);
}

/// API reports configured peer ASN when session is down.
#[tokio::test]
async fn test_peer_asn_api_fallback() {
    let server = start_test_server(test_config(65001, 1)).await;

    // Add peer with asn but don't start the other side
    server
        .client
        .add_peer(
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                passive_mode: Some(true),
                asn: Some(65002),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // list_peers should report configured asn when down
    let peers = server.client.get_peers().await.unwrap();
    let peer = peers.iter().find(|p| p.address == "127.0.0.2").unwrap();
    assert_eq!(peer.asn, 65002, "should show configured asn when down");
    assert_ne!(peer.state, BgpState::Established as i32);

    // get_peer should also report it
    let (peer_detail, _) = server
        .client
        .get_peer("127.0.0.2".to_string())
        .await
        .unwrap();
    assert_eq!(peer_detail.unwrap().asn, 65002);
}

#[tokio::test]
async fn test_add_peer_invalid_ttl_min() {
    let server = start_test_server(test_config(65001, 1)).await;
    for ttl in [0u32, 256, 1000] {
        let result = server
            .client
            .add_peer(
                "127.0.0.2".to_string(),
                Some(SessionConfig {
                    ttl_min: Some(ttl),
                    ..Default::default()
                }),
            )
            .await;
        assert!(result.is_err(), "ttl_min={ttl} should be rejected");
        assert_eq!(
            result.unwrap_err().code(),
            tonic::Code::InvalidArgument,
            "ttl_min={ttl}"
        );
    }
}

#[tokio::test]
async fn test_add_peer_with_llgr() {
    let server = start_test_server(test_config(65001, 1)).await;

    // Add passive peer with GR + LLGR via gRPC
    server
        .client
        .add_peer(
            "127.0.0.2".to_string(),
            Some(SessionConfig {
                passive_mode: Some(true),
                graceful_restart: Some(GracefulRestartConfig {
                    enabled: Some(true),
                    restart_time_secs: Some(90),
                }),
                llgr: Some(ProtoLlgrConfig {
                    enabled: Some(true),
                    stale_time_secs: Some(3600),
                    afi_safis: vec![ProtoAfiSafi { afi: 1, safi: 1 }],
                }),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // Verify get_peer returns the LLGR config
    let (peer, _) = server
        .client
        .get_peer("127.0.0.2".to_string())
        .await
        .unwrap();
    let session_config = peer.unwrap().session_config.unwrap();
    let llgr = session_config.llgr.unwrap();
    assert_eq!(llgr.enabled, Some(true));
    assert_eq!(llgr.stale_time_secs, Some(3600));
    assert_eq!(llgr.afi_safis.len(), 1);
    assert_eq!(llgr.afi_safis[0].afi, 1);
    assert_eq!(llgr.afi_safis[0].safi, 1);
}

/// gRPC: Add, list, and remove RPKI caches.
#[tokio::test]
async fn test_rpki_add_list_remove() {
    let server = start_test_server(test_config(65001, 1)).await;

    // No caches initially
    let resp = server.client.list_rpki_caches().await.unwrap();
    assert!(resp.caches.is_empty());
    assert_eq!(resp.total_vrp_count, 0);

    // Add a cache via gRPC
    let msg = server
        .client
        .add_rpki_cache(AddRpkiCacheRequest {
            address: "10.0.0.2:323".to_string(),
            preference: Some(5),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(msg.contains("added"));

    // List should show the cache
    let resp = server.client.list_rpki_caches().await.unwrap();
    assert_eq!(resp.caches.len(), 1);
    assert_eq!(resp.caches[0].address, "10.0.0.2:323");
    assert_eq!(resp.caches[0].preference, 5);
    assert_eq!(resp.caches[0].transport, "tcp");
    assert!(resp.caches[0].session_active);

    // Remove the cache
    let msg = server
        .client
        .remove_rpki_cache("10.0.0.2:323".to_string())
        .await
        .unwrap();
    assert!(msg.contains("removed"));

    // List should be empty again
    let resp = server.client.list_rpki_caches().await.unwrap();
    assert!(resp.caches.is_empty());
}

/// gRPC: AddRpkiCache with SSH transport validates required fields.
#[tokio::test]
async fn test_rpki_add_ssh_missing_fields() {
    let server = start_test_server(test_config(65001, 1)).await;

    // SSH transport without username -> error
    let result = server
        .client
        .add_rpki_cache(AddRpkiCacheRequest {
            address: "10.0.0.2:22".to_string(),
            transport: Some("ssh".to_string()),
            ..Default::default()
        })
        .await;
    assert!(result.is_err());

    // SSH transport without private key -> error
    let result = server
        .client
        .add_rpki_cache(AddRpkiCacheRequest {
            address: "10.0.0.2:22".to_string(),
            transport: Some("ssh".to_string()),
            ssh_username: Some("rpki".to_string()),
            ..Default::default()
        })
        .await;
    assert!(result.is_err());
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

#[tokio::test]
async fn test_add_ls_route() {
    let server = start_test_server(BgpConfig::new(
        64512,
        "127.0.0.1:0",
        Ipv4Addr::new(127, 0, 0, 1),
        90,
    ))
    .await;

    let nlri = make_ls_node_nlri(65001, &[10, 0, 0, 1]);
    let attr = make_ls_attr("router1");

    server
        .client
        .add_route(AddRouteRequest {
            route: Some(add_route_request::Route::Ls(Box::new(AddLsRouteRequest {
                nlri: Some(nlri),
                attribute: Some(attr),
                next_hop: None,
            }))),
        })
        .await
        .unwrap();

    // LS route should appear in unfiltered get_routes
    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    let ls_routes: Vec<&Route> = routes
        .iter()
        .filter(|r| matches!(&r.key, Some(route::Key::LsNlri(_))))
        .collect();
    assert_eq!(ls_routes.len(), 1, "expected 1 LS route in unfiltered list");

    let route = ls_routes[0];
    let nlri = match &route.key {
        Some(route::Key::LsNlri(n)) => n,
        _ => panic!("expected LS NLRI key"),
    };
    assert_eq!(nlri.nlri_type, LsNlriType::LsNode as i32);
    assert_eq!(nlri.protocol_id, LsProtocolId::LsDirect as i32);
    let local_node = nlri.local_node.as_ref().unwrap();
    assert_eq!(local_node.as_number, Some(65001));

    // Verify LS attribute roundtrip (ls_attribute moved to Path)
    let ls_attr = route.paths[0].ls_attribute.as_ref().unwrap();
    let node_attr = ls_attr.node.as_ref().unwrap();
    assert_eq!(node_attr.name, Some("router1".to_string()));
    assert_eq!(node_attr.ipv4_router_id, Some("10.0.0.1".to_string()));
}

#[tokio::test]
async fn test_remove_ls_route() {
    let server = start_test_server(BgpConfig::new(
        64512,
        "127.0.0.1:0",
        Ipv4Addr::new(127, 0, 0, 1),
        90,
    ))
    .await;

    let nlri = make_ls_node_nlri(65001, &[10, 0, 0, 1]);
    let attr = make_ls_attr("router1");

    // Add
    server
        .client
        .add_route(AddRouteRequest {
            route: Some(add_route_request::Route::Ls(Box::new(AddLsRouteRequest {
                nlri: Some(nlri.clone()),
                attribute: Some(attr),
                next_hop: None,
            }))),
        })
        .await
        .unwrap();

    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    assert_eq!(
        routes
            .iter()
            .filter(|r| matches!(&r.key, Some(route::Key::LsNlri(_))))
            .count(),
        1
    );

    // Remove
    server
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::LsNlri(Box::new(nlri))),
        })
        .await
        .unwrap();

    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    assert_eq!(
        routes
            .iter()
            .filter(|r| matches!(&r.key, Some(route::Key::LsNlri(_))))
            .count(),
        0,
        "LS route should be removed"
    );
}

/// RFC 9552 Section 8.2.3: configured Instance-ID is applied to locally originated LS routes.
#[tokio::test]
async fn test_ls_instance_id_config() {
    let mut config = BgpConfig::new(64512, "127.0.0.1:0", Ipv4Addr::new(127, 0, 0, 1), 90);
    config.bgp_ls.instance_id = 99;
    let server = start_test_server(config).await;

    // Inject LS route with identifier=0 (unset by caller)
    let nlri = make_ls_node_nlri(65001, &[10, 0, 0, 1]);
    assert_eq!(nlri.identifier, 0);

    server
        .client
        .add_route(AddRouteRequest {
            route: Some(add_route_request::Route::Ls(Box::new(AddLsRouteRequest {
                nlri: Some(nlri),
                attribute: Some(make_ls_attr("router1")),
                next_hop: None,
            }))),
        })
        .await
        .unwrap();

    let routes = server
        .client
        .list_routes(ListRoutesRequest {
            afi: Some(16388),
            safi: Some(71),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(routes.len(), 1);

    let stored_nlri = match &routes[0].key {
        Some(route::Key::LsNlri(n)) => n,
        _ => panic!("expected LS NLRI key"),
    };
    assert_eq!(
        stored_nlri.identifier, 99,
        "configured instance_id should be applied"
    );
}

#[tokio::test]
async fn test_list_routes_family_filter() {
    let server = start_test_server(BgpConfig::new(
        64512,
        "127.0.0.1:0",
        Ipv4Addr::new(127, 0, 0, 1),
        90,
    ))
    .await;

    // Add an IP route
    server
        .client
        .add_route(AddRouteRequest {
            route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.0.2.1".to_string(),
                origin: Origin::Igp as i32,
                ..Default::default()
            }))),
        })
        .await
        .unwrap();

    // Add an LS route
    let nlri = make_ls_node_nlri(65001, &[10, 0, 0, 1]);
    server
        .client
        .add_route(AddRouteRequest {
            route: Some(add_route_request::Route::Ls(Box::new(AddLsRouteRequest {
                nlri: Some(nlri),
                attribute: Some(make_ls_attr("router1")),
                next_hop: None,
            }))),
        })
        .await
        .unwrap();

    // Unfiltered: both routes
    let all = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .unwrap();
    assert_eq!(all.len(), 2, "should have 1 IP + 1 LS route");

    // Filter by IPv4 unicast (AFI=1, SAFI=1): only IP route
    let ipv4_only = server
        .client
        .list_routes(ListRoutesRequest {
            afi: Some(1),
            safi: Some(1),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(ipv4_only.len(), 1, "should have 1 IPv4 route");
    assert!(matches!(
        &ipv4_only[0].key,
        Some(route::Key::Prefix(p)) if !p.is_empty()
    ));

    // Filter by BGP-LS (AFI=16388, SAFI=71): only LS route
    let ls_only = server
        .client
        .list_routes(ListRoutesRequest {
            afi: Some(16388),
            safi: Some(71),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(ls_only.len(), 1, "should have 1 LS route");
    assert!(matches!(&ls_only[0].key, Some(route::Key::LsNlri(_))));
}

// ---------------------------------------------------------------------------
// Snapshot rotation / rollback / fail-hard
// ---------------------------------------------------------------------------

/// Number of snapshots kept on disk; mirrors `core::server::config::SNAPSHOT_COUNT`.
const SNAPSHOT_COUNT: u32 = 10;

/// Drive a fresh commit by adding one more BMP server; each call produces a
/// distinct config diff so snapshot rotation can be observed.
async fn commit_once(server: &TestServer, port: u16) {
    // Imperative AddBmpServer no longer persists; pair it with SaveConfig so
    // each call exercises the same rotate-snapshot + atomic-write pipeline as
    // before.
    server
        .client
        .add_bmp_server(format!("127.0.0.1:{}", port), None)
        .await
        .expect("add bmp server");
    server.save_config().await.expect("save config");
}

#[tokio::test]
async fn test_first_commit_rotates_startup_state() {
    // bgpggd reads rogg.conf at startup, so the file already exists when the
    // first commit lands. The first commit therefore rotates the startup
    // state into rogg.1.conf.
    let server = start_test_server(test_config(65001, 1)).await;

    assert!(!server.snapshot_exists(1), "no snapshot before any commit");

    commit_once(&server, 11100).await;
    assert!(
        server.snapshot_exists(1),
        "first commit rotates the startup-loaded rogg.conf into rogg.1.conf"
    );
}

#[tokio::test]
async fn test_commit_rotates_snapshots() {
    let server = start_test_server(test_config(65001, 1)).await;

    // Each commit rotates: startup file -> .1 on first commit, .1 -> .2 on
    // second commit, etc. After SNAPSHOT_COUNT+1 commits the oldest is
    // dropped and we have exactly SNAPSHOT_COUNT snapshots.
    let total = SNAPSHOT_COUNT + 1;
    for i in 0..total {
        commit_once(&server, 11200 + i as u16).await;
    }

    for i in 1..=SNAPSHOT_COUNT {
        assert!(
            server.snapshot_exists(i),
            "snapshot {} should exist after {} commits",
            i,
            total
        );
    }
    assert!(
        !server.snapshot_exists(SNAPSHOT_COUNT + 1),
        "snapshot {} should not exist (oldest dropped)",
        SNAPSHOT_COUNT + 1
    );

    // .1 reflects the state just before the most recent commit: total-1 BMP
    // servers (the most recent commit added the Nth).
    let snap1 = server.read_snapshot(1);
    assert_eq!(
        snap1.bmp_servers.len(),
        (total - 1) as usize,
        ".1 should reflect the prior state"
    );
    let current = server.read_conf();
    assert_eq!(current.bmp_servers.len(), total as usize);
}

#[tokio::test]
async fn test_list_snapshots() {
    let server = start_test_server(test_config(65001, 1)).await;

    // Four commits -> four snapshots (each commit rotates the prior file).
    for i in 0..4 {
        commit_once(&server, 11300 + i as u16).await;
    }
    let snapshots = server.client.list_config_snapshots().await.unwrap();
    assert_eq!(snapshots.len(), 4);
    let indices: Vec<u32> = snapshots.iter().map(|s| s.index).collect();
    assert_eq!(indices, vec![1, 2, 3, 4]);
    for snap in &snapshots {
        assert!(snap.size_bytes > 0, "snapshot {} has size", snap.index);
        assert!(snap.mtime_unix > 0, "snapshot {} has mtime", snap.index);
    }
}

#[tokio::test]
async fn test_rollback_restores_previous() {
    let server = start_test_server(test_config(65001, 1)).await;

    // Commit A: 1 BMP server.
    commit_once(&server, 11400).await;
    let conf_a = server.read_conf();

    // Commit B: 2 BMP servers. `rogg.1.conf` now holds A.
    commit_once(&server, 11401).await;
    let conf_b = server.read_conf();
    assert_eq!(conf_b.bmp_servers.len(), 2);

    // Roll back to A.
    server.rollback_config(1).await.unwrap();

    // Running config matches A.
    let after = server.read_conf();
    assert_eq!(after.bmp_servers.len(), 1);
    assert_eq!(after.bmp_servers[0].address, conf_a.bmp_servers[0].address);

    // New `.1` preserves forward history: it's the state we just left (B).
    let new_snap = server.read_snapshot(1);
    assert_eq!(new_snap.bmp_servers.len(), 2);
    assert_eq!(
        new_snap.bmp_servers[1].address,
        conf_b.bmp_servers[1].address
    );
}

#[tokio::test]
async fn test_apply_failure_no_revert() {
    let server = start_test_server(test_config(65001, 1)).await;

    // Establish a known-good state with one BMP server. First commit
    // rotates the startup file into rogg.1.conf.
    commit_once(&server, 11500).await;
    let before = server.read_conf();
    assert_eq!(before.bmp_servers.len(), 1);
    assert!(server.snapshot_exists(1));
    assert!(!server.snapshot_exists(2), "only one rotation so far");

    // Bad BMP address: peer validator and `reject_unsupported_changes` pass;
    // apply fails inside `reconfigure_bmp_servers` when it parses the address.
    let bad_candidate = format!(
        "router-id {}\nasn 65001\nlisten-addr \"{}\"\nbmp-server \"not-a-valid-address\" {{}}\n",
        before.router_id, before.listen_addr
    );
    let result = server.commit_config(bad_candidate).await;
    assert!(result.is_err(), "commit with bad BMP address must fail");

    // rogg.conf unchanged; no snapshot rotation triggered by the failure.
    let after = server.read_conf();
    assert_eq!(after.bmp_servers.len(), 1);
    assert_eq!(
        after.bmp_servers[0].address, before.bmp_servers[0].address,
        "failed commit must not mutate rogg.conf"
    );
    assert!(
        !server.snapshot_exists(2),
        "failed commit must not rotate snapshots"
    );
}

#[tokio::test]
async fn test_save_config_rotates_snapshot() {
    // Calling save twice rotates the prior rogg.conf into rogg.1.conf,
    // exercising the same persist pipeline as commit but without going
    // through reconfigure.
    let server = start_test_server(test_config(65001, 1)).await;

    server.save_config().await.expect("first save");
    assert!(
        server.snapshot_exists(1),
        "save rotates startup file into .1"
    );

    let conf = server.read_conf();
    assert_eq!(conf.asn, 65001);

    server.save_config().await.expect("second save");
    assert!(server.snapshot_exists(2), "second save shifts .1 -> .2");
}

/// Opens the lock file with EX flock held for as long as the returned
/// File lives. Optionally writes `uuid` into the file content.
/// Mirrors what `ggsh configure` does.
fn hold_exclusive_lock_with_uuid(server: &TestServer, uuid: Option<uuid::Uuid>) -> std::fs::File {
    use std::io::Write;
    let lock_path = server.lock_path();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(true)
        .open(&lock_path)
        .expect("open lock file");
    file.lock().expect("acquire EX flock");
    if let Some(uuid) = uuid {
        write!(file, "{}", uuid).expect("write UUID");
        file.flush().expect("flush");
    }
    file
}

#[tokio::test]
async fn test_add_peer_blocked_by_session_lock_then_resumes() {
    let server = start_test_server(test_config(65001, 1)).await;
    let cfg = SessionConfig {
        port: Some(179),
        ..Default::default()
    };

    {
        let _held = hold_exclusive_lock_with_uuid(&server, None);
        let err = server
            .client
            .add_peer("10.0.0.99".to_string(), Some(cfg.clone()))
            .await
            .expect_err("add_peer rejected while EX held");
        assert!(
            err.message().contains("config locked"),
            "got: {}",
            err.message()
        );
    }

    server
        .client
        .add_peer("10.0.0.99".to_string(), Some(cfg))
        .await
        .expect("add_peer succeeds after lock released");
}

#[tokio::test]
async fn test_save_and_commit_uuid_check() {
    let server = start_test_server(test_config(65001, 1)).await;
    let real = conf::fs::make_session_uuid();
    let other = conf::fs::make_session_uuid();
    let text = || server.read_conf().to_conf_str();

    // No session: any UUID rejected.
    let save_err = server.client.save_config(other).await.unwrap_err();
    assert!(
        save_err.message().contains("no active configure session"),
        "save no-session: got {}",
        save_err.message()
    );
    let commit_err = server
        .client
        .commit_config(text(), other)
        .await
        .unwrap_err();
    assert!(
        commit_err.message().contains("no active configure session"),
        "commit no-session: got {}",
        commit_err.message()
    );

    // Session held with `real`: wrong UUID rejected.
    let _held = hold_exclusive_lock_with_uuid(&server, Some(real));
    let save_err = server.client.save_config(other).await.unwrap_err();
    assert!(
        save_err.message().contains("session UUID mismatch"),
        "save mismatch: got {}",
        save_err.message()
    );
    let commit_err = server
        .client
        .commit_config(text(), other)
        .await
        .unwrap_err();
    assert!(
        commit_err.message().contains("session UUID mismatch"),
        "commit mismatch: got {}",
        commit_err.message()
    );
}

/// Validates that the brace-format text produced by ggsh's per-block AST
/// (via `Display`) round-trips through the daemon's `commit_config` and lands
/// in both `self.config` and on-disk `rogg.conf`. The candidate is built
/// directly from `conf::language_bgp` types to mirror what the
/// `apply_set_*` functions in `ggsh/src/cmd_configure.rs` produce.
#[tokio::test]
async fn test_ggsh_set_then_commit_persists() {
    use conf::language::{Root, Service};
    use conf::language_bgp::{
        BgpServiceBody, FamilyBlock, FamilyDirective, PeerBlock, PolicyBlock, PolicyRule,
        PrefixListBlock, Setting,
    };

    let server = start_test_server(test_config(65001, 1)).await;
    let starting = server.read_conf();
    let asn = starting.asn;
    let router_id = starting.router_id;
    let listen_addr = starting.listen_addr.clone();

    let body = BgpServiceBody {
        settings: vec![
            Setting::Asn(asn),
            Setting::RouterId(router_id),
            Setting::ListenAddr(listen_addr.clone()),
            Setting::SysName("test-bgpgg-127.0.0.1".to_string()),
            Setting::SysDescr("test bgpgg router".to_string()),
        ],
        peers: vec![PeerBlock {
            address: "10.0.0.1".to_string(),
            settings: vec![
                Setting::RemoteAs(65002),
                Setting::Interface("eth0".to_string()),
                Setting::NextHopSelf(true),
            ],
            families: vec![FamilyBlock {
                afi: conf::bgp::Afi::Ipv4,
                safi: conf::bgp::Safi::Unicast,
                directives: vec![FamilyDirective::ExportPolicy("mine-only".to_string())],
            }],
        }],
        policies: vec![PolicyBlock {
            name: "mine-only".to_string(),
            rules: vec![
                PolicyRule::Match {
                    set_name: "my-prefixes".to_string(),
                    action: "accept".to_string(),
                },
                PolicyRule::Default {
                    action: "reject".to_string(),
                },
            ],
        }],
        prefix_lists: vec![PrefixListBlock {
            name: "my-prefixes".to_string(),
            prefixes: vec![conf::language_bgp::PrefixListEntry {
                prefix: "172.23.211.0/27".to_string(),
                range: None,
            }],
        }],
        neighbor_sets: Vec::new(),
        as_path_sets: Vec::new(),
        community_sets: Vec::new(),
        ext_community_sets: Vec::new(),
        large_community_sets: Vec::new(),
        bmp_servers: Vec::new(),
        rpki_caches: Vec::new(),
        bgp_ls: None,
    };
    let candidate = Root {
        services: vec![Service::Bgp(body)],
    };

    server
        .commit_config(candidate.to_string())
        .await
        .expect("commit succeeds");

    // Daemon's persisted view reflects the new peer settings.
    let after = server.read_conf();
    assert_eq!(after.peers.len(), 1, "peer added");
    let added = after.peers.first().unwrap();
    assert_eq!(added.address, "10.0.0.1");
    assert_eq!(added.asn, Some(65002));
    assert_eq!(added.interface.as_deref(), Some("eth0"));
    assert!(added.next_hop_self);

    // policy / prefix-list / family blocks now survive the round-trip.
    assert_eq!(after.policy_definitions.len(), 1);
    assert_eq!(after.policy_definitions[0].name, "mine-only");
    assert_eq!(after.policy_definitions[0].statements.len(), 2);

    assert_eq!(after.defined_sets.prefix_sets.len(), 1);
    assert_eq!(after.defined_sets.prefix_sets[0].name, "my-prefixes");
    assert_eq!(
        after.defined_sets.prefix_sets[0].prefixes[0].prefix,
        "172.23.211.0/27"
    );

    assert_eq!(
        added.export_policy_for(conf::bgp::Afi::Ipv4, conf::bgp::Safi::Unicast),
        ["mine-only".to_string()]
    );
}

/// Configure-mode commits with `originate` entries must reconcile with the
/// loc-RIB at runtime: adds inject local routes, removes withdraw them, and
/// nexthop changes round-trip as withdraw + announce. Pre-validation rejects
/// invalid prefixes without touching server state.
#[tokio::test]
async fn test_config_originate_route() {
    let server = start_test_server(test_config(65001, 1)).await;
    let originate = |prefix: &str, nexthop: &str| OriginateRoute {
        prefix: prefix.to_string(),
        nexthop: nexthop.to_string(),
    };
    let commit = |entries: Vec<OriginateRoute>| async {
        let mut cfg = server.read_conf();
        cfg.originate = entries;
        server.commit_config(cfg.to_conf_str()).await
    };
    // Locally-originated routes carry an empty AS_PATH, IGP origin, default
    // local-pref 100, and the synthetic LOCAL_ROUTE_SOURCE_STR peer address.
    let local = |prefix: &str, nexthop: &str| {
        expected_route(
            prefix,
            PathParams {
                next_hop: nexthop.to_string(),
                peer_address: "127.0.0.1".to_string(),
                local_pref: Some(100),
                ..Default::default()
            },
        )
    };

    // 1) Initial commit adds two originated routes.
    commit(vec![
        originate("10.99.0.0/24", "192.168.1.1"),
        originate("10.100.0.0/24", "192.168.1.2"),
    ])
    .await
    .expect("commit 1");
    poll_rib(&[(
        &server,
        vec![
            local("10.99.0.0/24", "192.168.1.1"),
            local("10.100.0.0/24", "192.168.1.2"),
        ],
    )])
    .await;

    // 2) Change one nexthop, keep one unchanged, add a third.
    commit(vec![
        originate("10.99.0.0/24", "192.168.1.99"),
        originate("10.100.0.0/24", "192.168.1.2"),
        originate("10.101.0.0/24", "192.168.1.3"),
    ])
    .await
    .expect("commit 2");
    poll_rib(&[(
        &server,
        vec![
            local("10.99.0.0/24", "192.168.1.99"),
            local("10.100.0.0/24", "192.168.1.2"),
            local("10.101.0.0/24", "192.168.1.3"),
        ],
    )])
    .await;

    // 3) Drop every originate. loc-RIB must end empty.
    commit(vec![]).await.expect("commit 3");
    poll_route_withdrawal(&[&server]).await;

    // 4) Bad prefix is rejected at validate-time. State stays clean.
    let err = commit(vec![originate("not-a-prefix", "192.168.1.1")])
        .await
        .expect_err("bad prefix must be rejected");
    assert!(
        err.message().contains("invalid prefix"),
        "expected validate failure, got: {}",
        err.message()
    );
    poll_route_withdrawal(&[&server]).await;
}
