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

//! Tests for BGP CEASE notifications per RFC 4271 Section 6.7

mod utils;
pub use utils::*;

use bgpgg::bgp::msg_notification::{BgpError, CeaseSubcode};
use bgpgg::grpc::proto::{
    AdminState, BgpState, ListRoutesRequest, MaxPrefixAction, MaxPrefixSetting, Peer, SessionConfig,
};
use conf::bgp::BgpConfig;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_max_prefix_limit() {
    // (name, action, allow_automatic_stop, expect_disconnect)
    let test_cases = vec![
        // Terminate with allow_automatic_stop=true: disconnects
        ("terminate", MaxPrefixAction::Terminate as i32, None, true),
        // Discard: stays connected
        ("discard", MaxPrefixAction::Discard as i32, None, false),
        // Terminate with allow_automatic_stop=false: stays connected
        (
            "terminate_no_auto_stop",
            MaxPrefixAction::Terminate as i32,
            Some(false),
            false,
        ),
    ];

    for (name, action, allow_automatic_stop, expect_disconnect) in test_cases {
        // Server1: will inject routes
        let server1 = start_test_server(BgpConfig::new(
            65001,
            "127.0.0.1:0",
            Ipv4Addr::new(1, 1, 1, 1),
            300,
        ))
        .await;

        // Server2: will receive routes with max_prefix limit
        let server2 = start_test_server(BgpConfig::new(
            65002,
            "127.0.0.2:0",
            Ipv4Addr::new(2, 2, 2, 2),
            300,
        ))
        .await;

        // Server1 adds Server2 (so it accepts the connection)
        server1.add_peer(&server2).await;

        // Server2 connects to Server1 with max_prefix limit of 2
        server2
            .client
            .add_peer(
                "127.0.0.1".to_string(),
                Some(SessionConfig {
                    port: Some(server1.bgp_port as u32),
                    max_prefix: Some(MaxPrefixSetting { limit: 2, action }),
                    allow_automatic_stop,
                    ..Default::default()
                }),
            )
            .await
            .expect("Failed to add peer");

        // RFC 8212: eBGP peers need explicit accept-all policies
        apply_permit_all_routes(&server1, &server2).await;

        // Wait for peering to establish
        poll_until(
            || async { verify_peers(&server2, vec![server1.to_peer(BgpState::Established)]).await },
            "Timeout waiting for peering",
        )
        .await;

        // Server1 adds 3 routes (exceeds limit of 2)
        for i in 0..3 {
            announce_route(
                &server1,
                RouteParams::Ip(Box::new(IpRouteParams {
                    prefix: format!("10.{}.0.0/24", i),
                    next_hop: "1.1.1.1".to_string(),
                    ..Default::default()
                })),
            )
            .await;
        }

        if expect_disconnect {
            // Terminate: session should be closed (CEASE sent), configured peer stays in Idle
            // AdminState is set to PrefixLimitReached which maps to admin_down=true
            poll_until(
                || async {
                    verify_peers(
                        &server2,
                        vec![Peer {
                            address: server1.address.to_string(),
                            asn: 0, // Cleared on disconnect
                            state: BgpState::Idle.into(),
                            admin_state: AdminState::PrefixLimitExceeded.into(),
                            import_policies: vec![],
                            export_policies: vec![],
                            session_config: None,
                        }],
                    )
                    .await
                },
                &format!("Test case {}: timeout waiting for peer to go Idle", name),
            )
            .await;
        } else {
            // Discard: peer stays connected, routes are limited
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            assert!(
                verify_peers(&server2, vec![server1.to_peer(BgpState::Established)]).await,
                "Test case {}: peer should remain established",
                name
            );

            // Verify no CEASE notification was sent
            poll_peer_stats(
                &server2,
                &server1.address.to_string(),
                ExpectedStats {
                    notification_sent: Some(0),
                    ..Default::default()
                },
            )
            .await;

            let routes = server2
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .expect("Failed to get routes");
            assert!(
                routes.len() <= 2,
                "Test case {}: should have at most 2 routes, got {}",
                name,
                routes.len()
            );
        }
    }
}

#[tokio::test]
async fn test_remove_peer_sends_cease_notification() {
    let server = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
    ))
    .await;

    // Add passive peer so FakePeer connection is accepted
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

    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;

    server
        .client
        .remove_peer(peer.address.to_string())
        .await
        .expect("Failed to remove peer");

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::Cease(CeaseSubcode::PeerDeconfigured)
    );
}

#[tokio::test]
async fn test_disable_peer_sends_admin_shutdown() {
    let server = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        300,
    ))
    .await;

    // Add passive peer so FakePeer connection is accepted
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

    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;
    peer.handshake_keepalive().await;

    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;

    server
        .client
        .disable_peer(peer.address.to_string())
        .await
        .expect("Failed to disable peer");

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::Cease(CeaseSubcode::AdministrativeShutdown)
    );
}
