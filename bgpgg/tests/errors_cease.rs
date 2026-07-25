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

//! Tests for BGP CEASE notifications and connection collision detection per RFC 4271 Sections 6.7, 6.8

mod utils;
pub use utils::*;

use bgpgg::bgp::msg::AddPathMask;
use bgpgg::bgp::msg_notification::{BgpError, CeaseSubcode};
use bgpgg::grpc::proto::{
    AdminState, BgpState, ListRoutesRequest, MaxPrefixAction, MaxPrefixSetting, Peer, SessionConfig,
};
use conf::bgp::BgpConfig;
#[allow(hidden_glob_reexports)]
use conf::bgp::PeerConfig;
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

/// RFC 4271 6.8: Immediate collision detection when both connections have BGP IDs.
/// Tests collision when outgoing is already in OpenConfirm (has BGP ID) before incoming arrives.
#[tokio::test]
async fn test_collision_immediate() {
    let test_cases = vec![
        // (server_bgp_id, peer_bgp_id, outgoing_wins)
        (Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(1, 1, 1, 1), true), // local > remote: outgoing wins
        (Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(3, 3, 3, 3), false), // local < remote: incoming wins
    ];

    for (server_bgp_id, peer_bgp_id, outgoing_wins) in test_cases {
        // FakePeer listens, server will connect to it
        let mut peer = FakePeer::new("127.0.0.3:0", 65002).await;

        let mut config = BgpConfig::new(65001, "127.0.0.1:0", server_bgp_id, 300);
        config
            .insert_peer(PeerConfig {
                address: "127.0.0.3".to_string(),
                port: peer.port(),
                ..Default::default()
            })
            .unwrap();
        let server = start_test_server(config).await;

        // Accept server's outgoing connection and complete OPEN exchange
        // This puts outgoing in OpenConfirm with known BGP ID
        peer.accept().await;
        peer.read_open().await;
        peer.send_open(65002, peer_bgp_id, 300).await;

        // Wait for OpenConfirm (outgoing now has BGP ID)
        poll_until(
            || async {
                let peers = server.client.get_peers().await.unwrap();
                peers.len() == 1 && peers[0].state == BgpState::OpenConfirm as i32
            },
            "Timeout waiting for OpenConfirm",
        )
        .await;

        // FakePeer initiates incoming connection - collision resolved immediately
        let mut incoming_peer = FakePeer {
            stream: Some(peer.connect_to(&server).await),
            address: "127.0.0.3".to_string(),
            asn: 65002,
            listener: None,
            supports_4byte_asn: false,
            add_path: AddPathMask::NONE,
        };

        // Complete handshake on incoming
        incoming_peer.read_open().await;
        incoming_peer.send_open(65002, peer_bgp_id, 300).await;

        if outgoing_wins {
            // Outgoing wins - complete handshake on outgoing, incoming gets closed
            peer.send_keepalive().await;
            peer.read_keepalive().await;
        } else {
            // Incoming wins - complete handshake on incoming, outgoing gets closed
            incoming_peer.read_keepalive().await;
            incoming_peer.send_keepalive().await;
        }

        // Verify session established
        poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;
    }
}

/// Third incoming connection is rejected when both slots are occupied.
/// This tests that we don't accept more than 2 connections per peer.
#[tokio::test]
async fn test_reject_third_connection_when_slots_occupied() {
    use tokio::io::AsyncReadExt;

    // server1 and server2 peer and reach Established (incoming slot occupied on server1)
    let (server1, server2) = setup_two_peered_servers(common::PeerConfig::default()).await;

    // FakePeer on same IP as server2 tries to connect - should be rejected (third connection)
    let fake_peer = FakePeer::connect(Some("127.0.0.2"), &server1).await;

    // Connection should be rejected - notification sent async, may or may not arrive
    let mut stream = fake_peer.stream.unwrap();
    let mut buf = [0u8; 1024];
    let result =
        tokio::time::timeout(std::time::Duration::from_millis(500), stream.read(&mut buf)).await;

    // Should get EOF (connection closed), NOTIFICATION, or timeout
    match result {
        Ok(Ok(0)) => {} // EOF - connection closed
        Ok(Ok(n)) if n >= 19 => {
            // Got NOTIFICATION - verify it's ConnectionRejected
            assert_eq!(buf[19], 6, "Expected CEASE error code");
            assert_eq!(buf[20], 5, "Expected ConnectionRejected subcode");
        }
        Ok(Ok(_)) => panic!("Unexpected short read"),
        Ok(Err(_)) => {} // Read error - connection rejected
        Err(_) => {}     // Timeout - acceptable
    }

    // Original peer should still be Established
    assert!(
        verify_peers(&server1, vec![server2.to_peer(BgpState::Established)]).await,
        "Established session should be preserved"
    );
}

/// RFC 4271 6.8: Collision in Connect state - incoming wins scenario
/// Without the fix, incoming connection would be dropped and session would fail.
#[tokio::test]
async fn test_collision_connect_state() {
    // Peer listens, server connects with DelayOpen configured
    let mut peer = FakePeer::new("127.0.0.3:0", 65002).await;

    let mut config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 300);
    config
        .insert_peer(PeerConfig {
            address: "127.0.0.3".to_string(),
            port: peer.port(),
            delay_open_time_secs: Some(2),
            ..Default::default()
        })
        .unwrap();
    let server = start_test_server(config).await;

    // Accept outgoing connection - server is now in Connect waiting for DelayOpen timer
    peer.accept().await;

    // Verify peer is in Connect state (DelayOpen timer running, hasn't sent OPEN yet)
    poll_until_with_timeout(
        || async {
            let peers = server.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::Connect as i32
        },
        "Timeout waiting for Connect state",
        Duration::from_secs(1),
    )
    .await;

    // Collision: peer initiates incoming while server is in Connect with DelayOpen
    // Server spawns incoming in separate slot, collision resolved after OPEN exchange
    let mut incoming_peer = FakePeer {
        stream: Some(peer.connect_to(&server).await),
        address: "127.0.0.3".to_string(),
        asn: 65002,
        listener: None,
        supports_4byte_asn: false,
        add_path: AddPathMask::NONE,
    };

    // DelayOpen timer expires, server sends OPEN on outgoing connection
    peer.read_open().await;
    peer.send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300).await;

    // Server resolves collision: local(1.1.1.1) < remote(3.3.3.3) -> switch to incoming, drop outgoing
    // Outgoing connection gets closed (may or may not receive NOTIFICATION before close)

    // Complete handshake on incoming connection (the winner)
    incoming_peer.read_open().await;
    incoming_peer
        .send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300)
        .await;
    incoming_peer.read_keepalive().await;
    incoming_peer.send_keepalive().await;

    // Verify session established on incoming connection
    // Without fix: incoming was dropped, this will timeout
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;
}

/// RFC 4271 6.8: Deferred collision detection for outgoing connections
/// When server has outgoing in OpenSent (no BGP ID), incoming is deferred until OPEN received.
#[tokio::test]
async fn test_collision_deferred() {
    let test_cases = vec![
        // (server_bgp_id, peer_bgp_id, outgoing_wins)
        (Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(1, 1, 1, 1), true), // outgoing wins
        (Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(3, 3, 3, 3), false), // incoming wins
    ];

    for (server_bgp_id, peer_bgp_id, outgoing_wins) in test_cases {
        // Peer listens at 127.0.0.3, server will connect to it
        let mut peer = FakePeer::new("127.0.0.3:0", 65002).await;

        let mut config = BgpConfig::new(65001, "127.0.0.1:0", server_bgp_id, 300);
        config
            .insert_peer(PeerConfig {
                address: "127.0.0.3".to_string(),
                port: peer.port(),
                ..Default::default()
            })
            .unwrap();
        let server = start_test_server(config).await;

        // Accept server's outbound connection (server sends OPEN, but we don't read it yet)
        peer.accept().await;

        // Server is in OpenSent (sent OPEN, waiting for response)
        poll_until(
            || async {
                let peers = server.client.get_peers().await.unwrap();
                peers.len() == 1 && peers[0].state == BgpState::OpenSent as i32
            },
            "Timeout waiting for OpenSent",
        )
        .await;

        // Same peer initiates connection to server - triggers deferred collision (no BGP ID yet)
        let mut incoming_stream = peer.connect_to(&server).await;

        // Now exchange OPENs on first connection - server learns BGP ID and resolves collision
        peer.read_open().await;
        peer.send_open(65002, peer_bgp_id, 300).await;

        if outgoing_wins {
            // Complete handshake on outgoing connection
            peer.send_keepalive().await;
            peer.read_keepalive().await;

            // Outgoing wins, collision dropped, session reaches Established
            poll_until(
                || async {
                    let peers = server.client.get_peers().await.unwrap();
                    peers.len() == 1 && peers[0].state == BgpState::Established as i32
                },
                "Timeout waiting for Established (outgoing wins)",
            )
            .await;

            drop(incoming_stream);
        } else {
            // Incoming wins - server closes outgoing (peer gets NOTIFICATION), switches to incoming
            // Complete handshake on incoming connection
            // Wrap incoming_stream in FakePeer to use helper methods
            let mut incoming_peer = FakePeer {
                stream: Some(incoming_stream),
                address: "127.0.0.3".to_string(),
                asn: 65002,
                listener: None,
                supports_4byte_asn: false,
                add_path: AddPathMask::NONE,
            };

            incoming_peer.read_open().await;
            incoming_peer.send_open(65002, peer_bgp_id, 300).await;
            incoming_peer.read_keepalive().await;
            incoming_peer.send_keepalive().await;

            incoming_stream = incoming_peer.stream.take().unwrap();

            // Incoming wins, session reaches Established
            poll_until(
                || async {
                    let peers = server.client.get_peers().await.unwrap();
                    peers.len() == 1 && peers[0].state == BgpState::Established as i32
                },
                "Timeout waiting for Established (incoming wins)",
            )
            .await;

            drop(incoming_stream);
        }
    }
}

/// Test that candidate is promoted when primary connection dies before collision resolution.
#[tokio::test]
async fn test_collision_candidate_promotion_on_primary_disconnect() {
    // FakePeer listens, server will connect outgoing
    let mut peer = FakePeer::new("127.0.0.3:0", 65002).await;

    let mut config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 300);
    config
        .insert_peer(PeerConfig {
            address: "127.0.0.3".to_string(),
            port: peer.port(),
            ..Default::default()
        })
        .unwrap();
    let server = start_test_server(config).await;

    // Accept server's outgoing connection
    peer.accept().await;

    // Server is in OpenSent (sent OPEN, waiting for response)
    poll_until(
        || async {
            let peers = server.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::OpenSent as i32
        },
        "Timeout waiting for OpenSent",
    )
    .await;

    // FakePeer initiates incoming connection - becomes collision candidate
    let mut incoming_peer = FakePeer {
        stream: Some(peer.connect_to(&server).await),
        address: "127.0.0.3".to_string(),
        asn: 65002,
        listener: None,
        supports_4byte_asn: false,
        add_path: AddPathMask::NONE,
    };

    // Read OPEN from incoming - blocks until candidate is spawned and sends OPEN
    incoming_peer.read_open().await;

    // Kill outgoing BEFORE collision resolution (never sent OPEN response)
    drop(peer);

    // Server promotes candidate -> continue handshake on incoming
    incoming_peer
        .send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300)
        .await;
    incoming_peer.read_keepalive().await;
    incoming_peer.send_keepalive().await;

    // Verify session established via promoted candidate
    poll_peers(&server, vec![incoming_peer.to_peer(BgpState::Established)]).await;
}

/// Test that candidate's ASN is preserved when promoted after reaching Established.
/// This test reliably reproduces a bug where PeerHandshakeComplete updates peer.conn
/// instead of peer.candidate, causing ASN to be lost on promotion.
#[tokio::test]
async fn test_collision_candidate_asn_preserved_on_promotion() {
    // FakePeer listens, server will connect outgoing
    let mut peer = FakePeer::new("127.0.0.4:0", 65002).await;

    let mut config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 300);
    config
        .insert_peer(PeerConfig {
            address: "127.0.0.4".to_string(),
            port: peer.port(),
            ..Default::default()
        })
        .unwrap();
    let server = start_test_server(config).await;

    // Accept server's outgoing connection
    peer.accept().await;

    // Server is in OpenSent (sent OPEN, waiting for response)
    poll_until(
        || async {
            let peers = server.client.get_peers().await.unwrap();
            peers.len() == 1 && peers[0].state == BgpState::OpenSent as i32
        },
        "Timeout waiting for OpenSent",
    )
    .await;

    // FakePeer initiates incoming connection - becomes collision candidate
    let mut incoming_peer = FakePeer {
        stream: Some(peer.connect_to(&server).await),
        address: "127.0.0.4".to_string(),
        asn: 65002,
        listener: None,
        supports_4byte_asn: false,
        add_path: AddPathMask::NONE,
    };

    // Read OPEN from candidate
    incoming_peer.read_open().await;

    // Complete candidate's handshake BEFORE dropping primary
    // This ensures PeerHandshakeComplete is sent while candidate is still a candidate
    incoming_peer
        .send_open(65002, Ipv4Addr::new(4, 4, 4, 4), 300)
        .await;
    incoming_peer.read_keepalive().await;
    incoming_peer.send_keepalive().await;

    // Drop the primary - candidate should be promoted with correct ASN
    drop(peer);

    // Verify promoted connection has correct ASN (65002, not 0)
    poll_peers(&server, vec![incoming_peer.to_peer(BgpState::Established)]).await;
}
