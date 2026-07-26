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

//! Tests for connection collision detection per RFC 4271 Section 6.8.

mod utils;
pub use utils::*;

use bgpgg::bgp::msg::{read_bgp_message, BgpMessage, Message, PRE_OPEN_FORMAT};
use bgpgg::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
use bgpgg::grpc::proto::BgpState;
use bgpgg::metrics;
use conf::bgp::BgpConfig;
#[allow(hidden_glob_reexports)]
use conf::bgp::PeerConfig;
use std::net::Ipv4Addr;

/// Wait until the server emitted a collision metric for the fake peer.
/// The collision FSM has no externally visible state transitions while a
/// candidate is held, so tests synchronize on these events.
async fn poll_collision_event(server: &TestServer, name: &str) {
    assert_metric(server, name, &[("Peer", "127.0.0.3")], &[]).await;
}

/// RFC 4271 6.8: a connection arriving after the handshake passed OpenSent is
/// not a collision candidate. The accepted connection is dropped and the
/// session completes on the dialed connection, regardless of BGP IDs.
#[tokio::test]
async fn test_incoming_dropped_in_openconfirm() {
    // FakePeer listens, server will connect to it
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

    // Accept server's outgoing connection and complete OPEN exchange.
    // Server is in OpenConfirm. The remote BGP ID is higher, but that no
    // longer matters: past OpenSent the dialed connection keeps the session.
    peer.accept().await;
    peer.read_open().await;
    peer.send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300).await;
    poll_peer_state(&server, BgpState::OpenConfirm).await;

    // Incoming connection is dropped without an OPEN
    let mut incoming = peer.connect_to(&server).await;
    assert_conn_closed(&mut incoming).await;

    // Session completes on the dialed connection
    peer.send_keepalive().await;
    peer.read_keepalive().await;
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;
}

/// RFC 4271 6.8 allows at most two connections per peer. A third connection
/// arriving while a collision candidate is already held is dropped, and the
/// collision still resolves normally.
#[tokio::test]
async fn test_third_connection_dropped_during_collision() {
    let mut peer = FakePeer::new("127.0.0.3:0", 65002).await;

    // Server BGP ID (2.2.2.2) is higher than the peer's (1.1.1.1), so the
    // dialed connection wins the collision.
    let mut config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(2, 2, 2, 2), 300);
    config
        .insert_peer(PeerConfig {
            address: "127.0.0.3".to_string(),
            port: peer.port(),
            ..Default::default()
        })
        .unwrap();
    let server = start_test_server(config).await;

    // Connection 1: server dials -> OpenSent.
    peer.accept().await;
    poll_peer_state(&server, BgpState::OpenSent).await;

    // Connection 2: inbound, held as the collision candidate.
    let mut second = peer.connect_to(&server).await;

    // Connection 3: over the two-connection limit - dropped.
    let mut third = peer.connect_to(&server).await;
    assert_conn_closed(&mut third).await;

    // Collision resolves: peer's OPEN on the dialed connection, local wins
    peer.read_open().await;
    peer.send_open(65002, Ipv4Addr::new(1, 1, 1, 1), 300).await;
    peer.send_keepalive().await;
    peer.read_keepalive().await;
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;

    // The losing candidate is released at resolution, not held
    assert_conn_closed(&mut second).await;
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
    let mut incoming_peer = peer.connect_again(&server).await;

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

/// RFC 4271 6.8: the peer's first OPEN resolves the collision; higher BGP ID
/// wins. The OPEN is sent on the candidate connection: on the dialed one it
/// could arrive before the candidate is held, leaving no collision to resolve.
#[tokio::test]
async fn test_collision_resolution() {
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

        // Accept server's outbound connection and read its OPEN
        peer.accept().await;
        poll_peer_state(&server, BgpState::OpenSent).await;
        peer.read_open().await;

        // Candidate connection sends the OPEN that resolves the collision
        let mut incoming_peer = peer.connect_again(&server).await;
        incoming_peer.send_open(65002, peer_bgp_id, 300).await;

        if outgoing_wins {
            // Candidate loses and is dropped; handshake completes on the
            // dialed connection
            let mut candidate = incoming_peer.stream.take().unwrap();
            assert_conn_closed(&mut candidate).await;
            peer.send_open(65002, peer_bgp_id, 300).await;
            peer.send_keepalive().await;
            peer.read_keepalive().await;
        } else {
            // Candidate wins - dialed connection gets Cease, server promotes
            // the candidate and sends OPEN on it
            let notif = peer.read_notification().await;
            assert_eq!(
                notif.error(),
                &BgpError::Cease(CeaseSubcode::ConnectionCollisionResolution)
            );
            incoming_peer.read_open().await;
            incoming_peer.read_keepalive().await;
            incoming_peer.send_keepalive().await;
        }

        poll_peer_state(&server, BgpState::Established).await;
    }
}

/// The collision candidate is promoted when the dialed connection dies before
/// resolution: the task adopts the accepted connection and sends OPEN on it.
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
    poll_peer_state(&server, BgpState::OpenSent).await;

    // FakePeer initiates incoming connection - becomes collision candidate
    let mut incoming_peer = peer.connect_again(&server).await;

    // Kill the dialed connection - the candidate takes over
    drop(peer);

    // Server sends OPEN on the promoted connection
    incoming_peer.read_open().await;
    incoming_peer
        .send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300)
        .await;
    incoming_peer.read_keepalive().await;
    incoming_peer.send_keepalive().await;

    // Verify session established via promoted candidate
    poll_peers(&server, vec![incoming_peer.to_peer(BgpState::Established)]).await;
}

/// After the accepted connection wins a collision and later drops, the peer
/// task returns to Idle and re-dials, re-establishing the session.
#[tokio::test]
async fn test_reconnect_after_winner_drops() {
    let mut peer = FakePeer::new("127.0.0.3:0", 65002).await;

    let mut config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 300);
    config
        .insert_peer(PeerConfig {
            address: "127.0.0.3".to_string(),
            port: peer.port(),
            idle_hold_time_secs: Some(0),
            ..Default::default()
        })
        .unwrap();
    let server = start_test_server(config).await;

    // Collision: server dials (OpenSent), incoming candidate's OPEN wins.
    peer.accept().await;
    peer.read_open().await;
    let mut winner = peer.connect_again(&server).await;
    winner
        .send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300)
        .await;
    // Drain the Cease on the losing dialed connection.
    let _ = peer.read_notification().await;
    winner.read_open().await;
    winner.read_keepalive().await;
    winner.send_keepalive().await;
    poll_peers(&server, vec![winner.to_peer(BgpState::Established)]).await;

    // The winner drops: the task goes Idle and re-dials immediately
    // (idle_hold_time 0).
    drop(winner);
    peer.accept().await;
    peer.read_open().await;
    peer.send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300).await;
    peer.read_keepalive().await;
    peer.send_keepalive().await;
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;
}

/// One owner per peer: once a session is Established, the task never dials, so
/// active-active peering converges and stays stable with no further Ceases.
/// ConnectRetry is 1s so a regression that re-dials while Established (the
/// original churn bug) fires well inside the 3s stability window.
#[tokio::test]
async fn test_active_active_stable_after_convergence() {
    let mut config1 = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 90);
    config1.connect_retry_secs = 1;
    let mut config2 = BgpConfig::new(65002, "127.0.0.2:0", Ipv4Addr::new(2, 2, 2, 2), 90);
    config2.connect_retry_secs = 1;
    let [server1, server2] = chain_servers(
        [
            start_test_server(config1).await,
            start_test_server(config2).await,
        ],
        common::PeerConfig::default(),
    )
    .await;

    let stats_before = server1
        .client
        .get_peer(server2.address.to_string())
        .await
        .unwrap()
        .1
        .unwrap();

    poll_while(
        || async {
            verify_peers(&server1, vec![server2.to_peer(BgpState::Established)]).await
                && verify_peers(&server2, vec![server1.to_peer(BgpState::Established)]).await
        },
        Duration::from_secs(3),
        "active-active session flapped after convergence",
    )
    .await;

    // No NOTIFICATION exchanged after convergence
    let stats_after = server1
        .client
        .get_peer(server2.address.to_string())
        .await
        .unwrap()
        .1
        .unwrap();
    assert_eq!(
        stats_before.notification_sent, stats_after.notification_sent,
        "NOTIFICATION sent after convergence"
    );
    assert_eq!(
        stats_before.notification_received, stats_after.notification_received,
        "NOTIFICATION received after convergence"
    );
}

/// RFC 4271 8.2.2: a peer we hold in Idle (admin down) has its inbound
/// connections refused.
#[tokio::test]
async fn test_idle_peer_refuses_inbound() {
    let mut config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 300);
    config
        .insert_peer(PeerConfig {
            address: "127.0.0.1".to_string(),
            admin_down: true,
            ..Default::default()
        })
        .unwrap();
    let server = start_test_server(config).await;

    let fake_peer = FakePeer::connect(None, &server).await;
    let mut stream = fake_peer.stream.unwrap();
    assert_conn_closed(&mut stream).await;

    // Peer stays Idle
    let peers = server.client.get_peers().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].state, BgpState::Idle as i32);
}

/// Start a server that dials the FakePeer, accept the dial, and hold an
/// inbound collision candidate. Returns (fake, server, candidate) with the
/// server in OpenSent and its OPEN already read off the dialed connection.
async fn setup_collision(
    server_bgp_id: Ipv4Addr,
    expected_asn: Option<u32>,
) -> (FakePeer, TestServer, FakePeer) {
    let mut peer = FakePeer::new("127.0.0.3:0", 65002).await;

    let mut config = BgpConfig::new(65001, "127.0.0.1:0", server_bgp_id, 300);
    config
        .insert_peer(PeerConfig {
            address: "127.0.0.3".to_string(),
            port: peer.port(),
            asn: expected_asn,
            idle_hold_time_secs: Some(0),
            ..Default::default()
        })
        .unwrap();
    let server = start_test_server(config).await;

    peer.accept().await;
    poll_peer_state(&server, BgpState::OpenSent).await;
    peer.read_open().await;

    let candidate = peer.connect_again(&server).await;
    poll_collision_event(&server, metrics::COLLISION_DETECTED_COUNT).await;

    (peer, server, candidate)
}

/// A real peer sends OPEN on every connection it considers primary, so during
/// a collision the server can see OPENs on both connections in any order.
/// Either order must resolve to one session with the right winner.
#[tokio::test]
async fn test_collision_open_on_both_connections() {
    let cases = vec![
        // (name, server_bgp_id, dialed_open_first, server_wins)
        (
            "server wins, dialed first",
            Ipv4Addr::new(9, 9, 9, 9),
            true,
            true,
        ),
        (
            "server wins, candidate first",
            Ipv4Addr::new(9, 9, 9, 9),
            false,
            true,
        ),
        (
            "server loses, dialed first",
            Ipv4Addr::new(1, 1, 1, 1),
            true,
            false,
        ),
        (
            "server loses, candidate first",
            Ipv4Addr::new(1, 1, 1, 1),
            false,
            false,
        ),
    ];

    for (name, server_bgp_id, dialed_first, server_wins) in cases {
        let (mut peer, server, mut candidate) = setup_collision(server_bgp_id, None).await;
        let fake_id = Ipv4Addr::new(3, 3, 3, 3);

        if dialed_first {
            peer.send_open(65002, fake_id, 300).await;
            candidate.send_open(65002, fake_id, 300).await;
        } else {
            candidate.send_open(65002, fake_id, 300).await;
            peer.send_open(65002, fake_id, 300).await;
        }

        if server_wins {
            // Candidate is dropped silently; session completes on the dialed
            // connection.
            assert_conn_closed(candidate.stream.as_mut().unwrap()).await;
            peer.read_keepalive().await;
            peer.send_keepalive().await;
            poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;
        } else {
            // Dialed connection gets Cease; session completes on the
            // promoted candidate.
            let notif = peer.read_notification().await;
            assert_eq!(
                notif.error(),
                &BgpError::Cease(CeaseSubcode::ConnectionCollisionResolution),
                "{}",
                name
            );
            candidate.read_open().await;
            candidate.read_keepalive().await;
            candidate.send_keepalive().await;
            poll_peers(&server, vec![candidate.to_peer(BgpState::Established)]).await;
        }
    }
}

/// A NOTIFICATION on the dialed connection during a collision promotes the
/// candidate instead of killing the whole peer.
#[tokio::test]
async fn test_collision_notification_on_dialed_promotes_candidate() {
    let (mut peer, server, mut candidate) = setup_collision(Ipv4Addr::new(1, 1, 1, 1), None).await;

    let notif = NotificationMessage::new(
        BgpError::Cease(CeaseSubcode::ConnectionCollisionResolution),
        vec![],
    );
    peer.send_raw(&notif.serialize()).await;

    candidate.read_open().await;
    candidate
        .send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300)
        .await;
    candidate.read_keepalive().await;
    candidate.send_keepalive().await;
    poll_peers(&server, vec![candidate.to_peer(BgpState::Established)]).await;
}

/// Junk on the candidate connection (non-OPEN message, malformed bytes, or
/// abrupt close) drops only the candidate; the dialed session completes.
#[tokio::test]
async fn test_collision_candidate_junk_dropped() {
    #[derive(Clone, Copy)]
    enum Junk {
        Keepalive,
        BadBytes,
        Close,
    }

    for junk in [Junk::Keepalive, Junk::BadBytes, Junk::Close] {
        let (mut peer, server, mut candidate) =
            setup_collision(Ipv4Addr::new(1, 1, 1, 1), None).await;

        match junk {
            Junk::Keepalive => {
                candidate.send_keepalive().await;
                assert_conn_closed(candidate.stream.as_mut().unwrap()).await;
            }
            Junk::BadBytes => {
                candidate.send_raw(&[0xAB; 19]).await;
                assert_conn_closed(candidate.stream.as_mut().unwrap()).await;
            }
            Junk::Close => drop(candidate),
        }

        peer.send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300).await;
        peer.read_keepalive().await;
        peer.send_keepalive().await;
        poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;
    }
}

/// A candidate that wins the collision but fails OPEN validation (ASN
/// mismatch) gets a NOTIFICATION; the peer task recovers and re-dials.
#[tokio::test]
async fn test_collision_winner_fails_asn_validation() {
    let (mut peer, server, mut candidate) =
        setup_collision(Ipv4Addr::new(1, 1, 1, 1), Some(65002)).await;

    // Wrong ASN, but higher BGP ID: wins the collision, then fails validation.
    candidate
        .send_open(65003, Ipv4Addr::new(9, 9, 9, 9), 300)
        .await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::Cease(CeaseSubcode::ConnectionCollisionResolution)
    );

    candidate.read_open().await;
    let notif = candidate.read_notification().await;
    assert!(
        matches!(notif.error(), BgpError::OpenMessageError(_)),
        "expected OPEN message error, got {:?}",
        notif.error()
    );
    assert_conn_closed(candidate.stream.as_mut().unwrap()).await;

    // Peer task goes Idle and re-dials (idle_hold_time 0). Clean handshake
    // succeeds this time.
    peer.accept().await;
    peer.read_open().await;
    peer.send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300).await;
    peer.send_keepalive().await;
    peer.read_keepalive().await;
    poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;
}

/// Collision while DelayOpen runs on the dialed connection: the candidate's
/// OPEN resolves it (dialed wins -> candidate dropped silently), and a dialed
/// connection dying promotes the candidate under DelayOpen rules.
#[tokio::test]
async fn test_collision_delay_open() {
    for dialed_wins in [true, false] {
        let mut peer = FakePeer::new("127.0.0.3:0", 65002).await;

        let server_bgp_id = if dialed_wins {
            Ipv4Addr::new(9, 9, 9, 9)
        } else {
            Ipv4Addr::new(1, 1, 1, 1)
        };
        let mut config = BgpConfig::new(65001, "127.0.0.1:0", server_bgp_id, 300);
        config
            .insert_peer(PeerConfig {
                address: "127.0.0.3".to_string(),
                port: peer.port(),
                delay_open_time_secs: Some(2),
                ..Default::default()
            })
            .unwrap();
        let server = start_test_server(config).await;

        // Server dials and sits in Connect with DelayOpen running. accept()
        // only proves the TCP handshake finished; wait until the peer task
        // registered the dialed connection, or the candidate would be
        // adopted as primary instead of held.
        peer.accept().await;
        assert_metric(
            &server,
            metrics::TCP_CONNECTION_COUNT,
            &[("Peer", "127.0.0.3"), ("Direction", "Dialed")],
            &[],
        )
        .await;
        let mut candidate = peer.connect_again(&server).await;
        poll_collision_event(&server, metrics::COLLISION_DETECTED_COUNT).await;

        if dialed_wins {
            // Candidate's OPEN loses; dropped silently. DelayOpen expires and
            // the handshake completes on the dialed connection.
            candidate
                .send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300)
                .await;
            assert_conn_closed(candidate.stream.as_mut().unwrap()).await;
            peer.read_open().await;
            peer.send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300).await;
            peer.send_keepalive().await;
            peer.read_keepalive().await;
            poll_peers(&server, vec![peer.to_peer(BgpState::Established)]).await;
        } else {
            // Dialed connection dies during DelayOpen; candidate is promoted
            // with DelayOpen restarted. Its OPEN gets OPEN + KEEPALIVE back.
            drop(peer.stream.take());
            // Promotion runs connection_ready on the candidate, emitting the
            // accepted-connection metric: the only way one appears here.
            assert_metric(
                &server,
                metrics::TCP_CONNECTION_COUNT,
                &[("Peer", "127.0.0.3"), ("Direction", "Accepted")],
                &[],
            )
            .await;
            candidate
                .send_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300)
                .await;
            candidate.read_open().await;
            candidate.read_keepalive().await;
            candidate.send_keepalive().await;
            poll_peers(&server, vec![candidate.to_peer(BgpState::Established)]).await;
        }
    }
}

/// Drain leftover session messages (KEEPALIVE, EOR) until EOF, asserting the
/// connection closes without a NOTIFICATION (GR route preservation).
async fn assert_closed_without_notification(stream: &mut tokio::net::TcpStream) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let msg =
            tokio::time::timeout_at(deadline, read_bgp_message(&mut *stream, PRE_OPEN_FORMAT))
                .await;
        match msg {
            Ok(Ok(BgpMessage::Notification(notif))) => {
                panic!("expected close without NOTIFICATION, got {:?}", notif)
            }
            Ok(Ok(_)) => continue,
            Ok(Err(_)) => return, // EOF or reset
            Err(_) => panic!("connection was not closed"),
        }
    }
}

/// Complete a GR handshake on the fake peer's current connection and wait
/// for Established.
async fn gr_handshake(fake: &mut FakePeer, server: &TestServer) {
    fake.read_open().await;
    fake.send_open_with_gr(65002, Ipv4Addr::new(2, 2, 2, 2), 300, 120, false)
        .await;
    fake.send_keepalive().await;
    fake.read_keepalive().await;
    poll_peer_state(server, BgpState::Established).await;
}

/// GR adoption edge cases beyond the basic reconnect (covered in peer.rs):
/// an extra connection during the re-handshake is dropped without disturbing
/// it, and an adopted connection dying before OPEN recovers via Active.
#[tokio::test]
async fn test_gr_adoption_extra_conn_and_death_recovery() {
    let server = setup_server_with_passive_peer().await;

    let mut fake = FakePeer::connect(None, &server).await;
    fake.asn = 65002;
    gr_handshake(&mut fake, &server).await;

    // Adoption: old session closes without NOTIFICATION; a third connection
    // during the re-handshake is dropped.
    let new_stream = fake.connect_to(&server).await;
    poll_peer_state(&server, BgpState::OpenSent).await;
    let mut old = fake.stream.take().unwrap();
    assert_closed_without_notification(&mut old).await;
    fake.stream = Some(new_stream);

    let mut extra = fake.connect_to(&server).await;
    assert_conn_closed(&mut extra).await;

    gr_handshake(&mut fake, &server).await;

    // Adopted connection dies before OPEN: OpenSent -> TcpConnectionFails ->
    // Active, where a fresh inbound connection restarts the handshake.
    let new_stream = fake.connect_to(&server).await;
    poll_peer_state(&server, BgpState::OpenSent).await;
    let mut old = fake.stream.take().unwrap();
    assert_closed_without_notification(&mut old).await;
    drop(new_stream);
    poll_until(
        || async {
            server
                .client
                .get_peers()
                .await
                .is_ok_and(|peers| peers.len() == 1 && peers[0].state != BgpState::OpenSent as i32)
        },
        "peer stuck in OpenSent after adopted connection died",
    )
    .await;

    fake.stream = Some(fake.connect_to(&server).await);
    gr_handshake(&mut fake, &server).await;
}
