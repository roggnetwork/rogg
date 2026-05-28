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

//! Tests for BGP session and timer errors per RFC 4271 Sections 6.5, 6.6

mod utils;
pub use utils::*;

use bgpgg::bgp::msg_notification::BgpError;
use bgpgg::grpc::proto::BgpState;
use conf::bgp::BgpConfig;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_hold_timer_expiry() {
    let hold_timer_secs: u16 = 3;
    let mut config = BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        hold_timer_secs as u64,
    );
    add_passive_peer(&mut config, "127.0.0.1");
    let server = start_test_server(config).await;

    // FakePeer connects with same hold time but won't send keepalives
    let mut fake_peer = FakePeer::connect(None, &server).await;
    fake_peer
        .handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), hold_timer_secs)
        .await;
    fake_peer.handshake_keepalive().await;

    // Verify peer is established
    poll_until(
        || async {
            let peers = server.client.get_peers().await.unwrap_or_default();
            peers
                .iter()
                .any(|p| p.state == BgpState::Established as i32)
        },
        "Timeout waiting for peer to establish",
    )
    .await;

    // FakePeer does nothing - server should detect hold timer expiry and send NOTIFICATION
    let notif = fake_peer.read_notification().await;
    assert_eq!(*notif.error(), BgpError::HoldTimerExpired);

    // Peer is configured, so it stays in the list but goes back to non-Established state
    poll_until(
        || async {
            let peers = server.client.get_peers().await.unwrap_or_default();
            peers
                .iter()
                .any(|p| p.state != BgpState::Established as i32)
        },
        "Timeout waiting for peer to leave Established after hold timer expiry",
    )
    .await;
}
#[tokio::test]
async fn test_fsm_error_update_in_openconfirm() {
    let server = setup_server_with_passive_peer().await;

    // Connect and exchange OPEN only - server ends up in OpenConfirm
    let mut peer = FakePeer::connect(None, &server).await;
    peer.handshake_open(65002, Ipv4Addr::new(2, 2, 2, 2), 300)
        .await;

    // Send UPDATE while server is in OpenConfirm (should trigger FSM Error)
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
        &[24, 10, 11, 12], // 10.11.12.0/24
        None,
    );
    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(notif.error(), &BgpError::FiniteStateMachineError);
}
