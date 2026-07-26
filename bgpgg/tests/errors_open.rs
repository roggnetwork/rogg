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

//! Tests for BGP OPEN message error handling per RFC 4271 Section 6.2

mod utils;
pub use utils::*;

use bgpgg::bgp::msg::Message;
use bgpgg::bgp::msg_notification::{BgpError, OpenMessageError};
use bgpgg::bgp::msg_open::OpenMessage;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_open_unsupported_version() {
    let (_server, mut peer) = setup_server_and_fake_peer().await;

    let msg = build_raw_open(
        65002,
        300,
        u32::from(Ipv4Addr::new(2, 2, 2, 2)),
        RawOpenOptions {
            version_override: Some(3),
            ..Default::default()
        },
    );

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber)
    );
    // RFC 4271: Data field contains largest locally-supported version
    assert_eq!(notif.data(), &[0x00, 0x04]);
}

#[tokio::test]
async fn test_open_unacceptable_hold_time() {
    let test_cases = vec![1, 2];

    for hold_time in test_cases {
        let (_server, mut peer) = setup_server_and_fake_peer().await;

        let msg =
            OpenMessage::new(65002, hold_time, u32::from(Ipv4Addr::new(2, 2, 2, 2))).serialize();

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::OpenMessageError(OpenMessageError::UnacceptedHoldTime),
            "Failed for hold_time={}",
            hold_time
        );
        assert_eq!(
            notif.data(),
            &[] as &[u8],
            "Failed for hold_time={}",
            hold_time
        );
    }
}

/// RFC 6286: the BGP Identifier is any non-zero 4-octet value, unique per
/// AS. Reject zero (2.1) and our own identifier from an internal peer (2.2);
/// accept everything else, including non-unicast values and our own
/// identifier from an external peer. Server is AS 65001, router-id 1.1.1.1.
#[tokio::test]
async fn test_open_bgp_identifier_validation() {
    let test_cases = vec![
        // (name, peer_asn, bgp_id, reject)
        ("zero", 65002, 0x00000000, true),
        ("internal duplicate of our id", 65001, 0x01010101, true),
        ("broadcast", 65002, 0xFFFFFFFF, false),
        ("multicast", 65002, 0xE0000001, false),
        ("external peer with our id", 65002, 0x01010101, false),
    ];

    for (name, peer_asn, bgp_id, reject) in test_cases {
        let server = setup_server_with_passive_peer().await;
        let mut peer = FakePeer::connect(None, &server).await;
        peer.read_open().await;

        peer.send_raw(&OpenMessage::new(peer_asn, 300, bgp_id).serialize())
            .await;

        if reject {
            let notif = peer.read_notification().await;
            assert_eq!(
                notif.error(),
                &BgpError::OpenMessageError(OpenMessageError::BadBgpIdentifier),
                "Failed for case: {}",
                name
            );
        } else {
            // Server accepts the OPEN and enters OpenConfirm
            peer.read_keepalive().await;
        }
    }
}
