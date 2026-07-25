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

//! Tests for BGP message header error handling per RFC 4271 Section 6.1

mod utils;
pub use utils::*;

use bgpgg::bgp::msg::BGP_MARKER;
use bgpgg::bgp::msg_notification::{BgpError, MessageHeaderError};
use conf::bgp::BgpConfig;
use std::net::Ipv4Addr;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

#[tokio::test]
async fn test_invalid_marker() {
    let (_server, mut peer) = setup_server_and_fake_peer().await;

    // Corrupt first byte of marker
    let mut corrupted_marker = BGP_MARKER;
    corrupted_marker[0] = 0x00;

    let msg = build_raw_open(
        65002,
        300,
        u32::from(Ipv4Addr::new(2, 2, 2, 2)),
        RawOpenOptions {
            marker_override: Some(corrupted_marker),
            ..Default::default()
        },
    );

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized)
    );
}

#[tokio::test]
async fn test_bad_message_length() {
    let test_cases = vec![
        ("too small", [0x00, 0x12]), // 18: less than minimum (19)
        ("too large", [0x10, 0x01]), // 4097: greater than maximum (4096)
    ];

    for (name, length) in test_cases {
        let (_server, mut peer) = setup_server_and_fake_peer().await;

        let wrong_length = u16::from_be_bytes(length);
        let msg = build_raw_open(
            65002,
            300,
            u32::from(Ipv4Addr::new(2, 2, 2, 2)),
            RawOpenOptions {
                length_override: Some(wrong_length),
                ..Default::default()
            },
        );

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            "Test case: {}",
            name
        );
        // RFC requires the erroneous Length field in data
        assert_eq!(notif.data(), &length, "Test case: {}", name);
    }
}

#[tokio::test]
async fn test_keepalive_wrong_length() {
    let (_server, mut peer) = setup_server_and_fake_peer().await;

    // KEEPALIVE must be exactly 19 bytes, make it 20
    let msg = build_raw_keepalive(Some(20));

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength)
    );
    // RFC requires the erroneous Length field in data
    assert_eq!(notif.data(), &[0x00, 0x14]);
}

#[tokio::test]
async fn test_notification_length_too_small() {
    let (_server, mut peer) = setup_server_and_fake_peer().await;

    // NOTIFICATION minimum length is 21 (19 header + 2 for error code/subcode)
    // Create a message with type=3 (NOTIFICATION) and length=20
    let msg = build_raw_notification(0, 0, &[], Some(20));

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength)
    );
    assert_eq!(notif.data(), &[0x00, 0x14]);
}

#[tokio::test]
async fn test_invalid_message_type() {
    let (_server, mut peer) = setup_server_and_fake_peer().await;

    // Create message with invalid type (99)
    let msg = build_raw_open(
        65002,
        300,
        u32::from(Ipv4Addr::new(2, 2, 2, 2)),
        RawOpenOptions {
            msg_type_override: Some(99),
            ..Default::default()
        },
    );

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::MessageHeaderError(MessageHeaderError::BadMessageType)
    );
    // RFC requires the erroneous Type field in data
    assert_eq!(notif.data(), &[99]);
}

#[tokio::test]
async fn test_send_notification_without_open() {
    for flag in [true, false] {
        let mut config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 300);
        config
            .insert_peer(conf::bgp::PeerConfig {
                address: "127.0.0.1".to_string(),
                passive_mode: true,
                send_notification_without_open: flag,
                delay_open_time_secs: Some(60),
                ..Default::default()
            })
            .unwrap();
        let server = start_test_server(config).await;

        let mut peer = FakePeer::connect(None, &server).await;

        // Send invalid marker before OPEN is sent (delay_open delays it)
        let mut corrupted_marker = BGP_MARKER;
        corrupted_marker[0] = 0x00;
        let msg = build_raw_open(
            65002,
            300,
            0x02020202,
            RawOpenOptions {
                marker_override: Some(corrupted_marker),
                ..Default::default()
            },
        );
        peer.send_raw(&msg).await;

        let mut buf = [0u8; 1];
        let result = timeout(
            Duration::from_millis(100),
            peer.stream.as_mut().unwrap().read(&mut buf),
        )
        .await;

        if flag {
            assert!(result.is_ok(), "flag={}: should receive notification", flag);
        } else {
            match result {
                Ok(Ok(0)) | Err(_) => {} // EOF or timeout - no notification sent
                other => panic!("flag={}: unexpected {:?}", flag, other),
            }
        }
    }
}
