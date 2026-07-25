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

//! BSD-specific integration tests

#![cfg(target_os = "freebsd")]

mod utils;
pub use utils::*;

use bgpgg::grpc::proto::{BgpState, SessionConfig};
use conf::bgp::BgpConfig;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::Command;

// Test that TCP MD5 keys are cleaned up from SADB when a peer is removed.
// BSD only: Uses PF_KEY/SADB API. Linux TCP-MD5 uses socket options that are automatically cleaned up.
#[tokio::test]
async fn test_tcp_md5_cleanup_on_peer_removal() {
    // Flush SADB before test to start with clean state
    Command::new("setkey")
        .args(["-c"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(b"deleteall 127.0.0.11 127.0.0.12 tcp;\n")?;
                stdin.write_all(b"deleteall 127.0.0.12 127.0.0.11 tcp;\n")?;
            }
            child.wait()
        })
        .ok();

    // Small delay to ensure flush completes
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let key = b"cleanup-secret";
    let key_path = write_key_file("cleanup", key);

    // Convert key to hex format as it appears in setkey output (space-separated 4-byte groups)
    let key_hex = key
        .chunks(4)
        .map(|chunk| {
            chunk
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ");

    // Use unique IPs (127.0.0.11/12) to avoid SADB conflicts with other tests
    let server1 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.11:0",
        Ipv4Addr::new(11, 11, 11, 11),
        90,
    ))
    .await;
    let server2 = start_test_server(BgpConfig::new(
        65002,
        "127.0.0.12:0",
        Ipv4Addr::new(12, 12, 12, 12),
        90,
    ))
    .await;

    // Establish session with MD5 - server1 active, server2 passive to avoid race
    server1
        .add_peer_with_config(
            &server2,
            SessionConfig {
                md5_key_file: Some(key_path.clone()),
                ..Default::default()
            },
        )
        .await;

    server2
        .add_peer_with_config(
            &server1,
            SessionConfig {
                md5_key_file: Some(key_path.clone()),
                passive_mode: Some(true),
                ..Default::default()
            },
        )
        .await;

    // Wait for session to establish
    poll_until(
        || async {
            server1.client.get_peers().await.is_ok_and(|peers| {
                peers
                    .iter()
                    .any(|p| p.state == BgpState::Established as i32)
            })
        },
        "Session should establish",
    )
    .await;

    // Verify SADB entries exist for this specific key
    let output = Command::new("setkey")
        .arg("-D")
        .output()
        .expect("Failed to run setkey -D");
    let sadb_before = String::from_utf8_lossy(&output.stdout);
    assert!(
        sadb_before.contains(&key_hex),
        "SADB should contain key before removal"
    );

    // Remove peer from server1 (active) - server2 never added it so no reconnection
    server1.remove_peer(&server2).await;

    // Wait for peer to be removed
    poll_until(
        || async {
            server1
                .client
                .get_peers()
                .await
                .is_ok_and(|peers| peers.is_empty())
        },
        "Peer should be removed from server1",
    )
    .await;

    // Poll until SADB entries are cleaned up and stay clean
    // This ensures cleanup happened AND no reconnection attempts create new entries
    let key_hex_clone = key_hex.clone();
    poll_until_stable(
        move || {
            let key_hex = key_hex_clone.clone();
            async move {
                let output = Command::new("setkey")
                    .arg("-D")
                    .output()
                    .expect("Failed to run setkey -D");
                let sadb = String::from_utf8_lossy(&output.stdout);
                !sadb.contains(&key_hex)
            }
        },
        tokio::time::Duration::from_secs(1),
        "SADB should be cleaned up after peer removal and remain clean",
    )
    .await;

    // Cleanup - remove key file and flush SADB to avoid polluting other tests
    std::fs::remove_file(&key_path).ok();
    Command::new("setkey")
        .args(["-c"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(b"deleteall 127.0.0.11 127.0.0.12 tcp;\n")?;
                stdin.write_all(b"deleteall 127.0.0.12 127.0.0.11 tcp;\n")?;
            }
            child.wait()
        })
        .ok();
}
