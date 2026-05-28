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

//! Tests for Route Refresh (RFC 2918) and Enhanced Route Refresh (RFC 7313)

mod utils;
pub use utils::*;

use bgpgg::bgp::msg::BgpMessage;
use bgpgg::bgp::msg_route_refresh::RouteRefreshSubtype;
use std::net::Ipv4Addr;

/// Create server with a passive peer and connect FakePeer with basic route refresh.
async fn setup_basic_rr_peers() -> (TestServer, FakePeer) {
    let mut config = test_config(65001, 1);
    add_passive_peer(&mut config, "127.0.0.2");
    let server = start_test_server(config).await;

    let mp_cap = build_multiprotocol_capability_ipv4_unicast();
    let rr_cap = vec![2, 0]; // Route Refresh but no Enhanced Route Refresh
    let asn_cap = build_capability_4byte_asn(65002);
    let fake = FakePeer::connect_and_handshake(
        Some("127.0.0.2"),
        &server,
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
        Some(vec![mp_cap, rr_cap, asn_cap]),
    )
    .await;
    poll_peer_established(&server, "127.0.0.2").await;
    apply_permit_all(&server, "127.0.0.2").await;

    (server, fake)
}

/// Create server with a passive peer and connect FakePeer with enhanced RR.
async fn setup_enhanced_rr_peers() -> (TestServer, FakePeer) {
    let mut config = test_config(65001, 1);
    add_passive_peer(&mut config, "127.0.0.2");
    let server = start_test_server(config).await;
    let fake = FakePeer::connect_and_handshake_enhanced_rr(
        Some("127.0.0.2"),
        &server,
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
    )
    .await;
    poll_peer_established(&server, "127.0.0.2").await;
    apply_permit_all(&server, "127.0.0.2").await;
    (server, fake)
}

/// RFC 2918: Basic route refresh without enhanced RR.
/// Server should resend routes without BoRR/EoRR wrapping.
#[tokio::test]
async fn test_basic_route_refresh() {
    let (server, mut fake) = setup_basic_rr_peers().await;

    // Inject a route so server has something to resend
    announce_route(
        &server,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "127.0.0.2".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Skip initial messages until quiet
    let msg = loop {
        let msg = fake.read_message().await;
        if matches!(msg, BgpMessage::Update(_)) {
            break msg;
        }
    };
    assert!(matches!(msg, BgpMessage::Update(_)));

    // Send route refresh
    let rr = build_raw_route_refresh(1, 0, 1);
    fake.send_raw(&rr).await;

    // Server should resend UPDATE (no BoRR/EoRR wrapping)
    let msg = fake.read_message().await;
    assert!(
        matches!(msg, BgpMessage::Update(_)),
        "Expected UPDATE after route refresh, got {:?}",
        msg
    );
}

/// RFC 7313: BoRR marks routes stale, re-advertisement replaces them,
/// EoRR purges routes that were not re-advertised.
#[tokio::test]
async fn test_borr_eorr_stale_sweep() {
    let (server, mut fake) = setup_enhanced_rr_peers().await;

    // Announce two routes
    fake_announce_prefix(&server, &mut fake, &[24, 10, 0, 1], "10.0.1.0/24").await;
    fake_announce_prefix(&server, &mut fake, &[24, 10, 0, 2], "10.0.2.0/24").await;

    // Send BoRR for IPv4 Unicast -> marks both routes stale
    let borr = build_raw_route_refresh(1, 1, 1); // AFI=1, subtype=1 (BoRR), SAFI=1
    fake.send_raw(&borr).await;

    // Re-announce only 10.0.1.0/24 (10.0.2.0/24 remains stale)
    let update = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(fake.address.parse().unwrap()),
            &attr_local_pref(100),
        ],
        &[24, 10, 0, 1],
        None,
    );
    fake.send_raw(&update).await;

    // Send EoRR -> should purge 10.0.2.0/24 (still stale)
    let eorr = build_raw_route_refresh(1, 2, 1); // AFI=1, subtype=2 (EoRR), SAFI=1
    fake.send_raw(&eorr).await;

    // Wait for 10.0.2.0/24 to be withdrawn
    poll_until(
        || async { !has_route(&server, "10.0.2.0/24").await },
        "Timeout waiting for stale route 10.0.2.0/24 to be purged",
    )
    .await;

    // 10.0.1.0/24 should still exist
    assert!(
        has_route(&server, "10.0.1.0/24").await,
        "10.0.1.0/24 should survive EoRR"
    );
}

/// RFC 7313: Normal route refresh (subtype 0) should still work when
/// enhanced route refresh is negotiated, without stale marking.
#[tokio::test]
async fn test_normal_route_refresh() {
    let (server, mut fake) = setup_enhanced_rr_peers().await;

    fake_announce_prefix(&server, &mut fake, &[24, 10, 0, 1], "10.0.1.0/24").await;

    // Send normal route refresh (subtype 0)
    let rr = build_raw_route_refresh(1, 0, 1);
    fake.send_raw(&rr).await;

    // Route should still exist (not marked stale, just re-advertised)
    poll_while(
        || async { has_route(&server, "10.0.1.0/24").await },
        Duration::from_secs(2),
        "Route disappeared after normal route refresh",
    )
    .await;
}

/// RFC 7313 Section 5: Unknown subtypes (not 0, 1, 2) must be silently ignored.
#[tokio::test]
async fn test_unknown_subtype_ignored() {
    let (server, mut fake) = setup_enhanced_rr_peers().await;

    fake_announce_prefix(&server, &mut fake, &[24, 10, 0, 1], "10.0.1.0/24").await;

    // Send route refresh with unknown subtype 5
    let rr = build_raw_route_refresh(1, 5, 1);
    fake.send_raw(&rr).await;

    // Route should still exist
    poll_while(
        || async { has_route(&server, "10.0.1.0/24").await },
        Duration::from_secs(2),
        "Route disappeared after unknown route refresh subtype",
    )
    .await;
}

/// RFC 7313: When enhanced RR is not negotiated, BoRR/EoRR should be ignored.
#[tokio::test]
async fn test_borr_ignored_without_capability() {
    let (server, mut fake) = setup_basic_rr_peers().await;

    fake_announce_prefix(&server, &mut fake, &[24, 10, 0, 1], "10.0.1.0/24").await;

    // Send BoRR + EoRR - should be ignored since capability not negotiated
    fake.send_raw(&build_raw_route_refresh(1, 1, 1)).await;
    fake.send_raw(&build_raw_route_refresh(1, 2, 1)).await;

    // Route should still exist (BoRR ignored, routes not marked stale)
    poll_while(
        || async { has_route(&server, "10.0.1.0/24").await },
        Duration::from_secs(2),
        "Route disappeared despite enhanced RR not being negotiated",
    )
    .await;
}

/// RFC 7313: Sender wraps resend with BoRR/EoRR when enhanced RR is negotiated.
/// Inject a route via gRPC so the server has something to re-advertise,
/// then verify the response is: BoRR, UPDATE, EoRR.
#[tokio::test]
async fn test_sender_wraps_with_borr_eorr() {
    let (server, mut fake) = setup_enhanced_rr_peers().await;

    // Inject a route so the server has something to re-advertise
    announce_route(
        &server,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "127.0.0.2".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // FakePeer sends normal route refresh request to server
    let rr = build_raw_route_refresh(1, 0, 1);
    fake.send_raw(&rr).await;

    // Skip any messages before BoRR (EoR markers, initial UPDATEs)
    let msg = loop {
        let msg = fake.read_message().await;
        if matches!(msg, BgpMessage::RouteRefresh(ref rr) if rr.subtype == RouteRefreshSubtype::BoRR)
        {
            break msg;
        }
    };
    assert!(
        matches!(msg, BgpMessage::RouteRefresh(ref rr) if rr.subtype == RouteRefreshSubtype::BoRR),
        "Expected BoRR, got {:?}",
        msg
    );

    let msg = fake.read_message().await;
    assert!(
        matches!(msg, BgpMessage::Update(_)),
        "Expected UPDATE, got {:?}",
        msg
    );

    let msg = fake.read_message().await;
    assert!(
        matches!(msg, BgpMessage::RouteRefresh(ref rr) if rr.subtype == RouteRefreshSubtype::EoRR),
        "Expected EoRR, got {:?}",
        msg
    );
}

/// RFC 7313: Stale TTL timer sweeps stale routes when EoRR is not received.
#[tokio::test]
async fn test_enhanced_rr_stale_ttl_expiry() {
    let mut config = test_config(65001, 1);
    config.enhanced_rr_stale_ttl = Some(1);
    add_passive_peer(&mut config, "127.0.0.2");
    let server = start_test_server(config).await;
    let mut fake = FakePeer::connect_and_handshake_enhanced_rr(
        Some("127.0.0.2"),
        &server,
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
    )
    .await;
    poll_peer_established(&server, "127.0.0.2").await;
    apply_import_accept_all(&server, "127.0.0.2").await;

    fake_announce_prefix(&server, &mut fake, &[24, 10, 0, 1], "10.0.1.0/24").await;

    // Send BoRR but do NOT send EoRR -> timer should sweep after 1s
    fake.send_raw(&build_raw_route_refresh(1, 1, 1)).await;

    poll_until_with_timeout(
        || async { !has_route(&server, "10.0.1.0/24").await },
        "Stale TTL (1s) did not sweep route within 3s",
        Duration::from_secs(3),
    )
    .await;
}

/// RFC 7313: EoRR sweeps all stale routes when none are re-advertised.
#[tokio::test]
async fn test_eorr_sweeps_all_routes() {
    let (server, mut fake) = setup_enhanced_rr_peers().await;

    fake_announce_prefix(&server, &mut fake, &[24, 10, 0, 1], "10.0.1.0/24").await;
    fake_announce_prefix(&server, &mut fake, &[24, 10, 0, 2], "10.0.2.0/24").await;

    // BoRR + EoRR with no routes re-advertised between them
    fake.send_raw(&build_raw_route_refresh(1, 1, 1)).await;
    fake.send_raw(&build_raw_route_refresh(1, 2, 1)).await;

    // All routes should be purged
    poll_route_withdrawal(&[&server]).await;
}
