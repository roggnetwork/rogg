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

//! Tests for BGP UPDATE message error handling per RFC 7606 and RFC 4271 Section 6.3

mod utils;
pub use utils::*;

use bgpgg::bgp::msg::MessageType;
use bgpgg::bgp::msg::BGP_MARKER;
use bgpgg::bgp::msg_notification::{BgpError, UpdateMessageError};
use bgpgg::bgp::msg_update::{attr_flags, attr_type_code, Origin};
use bgpgg::grpc::proto::{BgpState, ListRoutesRequest};
use std::net::Ipv4Addr;

/// RFC 7606: missing well-known mandatory attribute -> treat-as-withdraw (session stays up)
#[tokio::test]
async fn test_update_missing_well_known_attribute() {
    let test_cases = vec![
        (
            "origin",
            vec![
                attr_as_path_empty(),
                attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
        ),
        (
            "as_path",
            vec![attr_origin_igp(), attr_next_hop(Ipv4Addr::new(10, 0, 0, 1))],
        ),
        ("next_hop", vec![attr_origin_igp(), attr_as_path_empty()]),
    ];

    for (name, attrs) in test_cases {
        let (server, mut peer) = setup_server_and_fake_peer().await;

        let nlri = &[24, 10, 11, 12]; // 10.11.12.0/24
        let msg = build_raw_update(
            &[],
            &attrs.iter().map(|a| a.as_slice()).collect::<Vec<_>>(),
            nlri,
            None,
        );

        peer.send_raw(&msg).await;

        // RFC 7606: treat-as-withdraw, session stays up
        poll_peer_stats(
            &server,
            &peer.address,
            ExpectedStats {
                update_received: Some(1),
                ..Default::default()
            },
        )
        .await;

        assert!(
            verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
            "Test case: {} - peer should stay established (treat-as-withdraw)",
            name
        );

        // Route should NOT be installed
        let routes = server
            .client
            .list_routes(ListRoutesRequest::default())
            .await
            .expect("get routes");
        assert!(
            routes.is_empty(),
            "Test case: {} - route should be withdrawn",
            name
        );
    }
}

#[tokio::test]
async fn test_update_malformed_attribute_list() {
    let (_server, mut peer) = setup_server_and_fake_peer().await;

    // Withdrawn route: 10.11.12.0/24 (prefix length byte followed by prefix bytes)
    let withdrawn_data = &[24, 10, 11, 12];

    // Build UPDATE claiming 100 bytes of attributes but provide none
    // Withdrawn Routes Length (4) + Total Attribute Length (100) + 4 exceeds actual message length
    let msg = build_raw_update(withdrawn_data, &[], &[], Some(100));

    peer.send_raw(&msg).await;

    // This is a framing error -> still session reset
    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList)
    );
    assert_eq!(notif.data(), &[] as &[u8]);
}

/// RFC 7606: ORIGIN flag errors -> treat-as-withdraw (session stays up)
#[tokio::test]
async fn test_update_attribute_flags_error_origin() {
    let test_cases = vec![
        (
            "optional_transitive",
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
        ),
        (
            "transitive_partial",
            attr_flags::TRANSITIVE | attr_flags::PARTIAL,
        ),
    ];

    for (name, wrong_flags) in test_cases {
        let (server, mut peer) = setup_server_and_fake_peer().await;

        let malformed_attr =
            build_attr_bytes(wrong_flags, attr_type_code::ORIGIN, 1, &[Origin::IGP as u8]);
        let nlri = &[24, 10, 11, 12];
        let msg = build_raw_update(
            &[],
            &[
                &malformed_attr,
                &attr_as_path_empty(),
                &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
            nlri,
            None,
        );

        peer.send_raw(&msg).await;

        // RFC 7606: treat-as-withdraw, session stays up
        poll_peer_stats(
            &server,
            &peer.address,
            ExpectedStats {
                update_received: Some(1),
                ..Default::default()
            },
        )
        .await;

        assert!(
            verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
            "Test case: {} - peer should stay established",
            name
        );

        let routes = server
            .client
            .list_routes(ListRoutesRequest::default())
            .await
            .expect("get routes");
        assert!(
            routes.is_empty(),
            "Test case: {} - route should be withdrawn",
            name
        );
    }
}

/// RFC 7606 Section 7.4: MED flag errors -> treat-as-withdraw (session stays up, route withdrawn)
#[tokio::test]
async fn test_update_attribute_flags_error_med_missing_optional_bit() {
    let (server, mut peer) = setup_server_and_fake_peer().await;

    // Build MED attribute with WRONG flags (missing OPTIONAL bit)
    let wrong_flags = attr_flags::TRANSITIVE; // Should have OPTIONAL too
    let malformed_attr = build_attr_bytes(
        wrong_flags,
        attr_type_code::MULTI_EXIT_DISC,
        4,
        &[0, 0, 0, 100],
    );
    let nlri = &[24, 10, 11, 12];
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
            &malformed_attr,
        ],
        nlri,
        None,
    );

    peer.send_raw(&msg).await;

    // RFC 7606 Section 7.4: treat-as-withdraw for MED, session stays up
    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    assert!(
        verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
        "Peer should stay established (treat-as-withdraw for MED)"
    );

    // Route should NOT be installed (treat-as-withdraw)
    poll_while(
        || async {
            let routes = server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .unwrap_or_default();
            routes.iter().all(|r| !route_has_prefix(r, "10.11.12.0/24"))
        },
        Duration::from_secs(1),
        "route 10.11.12.0/24 should not be installed",
    )
    .await;
}

/// RFC 7606 Section 5.2: attribute length errors with no NLRI/withdrawn
/// escalate to session reset (no routes to withdraw)
#[tokio::test]
async fn test_update_attribute_length_error_no_nlri() {
    // Only attributes whose error action is treat-as-withdraw escalate via
    // Section 5.2 when there are no NLRI. LOCAL_PREF is excluded because
    // on eBGP sessions (setup_server_and_fake_peer) it's attribute-discard
    // per RFC 7606 Section 7.5.
    let test_cases = vec![
        (
            "origin_wrong_length",
            build_attr_bytes(
                attr_flags::TRANSITIVE,
                attr_type_code::ORIGIN,
                2,
                &[Origin::IGP as u8],
            ),
        ),
        (
            "next_hop_wrong_length",
            build_attr_bytes(
                attr_flags::TRANSITIVE,
                attr_type_code::NEXT_HOP,
                5,
                &[10, 0, 0, 1, 0],
            ),
        ),
    ];

    for (name, malformed_attr) in test_cases {
        let (_server, mut peer) = setup_server_and_fake_peer().await;

        // No NLRI -> Section 5.2 escalation -> session reset
        let msg = build_raw_update(&[], &[&malformed_attr], &[], None);
        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
            "Test case: {}",
            name
        );
    }
}

/// RFC 7606 Section 5.2: UPDATE with withdrawn routes + malformed attr + no reachable NLRI
/// must escalate to session reset even though withdrawn routes exist.
#[tokio::test]
async fn test_update_section_5_2_no_reachable_nlri_escalation() {
    let (_server, mut peer) = setup_server_and_fake_peer().await;

    // Malformed ORIGIN (length=2 instead of 1) -> normally treat-as-withdraw
    let malformed_origin =
        build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 2, &[0, 0]);

    // UPDATE has withdrawn routes but NO reachable NLRI
    let withdrawn = &[24, 10, 11, 12]; // 10.11.12.0/24
    let msg = build_raw_update(withdrawn, &[&malformed_origin], &[], None);
    peer.send_raw(&msg).await;

    // Section 5.2: path attributes present (not just MP_UNREACH_NLRI),
    // no reachable NLRI, error is not attribute-discard -> session reset
    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
    );
}

/// RFC 7606: attribute length error with NLRI -> treat-as-withdraw (session stays up)
#[tokio::test]
async fn test_update_attribute_length_error_with_nlri() {
    let (server, mut peer) = setup_server_and_fake_peer().await;

    // NEXT_HOP with wrong length (5 instead of 4) - but correctly sized in the wire buffer
    let malformed_attr = build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::NEXT_HOP,
        5,
        &[10, 0, 0, 1, 0],
    );

    let nlri = &[24, 10, 11, 12];
    // Send only the malformed attr (other missing attrs also trigger treat-as-withdraw)
    let msg = build_raw_update(&[], &[&malformed_attr], nlri, None);
    peer.send_raw(&msg).await;

    // RFC 7606: treat-as-withdraw, session stays up
    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    assert!(
        verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
        "Peer should stay established (treat-as-withdraw)",
    );

    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .expect("get routes");
    assert!(routes.is_empty(), "Route should be withdrawn");
}

/// Unrecognized well-known attribute still causes session reset
#[tokio::test]
async fn test_update_unrecognized_well_known_attribute() {
    let (_server, mut peer) = setup_server_and_fake_peer().await;

    // Unrecognized well-known attribute (OPTIONAL=0, unassigned type code)
    let unrecognized_attr = build_attr_bytes(attr_flags::TRANSITIVE, 200, 2, &[0xaa, 0xbb]);
    let msg = build_raw_update(&[], &[&unrecognized_attr], &[], None);

    peer.send_raw(&msg).await;

    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::UnrecognizedWellKnownAttribute)
    );
    assert_eq!(notif.data(), &[attr_flags::TRANSITIVE, 200, 2, 0xaa, 0xbb]);
}

/// RFC 7606: invalid ORIGIN value -> treat-as-withdraw (session stays up)
#[tokio::test]
async fn test_update_invalid_origin_attribute() {
    let (server, mut peer) = setup_server_and_fake_peer().await;

    let invalid_origin_attr =
        build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 1, &[3]); // 3 is invalid

    let nlri = &[24, 10, 11, 12];
    let msg = build_raw_update(
        &[],
        &[
            &invalid_origin_attr,
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
        nlri,
        None,
    );

    peer.send_raw(&msg).await;

    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    assert!(
        verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
        "Peer should stay established (treat-as-withdraw for invalid ORIGIN)"
    );

    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .expect("get routes");
    assert!(routes.is_empty(), "Route should be withdrawn");
}

/// RFC 7606: invalid NEXT_HOP -> treat-as-withdraw (session stays up)
#[tokio::test]
async fn test_update_invalid_next_hop_attribute() {
    let test_cases = vec![
        ("0.0.0.0", [0x00, 0x00, 0x00, 0x00]),
        ("255.255.255.255", [0xff, 0xff, 0xff, 0xff]),
        ("224.0.0.1", [0xe0, 0x00, 0x00, 0x01]),
    ];

    for (name, ip_bytes) in test_cases {
        let (server, mut peer) = setup_server_and_fake_peer().await;

        let invalid_next_hop_attr = build_attr_bytes(
            attr_flags::TRANSITIVE,
            attr_type_code::NEXT_HOP,
            4,
            &ip_bytes,
        );

        let nlri = &[24, 10, 11, 12];
        let msg = build_raw_update(
            &[],
            &[
                &attr_origin_igp(),
                &attr_as_path_empty(),
                &invalid_next_hop_attr,
            ],
            nlri,
            None,
        );

        peer.send_raw(&msg).await;

        poll_peer_stats(
            &server,
            &peer.address,
            ExpectedStats {
                update_received: Some(1),
                ..Default::default()
            },
        )
        .await;

        assert!(
            verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
            "Test case: {} - peer should stay established (treat-as-withdraw)",
            name
        );

        let routes = server
            .client
            .list_routes(ListRoutesRequest::default())
            .await
            .expect("get routes");
        assert!(
            routes.is_empty(),
            "Test case: {} - route should be withdrawn",
            name
        );
    }
}

// RFC 4271 5.1.3 NEXT_HOP semantic validation tests

#[tokio::test]
async fn test_next_hop_is_local_address_rejected() {
    // Server bound to 127.0.0.1, FakePeer sends UPDATE with NEXT_HOP = 127.0.0.1
    let (server, mut peer) = setup_server_and_fake_peer().await;

    // Send UPDATE with NEXT_HOP = server's local address (127.0.0.1)
    let nlri = &[24, 10, 11, 12]; // 10.11.12.0/24
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(127, 0, 0, 1)), // Server's local addr
        ],
        nlri,
        None,
    );
    peer.send_raw(&msg).await;

    // Give server time to process
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Route should NOT be installed (NEXT_HOP = local address)
    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .expect("Failed to get routes");
    assert!(
        routes.is_empty(),
        "Route should be rejected when NEXT_HOP is local address"
    );
}

/// RFC 7606: malformed AS_PATH (parse errors) -> treat-as-withdraw (session stays up)
#[tokio::test]
async fn test_update_malformed_as_path() {
    let test_cases = vec![
        (
            "invalid_segment_type",
            build_attr_bytes(
                attr_flags::TRANSITIVE,
                attr_type_code::AS_PATH,
                4,
                &[0x00, 0x01, 0x00, 0x0a], // segment_type=0 (invalid), len=1, ASN=10
            ),
        ),
        (
            "truncated_asn_data",
            build_attr_bytes(
                attr_flags::TRANSITIVE,
                attr_type_code::AS_PATH,
                4,
                &[0x02, 0x02, 0x00, 0x0a], // AS_SEQUENCE, claims 2 ASNs but only 1 provided
            ),
        ),
    ];

    for (name, malformed_as_path) in test_cases {
        let (server, mut peer) = setup_server_and_fake_peer().await;

        let nlri = &[24, 10, 11, 12];
        let msg = build_raw_update(
            &[],
            &[
                &attr_origin_igp(),
                &malformed_as_path,
                &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
            nlri,
            None,
        );

        peer.send_raw(&msg).await;

        poll_peer_stats(
            &server,
            &peer.address,
            ExpectedStats {
                update_received: Some(1),
                ..Default::default()
            },
        )
        .await;

        assert!(
            verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
            "Test case: {} - peer should stay established (treat-as-withdraw)",
            name
        );

        let routes = server
            .client
            .list_routes(ListRoutesRequest::default())
            .await
            .expect("get routes");
        assert!(
            routes.is_empty(),
            "Test case: {} - route should be withdrawn",
            name
        );
    }
}

/// RFC 7606 Section 7.2: eBGP first-AS mismatch -> treat-as-withdraw (session stays up)
#[tokio::test]
async fn test_update_as_path_first_as_mismatch() {
    let (server, mut peer) = setup_server_and_fake_peer().await;

    // Peer is AS 65002, but AS_PATH starts with 65027
    let bad_as_path = build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::AS_PATH,
        6,
        &[0x02, 0x02, 0xfe, 0x03, 0xfe, 0x04], // AS_SEQUENCE [65027, 65028]
    );

    let nlri = &[24, 10, 11, 12];
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &bad_as_path,
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
        nlri,
        None,
    );

    peer.send_raw(&msg).await;

    // RFC 7606 Section 7.2: treat-as-withdraw, session stays up
    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    assert!(
        verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
        "peer should stay established (treat-as-withdraw)"
    );

    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .expect("get routes");
    assert!(routes.is_empty(), "route should be withdrawn");
}

/// RFC 7606: optional attribute errors -> attribute-discard (session stays up, route installed)
#[tokio::test]
async fn test_update_optional_attribute_error() {
    // MED is now treat-as-withdraw (RFC 7606 Section 7.4), so only
    // AGGREGATOR remains as a true attribute-discard case here.
    let (server, mut peer) = setup_server_and_fake_peer().await;
    apply_import_accept_all(&server, &peer.address).await;

    let invalid_attr = build_attr_bytes(
        attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
        attr_type_code::AGGREGATOR,
        4,
        &[0x00, 0x01, 0x01, 0x01],
    );
    let nlri = &[24, 10, 11, 12];
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
            &invalid_attr,
        ],
        nlri,
        None,
    );

    peer.send_raw(&msg).await;

    // RFC 7606 Section 7.7: attribute-discard for AGGREGATOR, route installed
    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    assert!(
        verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
        "Peer should stay established (attribute-discard for AGGREGATOR)"
    );

    // Route should be installed (bad optional attr discarded, rest valid)
    poll_until(
        || async {
            let routes = server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .unwrap_or_default();
            routes.iter().any(|r| route_has_prefix(r, "10.11.12.0/24"))
        },
        "route 10.11.12.0/24 should be installed",
    )
    .await;
}

/// RFC 7606: duplicate non-MP attributes are silently discarded (keep first)
#[tokio::test]
async fn test_update_duplicate_attribute() {
    let (server, mut peer) = setup_server_and_fake_peer().await;
    apply_import_accept_all(&server, &peer.address).await;

    // Send UPDATE with two ORIGIN attributes (duplicate) - silently keep first
    let nlri = &[24, 10, 11, 12];
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
        nlri,
        None,
    );

    peer.send_raw(&msg).await;

    // RFC 7606: duplicate non-MP attrs silently discarded, session stays up
    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    assert!(
        verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
        "Peer should stay established (duplicate attr discarded)"
    );

    // Route should be installed successfully
    poll_until(
        || async {
            let routes = server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .unwrap_or_default();
            routes.iter().any(|r| route_has_prefix(r, "10.11.12.0/24"))
        },
        "route 10.11.12.0/24 should be installed",
    )
    .await;
}

#[tokio::test]
async fn test_update_no_nlri_valid() {
    let (server, mut peer) = setup_server_and_fake_peer().await;

    // UPDATE with valid attributes but no NLRI
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
        &[], // No NLRI
        None,
    );

    peer.send_raw(&msg).await;

    // Wait for UPDATE to be received
    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    // Peer should still be established (no NOTIFICATION sent)
    assert!(
        verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
        "Peer should remain established after valid UPDATE with no NLRI"
    );
}

#[tokio::test]
async fn test_update_multicast_nlri_ignored() {
    let (server, mut peer) = setup_server_and_fake_peer().await;

    // Send UPDATE with multicast NLRI (224.0.0.0/24)
    let multicast_nlri = &[24, 224, 0, 0];
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
        multicast_nlri,
        None,
    );

    peer.send_raw(&msg).await;

    // Wait for UPDATE to be received
    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    // Multicast prefix should be silently ignored, not installed
    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .expect("Failed to get routes");
    assert!(routes.is_empty(), "Multicast NLRI should be ignored");
}

/// RFC 7606: eBGP peers should have LOCAL_PREF silently stripped by parser
#[tokio::test]
async fn test_update_ebgp_local_pref_stripped() {
    // setup_server_and_fake_peer: server=AS65001, peer=AS65002 -> eBGP
    let (server, mut peer) = setup_server_and_fake_peer().await;
    apply_import_accept_all(&server, &peer.address).await;

    // Send UPDATE with LOCAL_PREF=200 (should be stripped for eBGP)
    let nlri = &[24, 10, 11, 12]; // 10.11.12.0/24
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
            &attr_local_pref(200),
        ],
        nlri,
        None,
    );

    peer.send_raw(&msg).await;

    // Route should be installed (LOCAL_PREF silently stripped, not an error)
    poll_until(
        || async {
            let routes = server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .unwrap_or_default();
            routes
                .iter()
                .any(|route| route_has_prefix(route, "10.11.12.0/24"))
        },
        "route 10.11.12.0/24 should be installed",
    )
    .await;

    // Verify LOCAL_PREF was stripped -> defaults to 100 in Loc-RIB
    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .expect("get routes");
    let route = routes
        .iter()
        .find(|route| route_has_prefix(route, "10.11.12.0/24"))
        .expect("route should exist");
    let path = &route.paths[0];
    assert_eq!(
        path.local_pref,
        Some(100),
        "LOCAL_PREF should be stripped from eBGP and default to 100 (got {:?})",
        path.local_pref
    );
}

/// RFC 7606: when multiple attribute errors occur, the strongest strategy wins
/// TreatAsWithdraw > AttributeDiscard
#[tokio::test]
async fn test_update_multiple_errors_strongest_wins() {
    let (server, mut peer) = setup_server_and_fake_peer().await;

    // Invalid ORIGIN value -> TreatAsWithdraw
    let invalid_origin = build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 1, &[3]);
    // Invalid MED length (3 instead of 4) -> AttributeDiscard
    let invalid_med = build_attr_bytes(
        attr_flags::OPTIONAL,
        attr_type_code::MULTI_EXIT_DISC,
        3,
        &[0, 0, 1],
    );

    let nlri = &[24, 10, 11, 12]; // 10.11.12.0/24
    let msg = build_raw_update(
        &[],
        &[
            &invalid_origin,
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
            &invalid_med,
        ],
        nlri,
        None,
    );

    peer.send_raw(&msg).await;

    // TreatAsWithdraw wins over AttributeDiscard -> session stays up, route withdrawn
    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    assert!(
        verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
        "Peer should stay established (treat-as-withdraw, not session reset)"
    );

    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .expect("get routes");
    assert!(
        routes.is_empty(),
        "Route should be withdrawn (treat-as-withdraw wins)"
    );
}

/// RFC 7606 Section 3(g): duplicate MP attributes -> session reset
#[tokio::test]
async fn test_update_duplicate_mp_attributes() {
    let mp_reach_value: &[u8] = &[
        0x00, 0x01, // AFI = IPv4
        0x01, // SAFI = Unicast
        0x04, // Next hop length = 4
        0x0a, 0x00, 0x00, 0x01, // Next hop = 10.0.0.1
        0x00, // Reserved
        0x18, 0x0a, 0x0b, 0x0c, // NLRI: 10.11.12.0/24
    ];
    let mp_reach = build_attr_bytes(
        attr_flags::OPTIONAL,
        attr_type_code::MP_REACH_NLRI,
        mp_reach_value.len() as u8,
        mp_reach_value,
    );

    let mp_unreach_value: &[u8] = &[
        0x00, 0x01, // AFI = IPv4
        0x01, // SAFI = Unicast
        0x18, 0x0a, 0x0b, 0x0c, // Withdrawn: 10.11.12.0/24
    ];
    let mp_unreach = build_attr_bytes(
        attr_flags::OPTIONAL,
        attr_type_code::MP_UNREACH_NLRI,
        mp_unreach_value.len() as u8,
        mp_unreach_value,
    );

    let test_cases: Vec<(&str, Vec<u8>)> = vec![
        ("duplicate_mp_reach", mp_reach),
        ("duplicate_mp_unreach", mp_unreach),
    ];

    for (name, mp_attr) in test_cases {
        let (_server, mut peer) = setup_server_and_fake_peer().await;

        let msg = build_raw_update(
            &[],
            &[
                &attr_origin_igp(),
                &attr_as_path_empty(),
                &mp_attr,
                &mp_attr,
            ],
            &[],
            None,
        );

        peer.send_raw(&msg).await;

        let notif = peer.read_notification().await;
        assert_eq!(
            notif.error(),
            &BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
            "Test case: {} - duplicate MP attribute should cause session reset",
            name
        );
    }
}

/// RFC 7606 Section 4: runt attribute header (fewer than 3 bytes remaining) -> treat-as-withdraw
#[tokio::test]
async fn test_update_runt_attribute_header() {
    let test_cases = vec![
        ("1_trailing_byte", vec![0xFFu8]),
        ("2_trailing_bytes", vec![0xFF, 0xFF]),
    ];

    for (name, trailing) in test_cases {
        let (server, mut peer) = setup_server_and_fake_peer().await;

        // Build valid attributes, then append trailing runt bytes
        let origin = attr_origin_igp();
        let as_path = attr_as_path_empty();
        let next_hop = attr_next_hop(Ipv4Addr::new(10, 0, 0, 1));
        let valid_len = origin.len() + as_path.len() + next_hop.len();
        let total_len = (valid_len + trailing.len()) as u16;

        // Manually construct the UPDATE body with trailing bytes in the attributes section
        let nlri = &[24, 10, 11, 12]; // 10.11.12.0/24
        let mut body = Vec::new();
        body.extend_from_slice(&0u16.to_be_bytes()); // withdrawn routes length
        body.extend_from_slice(&total_len.to_be_bytes()); // total attr length (includes runt)
        body.extend_from_slice(&origin);
        body.extend_from_slice(&as_path);
        body.extend_from_slice(&next_hop);
        body.extend_from_slice(&trailing);
        body.extend_from_slice(nlri);
        let msg = build_raw_message(BGP_MARKER, None, 2, &body); // type 2 = UPDATE

        peer.send_raw(&msg).await;

        // RFC 7606 Section 4: treat-as-withdraw, session stays up
        poll_peer_stats(
            &server,
            &peer.address,
            ExpectedStats {
                update_received: Some(1),
                ..Default::default()
            },
        )
        .await;

        assert!(
            verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
            "Test case: {} - peer should stay established",
            name
        );

        let routes = server
            .client
            .list_routes(ListRoutesRequest::default())
            .await
            .expect("get routes");
        assert!(
            routes.is_empty(),
            "Test case: {} - route should be withdrawn",
            name
        );
    }
}

/// RFC 7606 Section 4: attribute length exceeds remaining buffer -> treat-as-withdraw
#[tokio::test]
async fn test_update_attribute_length_overrun() {
    let (server, mut peer) = setup_server_and_fake_peer().await;

    // Build an attribute that claims more data than available.
    // ORIGIN with length=10 but only 1 byte of value data
    let overrun_attr = build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::ORIGIN,
        10,      // claims 10 bytes
        &[0x00], // only 1 byte
    );

    let nlri = &[24, 10, 11, 12]; // 10.11.12.0/24

    // Override total_attr_len to match the actual bytes we provide (not the claimed length)
    // The parser will see the attribute header claiming 10 bytes but only having a few available
    let msg = build_raw_update(&[], &[&overrun_attr], nlri, None);

    peer.send_raw(&msg).await;

    // RFC 7606 Section 4: treat-as-withdraw, session stays up
    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    assert!(
        verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
        "peer should stay established"
    );

    let routes = server
        .client
        .list_routes(ListRoutesRequest::default())
        .await
        .expect("get routes");
    assert!(routes.is_empty(), "route should be withdrawn");
}

/// RFC 7606: per-attribute malformed handling.
///
/// Each attribute type has a defined error action from malformed_attr_action():
///   - TreatAsWithdraw: session stays up, route withdrawn
///   - Discard: session stays up, route installed (bad attr dropped)
///
/// LOCAL_PREF, ORIGINATOR_ID, and CLUSTER_LIST differ by session type
/// (eBGP -> Discard, iBGP -> TreatAsWithdraw).
#[tokio::test]
async fn test_malformed_attribute_actions() {
    /// Which attribute should be absent after attribute-discard.
    /// None means treat-as-withdraw (route removed entirely).
    enum DiscardedAttr {
        LocalPref,
        AtomicAggregate,
        Aggregator,
        OriginatorId,
        ClusterList,
    }

    struct Case {
        name: &'static str,
        peer_asn: u32, // 65001 = iBGP, 65002 = eBGP
        /// Capabilities for the FakePeer OPEN. None = no 4-byte ASN.
        capabilities: Option<Vec<Vec<u8>>>,
        attrs: Vec<Vec<u8>>,
        treat_as_withdraw: bool,
        /// For attribute-discard cases: verify the specific attribute is absent.
        discarded_attr: Option<DiscardedAttr>,
    }

    let valid_origin = attr_origin_igp();
    let valid_as_path = attr_as_path_empty();
    let valid_next_hop = attr_next_hop(Ipv4Addr::new(10, 0, 0, 1));
    let valid_local_pref = attr_local_pref(200);

    let test_cases = vec![
        // Section 7.1: ORIGIN wrong length
        Case {
            name: "origin_wrong_length",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 2, &[0, 0]),
                valid_as_path.clone(),
                valid_next_hop.clone(),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
        // Section 7.2: AS_PATH invalid segment type
        Case {
            name: "as_path_invalid_segment",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                build_attr_bytes(
                    attr_flags::TRANSITIVE,
                    attr_type_code::AS_PATH,
                    4,
                    &[0x00, 0x01, 0x00, 0x0a], // segment_type=0 invalid
                ),
                valid_next_hop.clone(),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
        // Section 7.3: NEXT_HOP wrong length
        Case {
            name: "next_hop_wrong_length",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                build_attr_bytes(
                    attr_flags::TRANSITIVE,
                    attr_type_code::NEXT_HOP,
                    5,
                    &[10, 0, 0, 1, 0],
                ),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
        // Section 7.4: MED wrong length
        Case {
            name: "med_wrong_length",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::OPTIONAL,
                    attr_type_code::MULTI_EXIT_DISC,
                    3,
                    &[0, 0, 1],
                ),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
        // Section 7.5: LOCAL_PREF wrong length (eBGP -> Discard)
        Case {
            name: "local_pref_wrong_length_ebgp",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::TRANSITIVE,
                    attr_type_code::LOCAL_PREF,
                    3,
                    &[0, 0, 1],
                ),
            ],
            treat_as_withdraw: false,
            discarded_attr: Some(DiscardedAttr::LocalPref),
        },
        // Section 7.5: LOCAL_PREF wrong length (iBGP -> TreatAsWithdraw)
        Case {
            name: "local_pref_wrong_length_ibgp",
            peer_asn: 65001,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::TRANSITIVE,
                    attr_type_code::LOCAL_PREF,
                    3,
                    &[0, 0, 1],
                ),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
        // Section 7.6: ATOMIC_AGGREGATE wrong length
        Case {
            name: "atomic_aggregate_wrong_length",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::TRANSITIVE,
                    attr_type_code::ATOMIC_AGGREGATE,
                    1,
                    &[0],
                ),
            ],
            treat_as_withdraw: false,
            discarded_attr: Some(DiscardedAttr::AtomicAggregate),
        },
        // Section 7.7: AGGREGATOR wrong length
        Case {
            name: "aggregator_wrong_length",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                    attr_type_code::AGGREGATOR,
                    4,
                    &[0, 1, 1, 1],
                ),
            ],
            treat_as_withdraw: false,
            discarded_attr: Some(DiscardedAttr::Aggregator),
        },
        // Section 7.7: AGGREGATOR length=6 wrong when 4-byte ASN negotiated
        Case {
            name: "aggregator_2byte_len_with_4byte_asn",
            peer_asn: 65002,
            capabilities: Some(vec![build_capability_4byte_asn(65002)]),
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                    attr_type_code::AGGREGATOR,
                    6,
                    &[0, 1, 10, 0, 0, 1], // 2-byte ASN format (wrong for 4-byte session)
                ),
            ],
            treat_as_withdraw: false,
            discarded_attr: Some(DiscardedAttr::Aggregator),
        },
        // Section 7.7: AGGREGATOR length=8 wrong when 4-byte ASN NOT negotiated
        Case {
            name: "aggregator_4byte_len_without_4byte_asn",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                    attr_type_code::AGGREGATOR,
                    8,
                    &[0, 0, 0, 1, 10, 0, 0, 1], // 4-byte ASN format (wrong for 2-byte session)
                ),
            ],
            treat_as_withdraw: false,
            discarded_attr: Some(DiscardedAttr::Aggregator),
        },
        // Section 7.8: COMMUNITIES wrong length (not multiple of 4)
        Case {
            name: "communities_wrong_length",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                    attr_type_code::COMMUNITIES,
                    3,
                    &[0, 0, 1],
                ),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
        // Section 7.9: ORIGINATOR_ID wrong length (eBGP -> Discard)
        Case {
            name: "originator_id_wrong_length_ebgp",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::OPTIONAL,
                    attr_type_code::ORIGINATOR_ID,
                    3,
                    &[1, 1, 1],
                ),
            ],
            treat_as_withdraw: false,
            discarded_attr: Some(DiscardedAttr::OriginatorId),
        },
        // Section 7.9: ORIGINATOR_ID wrong length (iBGP -> TreatAsWithdraw)
        Case {
            name: "originator_id_wrong_length_ibgp",
            peer_asn: 65001,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::OPTIONAL,
                    attr_type_code::ORIGINATOR_ID,
                    3,
                    &[1, 1, 1],
                ),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
        // Section 7.10: CLUSTER_LIST wrong length (eBGP -> Discard)
        Case {
            name: "cluster_list_wrong_length_ebgp",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::OPTIONAL,
                    attr_type_code::CLUSTER_LIST,
                    3,
                    &[1, 1, 1],
                ),
            ],
            treat_as_withdraw: false,
            discarded_attr: Some(DiscardedAttr::ClusterList),
        },
        // Section 7.10: CLUSTER_LIST wrong length (iBGP -> TreatAsWithdraw)
        Case {
            name: "cluster_list_wrong_length_ibgp",
            peer_asn: 65001,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::OPTIONAL,
                    attr_type_code::CLUSTER_LIST,
                    3,
                    &[1, 1, 1],
                ),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
        // Section 7.14: EXTENDED_COMMUNITIES wrong length (not multiple of 8)
        Case {
            name: "extended_communities_wrong_length",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                    attr_type_code::EXTENDED_COMMUNITIES,
                    7,
                    &[0; 7],
                ),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
        // Section 8: LARGE_COMMUNITIES wrong length (not multiple of 12)
        Case {
            name: "large_communities_wrong_length",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                    attr_type_code::LARGE_COMMUNITIES,
                    11,
                    &[0; 11],
                ),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
        // Section 7.9: valid ORIGINATOR_ID from eBGP -> Discard (stripped)
        Case {
            name: "originator_id_valid_ebgp_stripped",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                attr_originator_id(Ipv4Addr::new(1, 1, 1, 1)),
            ],
            treat_as_withdraw: false,
            discarded_attr: Some(DiscardedAttr::OriginatorId),
        },
        // Section 7.10: valid CLUSTER_LIST from eBGP -> Discard (stripped)
        Case {
            name: "cluster_list_valid_ebgp_stripped",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                attr_cluster_list(&[Ipv4Addr::new(1, 1, 1, 1)]),
            ],
            treat_as_withdraw: false,
            discarded_attr: Some(DiscardedAttr::ClusterList),
        },
        // RFC 7606 Section 3(c): ORIGIN wrong flags -> treat-as-withdraw
        Case {
            name: "origin_wrong_flags",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                // ORIGIN with OPTIONAL flag set (should be well-known=0)
                build_attr_bytes(attr_flags::OPTIONAL, attr_type_code::ORIGIN, 1, &[0]),
                valid_as_path.clone(),
                valid_next_hop.clone(),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
        // RFC 7606 Section 3(f): ATOMIC_AGGREGATE wrong flags -> attribute-discard
        Case {
            name: "atomic_aggregate_wrong_flags",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                // ATOMIC_AGGREGATE with OPTIONAL flag set (should be well-known=0)
                build_attr_bytes(
                    attr_flags::OPTIONAL,
                    attr_type_code::ATOMIC_AGGREGATE,
                    0,
                    &[],
                ),
            ],
            treat_as_withdraw: false,
            discarded_attr: Some(DiscardedAttr::AtomicAggregate),
        },
        // RFC 7606 Section 3(f): AGGREGATOR wrong flags -> attribute-discard
        Case {
            name: "aggregator_wrong_flags",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                // AGGREGATOR with TRANSITIVE only (missing OPTIONAL)
                build_attr_bytes(
                    attr_flags::TRANSITIVE,
                    attr_type_code::AGGREGATOR,
                    6,
                    &[0, 1, 1, 1, 1, 1],
                ),
            ],
            treat_as_withdraw: false,
            discarded_attr: Some(DiscardedAttr::Aggregator),
        },
        // RFC 7606 Section 3(c): AS4_PATH wrong flags -> treat-as-withdraw
        Case {
            name: "as4_path_wrong_flags",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::AS4_PATH, 0, &[]),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
        // RFC 7606 Section 3(c): AS4_AGGREGATOR wrong flags -> treat-as-withdraw
        Case {
            name: "as4_aggregator_wrong_flags",
            peer_asn: 65002,
            capabilities: None,
            attrs: vec![
                valid_origin.clone(),
                valid_as_path.clone(),
                valid_next_hop.clone(),
                build_attr_bytes(
                    attr_flags::TRANSITIVE,
                    attr_type_code::AS4_AGGREGATOR,
                    0,
                    &[],
                ),
            ],
            treat_as_withdraw: true,
            discarded_attr: None,
        },
    ];

    for case in test_cases {
        let server = setup_server_with_passive_peer().await;
        let mut peer = FakePeer::connect_and_handshake(
            None,
            &server,
            case.peer_asn,
            Ipv4Addr::new(2, 2, 2, 2),
            case.capabilities,
        )
        .await;
        apply_import_accept_all(&server, &peer.address).await;

        // First install the route with a valid UPDATE
        peer.send_raw(&build_raw_update(
            &[],
            &[
                &valid_origin,
                &valid_as_path,
                &valid_next_hop,
                &valid_local_pref,
            ],
            &[24, 10, 11, 12], // 10.11.12.0/24
            None,
        ))
        .await;

        let install_msg = format!(
            "Test case: {} - route should be installed before malformed UPDATE",
            case.name
        );
        poll_until(
            || async {
                let routes = server
                    .client
                    .list_routes(ListRoutesRequest::default())
                    .await
                    .unwrap_or_default();
                routes
                    .iter()
                    .any(|route| route_has_prefix(route, "10.11.12.0/24"))
            },
            &install_msg,
        )
        .await;

        // Now send the malformed UPDATE for the same prefix
        peer.send_raw(&build_raw_update(
            &[],
            &case.attrs.iter().map(|a| a.as_slice()).collect::<Vec<_>>(),
            &[24, 10, 11, 12],
            None,
        ))
        .await;

        poll_peer_stats(
            &server,
            &peer.address,
            ExpectedStats {
                update_received: Some(2),
                ..Default::default()
            },
        )
        .await;

        assert!(
            verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
            "Test case: {} - peer should stay established",
            case.name
        );

        if case.treat_as_withdraw {
            poll_route_withdrawal(&[&server]).await;
        } else {
            let routes = server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .expect("get routes");
            let route = routes
                .iter()
                .find(|route| route_has_prefix(route, "10.11.12.0/24"))
                .unwrap_or_else(|| {
                    panic!(
                        "Test case: {} - route should still be installed (attribute-discard)",
                        case.name
                    )
                });
            if let Some(ref attr) = case.discarded_attr {
                let path = &route.paths[0];
                match attr {
                    DiscardedAttr::LocalPref => assert_eq!(
                        path.local_pref,
                        Some(100),
                        "Test case: {} - LOCAL_PREF should revert to default (100) after discard",
                        case.name
                    ),
                    DiscardedAttr::AtomicAggregate => assert!(
                        !path.atomic_aggregate,
                        "Test case: {} - ATOMIC_AGGREGATE should be discarded",
                        case.name
                    ),
                    DiscardedAttr::Aggregator => assert!(
                        path.aggregator.is_none(),
                        "Test case: {} - AGGREGATOR should be discarded",
                        case.name
                    ),
                    DiscardedAttr::OriginatorId => assert!(
                        path.originator_id.is_none(),
                        "Test case: {} - ORIGINATOR_ID should be discarded",
                        case.name
                    ),
                    DiscardedAttr::ClusterList => assert!(
                        path.cluster_list.is_empty(),
                        "Test case: {} - CLUSTER_LIST should be discarded",
                        case.name
                    ),
                }
            }
        }
    }
}

/// RFC 7606 Section 3: syntactically incorrect Withdrawn Routes field -> treat-as-withdraw.
/// The announced route should be treated as withdrawn, session stays up.
#[tokio::test]
async fn test_malformed_withdrawn_routes_nlri() {
    let server = setup_server_with_passive_peer().await;
    let mut peer =
        FakePeer::connect_and_handshake(None, &server, 65002, Ipv4Addr::new(2, 2, 2, 2), None)
            .await;
    apply_import_accept_all(&server, &peer.address).await;

    // First install a route via valid UPDATE
    peer.send_raw(&build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
        &[24, 10, 11, 12], // 10.11.12.0/24
        None,
    ))
    .await;

    poll_until(
        || async {
            let routes = server
                .client
                .list_routes(ListRoutesRequest::default())
                .await
                .unwrap_or_default();
            routes
                .iter()
                .any(|route| route_has_prefix(route, "10.11.12.0/24"))
        },
        "route should be installed before malformed UPDATE",
    )
    .await;

    // Build UPDATE with malformed withdrawn routes (prefix_len=33, invalid for IPv4)
    // and a valid NLRI announcement for the same prefix.
    // The malformed withdrawn field should trigger treat-as-withdraw,
    // converting the announced NLRI into a withdrawal.
    let malformed_withdrawn = vec![33, 10, 11, 12, 0, 0]; // prefix_len=33 is invalid
    let attrs: Vec<Vec<u8>> = vec![
        attr_origin_igp(),
        attr_as_path_empty(),
        attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
    ];
    let nlri = vec![24, 10, 11, 12]; // 10.11.12.0/24

    // Build the raw UPDATE manually since build_raw_update uses correct withdrawn bytes
    let mut body = Vec::new();
    body.extend_from_slice(&(malformed_withdrawn.len() as u16).to_be_bytes());
    body.extend_from_slice(&malformed_withdrawn);
    let total_attr_len: usize = attrs.iter().map(|attr| attr.len()).sum();
    body.extend_from_slice(&(total_attr_len as u16).to_be_bytes());
    for attr in &attrs {
        body.extend_from_slice(attr);
    }
    body.extend_from_slice(&nlri);
    let update = build_raw_message(BGP_MARKER, None, MessageType::Update.as_u8(), &body);
    peer.send_raw(&update).await;

    // The announced route should be withdrawn (treat-as-withdraw)
    poll_route_withdrawal(&[&server]).await;

    // Session should remain up
    assert!(
        verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
        "peer should stay established after malformed withdrawn routes"
    );
}

/// RFC 7606 Section 3(j): malformed NLRI field (prefix_len > 32) makes it impossible
/// to use treat-as-withdraw, so session reset applies.
#[tokio::test]
async fn test_malformed_nlri_field_session_reset() {
    let (_server, mut peer) = setup_server_and_fake_peer().await;

    // prefix_len=33 is invalid for IPv4
    let bad_nlri = &[33, 10, 11, 12, 0, 0];
    let msg = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_empty(),
            &attr_next_hop(Ipv4Addr::new(10, 0, 0, 1)),
        ],
        bad_nlri,
        None,
    );

    peer.send_raw(&msg).await;

    // NLRI can't be parsed -> session reset
    let notif = peer.read_notification().await;
    assert_eq!(
        notif.error(),
        &BgpError::UpdateMessageError(UpdateMessageError::InvalidNetworkField),
    );
}

/// RFC 7606 Section 5.2 negative case: discard-only error with no NLRI should NOT
/// escalate to session reset. Malformed ATOMIC_AGGREGATE is attribute-discard,
/// so the UPDATE is processed normally (no routes affected).
#[tokio::test]
async fn test_discard_only_no_nlri_no_escalation() {
    let (server, mut peer) = setup_server_and_fake_peer().await;

    // Malformed ATOMIC_AGGREGATE (length=1 instead of 0) -> attribute-discard
    let malformed_atomic_agg = build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::ATOMIC_AGGREGATE,
        1,
        &[0],
    );

    // No NLRI, no withdrawn routes - just the malformed attribute
    let msg = build_raw_update(&[], &[&malformed_atomic_agg], &[], None);
    peer.send_raw(&msg).await;

    // Attribute-discard errors should NOT trigger Section 5.2 escalation
    poll_peer_stats(
        &server,
        &peer.address,
        ExpectedStats {
            update_received: Some(1),
            ..Default::default()
        },
    )
    .await;

    assert!(
        verify_peers(&server, vec![peer.to_peer(BgpState::Established)]).await,
        "Peer should stay established (discard-only error, no Section 5.2 escalation)"
    );
}
