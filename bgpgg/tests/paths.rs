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

//! Tests for RFC 4271 Section 5: Path Attributes
//!
//! This module tests path attribute handling:
//!
//! ORIGIN preservation:
//! - ORIGIN attribute (IGP, EGP, INCOMPLETE) MUST NOT be changed by intermediate speakers
//!
//! AS_PATH manipulation:
//! - Originating routes: empty AS_PATH to iBGP peers, [local_AS] to eBGP peers
//! - eBGP: prepend local AS to AS_PATH when advertising to external peers
//! - iBGP: do NOT modify AS_PATH when advertising to internal peers
//!
//! NEXT_HOP handling:
//! - iBGP: Locally-originated routes with unspecified NEXT_HOP (0.0.0.0) are rewritten to router ID
//!
//! Extended Communities (RFC 4360):
//! - Transitive extended communities (bit 6 = 0) propagate across eBGP
//! - Non-transitive extended communities (bit 6 = 1) filtered on eBGP, propagate over iBGP

mod utils;
pub use utils::*;

use bgpgg::bgp::community;
use bgpgg::bgp::ext_community::*;
use bgpgg::bgp::msg_update::{attr_flags, attr_type_code};
use bgpgg::bgp::msg_update_types::LargeCommunity;
use bgpgg::bgp::msg_update_types::AS_TRANS;
use bgpgg::grpc::proto::{
    self, add_route_request,
    extended_community::{Community, TwoOctetAsSpecific},
    AddIpRouteRequest, AddRouteRequest, AsPathSegment, BgpState, ExtendedCommunity,
    ListRoutesRequest, Origin, SessionConfig, UnknownAttribute,
};
use conf::bgp::BgpConfig;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_origin_preservation() {
    // RFC 4271 Section 5.1.1: ORIGIN attribute
    // "Its value SHOULD NOT be changed by any other speaker."
    //
    // Topology: S1(AS65001) -> S2(AS65002) -> S3(AS65003)
    //                          eBGP           eBGP
    let [server1, server2, server3] = &mut create_asn_chain([65001, 65002, 65003], None).await;

    // S1 originates routes with different ORIGIN values
    let test_routes = [
        ("10.1.0.0/24", "192.168.1.1", Origin::Igp),
        ("10.2.0.0/24", "192.168.2.1", Origin::Egp),
        ("10.3.0.0/24", "192.168.3.1", Origin::Incomplete),
    ];

    for (prefix, next_hop, origin) in test_routes {
        announce_route(
            server1,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: prefix.to_string(),
                next_hop: next_hop.to_string(),
                origin: Some(origin),
                ..Default::default()
            })),
        )
        .await;
    }

    // Helper to build expected routes with different AS_PATH, next_hop, and peer_address
    let build_expected_routes =
        |as_path: Vec<AsPathSegment>, next_hop: &str, peer_address: String| {
            test_routes
                .iter()
                .map(|(prefix, _, origin)| {
                    expected_route(
                        prefix,
                        PathParams {
                            as_path: as_path.clone(),
                            next_hop: next_hop.to_string(),
                            peer_address: peer_address.clone(),
                            origin: Some(*origin),
                            local_pref: Some(100),
                            ..Default::default()
                        },
                    )
                })
                .collect()
        };

    // Verify ORIGIN is preserved at each hop
    // eBGP rewrites NEXT_HOP to local address of the sending speaker
    poll_rib(&[
        (
            server2,
            build_expected_routes(
                vec![as_sequence(vec![65001])],
                &server1.address.to_string(),
                server1.address.to_string(),
            ),
        ),
        (
            server3,
            build_expected_routes(
                vec![as_sequence(vec![65002, 65001])],
                &server2.address.to_string(),
                server2.address.to_string(),
            ),
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_as_path_prepending_ebgp_vs_ibgp() {
    // RFC 4271 Section 5.1.2: AS_PATH handling
    //
    // eBGP: When advertising to external peer, prepend local AS to AS_PATH
    // iBGP: When advertising to internal peer, AS_PATH MUST NOT be modified
    //
    // Topology: S1(AS65001) -> S2(AS65002) -> S3(AS65002) -> S4(AS65003)
    //                          eBGP           iBGP           eBGP
    let [server1, server2, server3, server4] =
        &mut create_asn_chain([65001, 65002, 65002, 65003], None).await;

    // S1 originates a route (starts with empty AS_PATH)
    announce_route(
        server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Verify AS_PATH and NEXT_HOP at each hop:
    //
    // S1 -> S2 (eBGP): S1 creates AS_PATH=[65001], NEXT_HOP=1.1.1.1
    // S2 -> S3 (iBGP): S2 preserves AS_PATH=[65001] (does NOT prepend), NEXT_HOP=1.1.1.1 (preserved)
    // S3 -> S4 (eBGP): S3 prepends AS_PATH=[65002, 65001], NEXT_HOP=3.3.3.3 (rewritten to S3's router ID)
    poll_rib(&[
        (
            server2,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    ..PathParams::from_peer(server1) // eBGP: S1 created AS_SEQUENCE with its AS
                },
            )],
        ),
        (
            server3,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    as_path: vec![as_sequence(vec![65001])], // iBGP: S2 did NOT modify AS_PATH
                    next_hop: server1.address.to_string(),   // iBGP: NEXT_HOP preserved from S2
                    peer_address: server2.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                },
            )],
        ),
        (
            server4,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    as_path: vec![as_sequence(vec![65002, 65001])], // eBGP: S3 prepended its AS
                    ..PathParams::from_peer(server3) // eBGP: NEXT_HOP rewritten to S3's local address
                },
            )],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_originating_speaker_as_path() {
    // RFC 4271 Section 5.1.2: When a BGP speaker originates a route:
    //
    // (a) To external peer: includes its own AS in AS_SEQUENCE (single segment, single AS)
    // (b) To internal peer: includes empty AS_PATH
    //
    // Topology: S1(AS65001) -> S2(AS65001) -> S3(AS65002)
    //                          iBGP           eBGP
    let [server1, server2, server3] = &mut create_asn_chain([65001, 65001, 65002], None).await;

    // S1 originates a route
    announce_route(
        server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Verify AS_PATH and NEXT_HOP at each hop:
    //
    // S1 -> S2 (iBGP): S1 sends empty AS_PATH (case b), NEXT_HOP=192.168.1.1 (preserved explicit value)
    // S2 -> S3 (eBGP): S2 creates AS_PATH=[65001] (prepends its AS), NEXT_HOP=2.2.2.2 (rewritten to S2's router ID)
    poll_rib(&[
        (
            server2,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    as_path: vec![],                     // iBGP: originating speaker sends empty AS_PATH
                    next_hop: "192.168.1.1".to_string(), // iBGP: NEXT_HOP preserved (explicit value, not 0.0.0.0)
                    peer_address: server1.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                },
            )],
        ),
        (
            server3,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    ..PathParams::from_peer(server2) // eBGP: S2 prepended AS65001, NEXT_HOP rewritten
                },
            )],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_ebgp_prepend_as_before_as_set() {
    // RFC 4271 Section 5.1.2: AS_PATH handling with AS_SET
    //
    // Topology: S1(AS65001) -> S2(AS65002)
    //                          eBGP
    //
    // S1 injects a route with AS_SET[65003, 65004] as the first segment.
    // S2 should receive it with AS_SEQUENCE[65001] prepended by S1.

    let [server1, server2] = &mut create_asn_chain([65001, 65002], None).await;

    // S1 adds a route with AS_SET as the first segment
    announce_route(
        server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            as_path: vec![
                as_set(vec![65003, 65004]), // AS_SET as first segment
                as_sequence(vec![65005]),   // AS_SEQUENCE after
            ],
            ..Default::default()
        })),
    )
    .await;

    // Verify S2 receives the route with AS_SEQUENCE[65001] prepended
    // Result: AS_SEQUENCE[65001], AS_SET[65003, 65004], AS_SEQUENCE[65005]
    // eBGP: NEXT_HOP rewritten to S1's router ID
    poll_rib(&[(
        server2,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![
                    as_sequence(vec![65001]),   // Prepended by S1 (eBGP)
                    as_set(vec![65003, 65004]), // Original AS_SET
                    as_sequence(vec![65005]),   // Original AS_SEQUENCE
                ],
                ..PathParams::from_peer(server1) // eBGP: NEXT_HOP rewritten to S1's local address
            },
        )],
    )])
    .await;
}

#[tokio::test]
async fn test_next_hop_locally_originated_to_ibgp() {
    // RFC 4271 Section 5.1.3: NEXT_HOP for locally-originated routes
    //
    // "When announcing a locally-originated route to an internal peer, the BGP speaker
    // SHOULD use the interface address of the router through which the announced network
    // is reachable for the speaker as the NEXT_HOP."
    //
    // Topology: S1(AS65001, router_id=1.1.1.1) -> S2(AS65001, router_id=2.2.2.2)
    //                                    iBGP
    //
    // When S1 originates a route with NEXT_HOP unspecified (0.0.0.0),
    // the BGP speaker SHOULD set it to S1's local address (1.1.1.1)
    // when sending to iBGP peer S2.
    //
    // Note: NEXT_HOP is only auto-set when it's unspecified.
    // If explicitly set to a non-zero value, it's preserved.
    let [server1, server2] = &mut create_asn_chain([65001, 65001], None).await;

    // S1 originates a route with NEXT_HOP unspecified (0.0.0.0)
    announce_route(
        server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "0.0.0.0".to_string(), // Unspecified NEXT_HOP,
            ..Default::default()
        })),
    )
    .await;

    // RFC expectation: S2 should receive the route with NEXT_HOP set to S1's local address
    // (the interface address used for the peering session)
    poll_rib(&[(
        server2,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![], // iBGP: empty AS_PATH for locally-originated route
                next_hop: server1.address.to_string(), // NEXT_HOP should be set to S1's local address
                peer_address: server1.address.to_string(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                ..Default::default()
            },
        )],
    )])
    .await;
}

#[tokio::test]
async fn test_next_hop_rewrite_to_ebgp() {
    // RFC 4271 Section 5.1.3: NEXT_HOP handling when advertising to eBGP
    //
    // "By default, the BGP speaker SHOULD use the IP address of the interface
    // that the speaker uses to establish the BGP connection to peer X in the
    // NEXT_HOP attribute."
    //
    // Topology: S1(AS65001) -> S2(AS65001) -> S3(AS65002)
    //                          iBGP           eBGP
    //
    // When S1 sends a route to S2 via iBGP, S2 preserves NEXT_HOP.
    // When S2 advertises to S3 via eBGP, S2 SHOULD rewrite NEXT_HOP to self.
    let [server1, server2, server3] = &mut create_asn_chain([65001, 65001, 65002], None).await;

    // S1 originates a route with explicit NEXT_HOP
    announce_route(
        server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.100".to_string(), // Arbitrary NEXT_HOP,
            ..Default::default()
        })),
    )
    .await;

    // Verify NEXT_HOP handling:
    // S1 -> S2 (iBGP): NEXT_HOP preserved as 192.168.1.100
    // S2 -> S3 (eBGP): NEXT_HOP rewritten to S2's local address (2.2.2.2)
    poll_rib(&[
        (
            server2,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    as_path: vec![],                       // iBGP: empty AS_PATH
                    next_hop: "192.168.1.100".to_string(), // iBGP: NEXT_HOP preserved
                    peer_address: server1.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100),
                    ..Default::default()
                },
            )],
        ),
        (
            server3,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    ..PathParams::from_peer(server2) // eBGP: AS prepended, NEXT_HOP rewritten
                },
            )],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_local_pref_send_to_ibgp() {
    // RFC 4271 Section 5.1.5: LOCAL_PREF handling
    //
    // "LOCAL_PREF is a well-known attribute that SHALL be included in all
    //  UPDATE messages that a given BGP speaker sends to other internal peers."
    //
    // Topology: S1(AS65000) -> S2(AS65001) -> S3(AS65001)
    //                          eBGP           iBGP
    //
    // Verify LOCAL_PREF is propagated through iBGP:
    // - S1 originates route (external AS)
    // - S2 receives via eBGP, DefaultLocalPref policy sets to 100
    // - S3 receives via iBGP with LOCAL_PREF=100 (proves it was in UPDATE)
    let [server1, server2, server3] = &mut create_asn_chain([65000, 65001, 65001], None).await;

    // S1 originates a route
    announce_route(
        server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Verify:
    // S2 (eBGP): receives route with LOCAL_PREF=100 (set by DefaultLocalPref policy)
    // S3 (iBGP): receives route with LOCAL_PREF=100 (proves LOCAL_PREF was in UPDATE from S2)
    poll_rib(&[
        (
            server2,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    ..PathParams::from_peer(server1) // LOCAL_PREF set by DefaultLocalPref policy
                },
            )],
        ),
        (
            server3,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    as_path: vec![as_sequence(vec![65000])], // iBGP preserves AS_PATH
                    next_hop: server1.address.to_string(),   // iBGP preserves NEXT_HOP
                    peer_address: server2.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100), // LOCAL_PREF preserved from S2's UPDATE (proves it was included)
                    ..Default::default()
                },
            )],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_local_pref_not_sent_to_ebgp() {
    // RFC 4271 Section 5.1.5: LOCAL_PREF is only for iBGP
    //
    // "A BGP speaker SHALL calculate the degree of preference for each external
    //  route based on the locally-configured policy, and include the degree of
    //  preference when advertising a route to its internal peers."
    //
    // LOCAL_PREF is well-known discretionary, so it's NOT sent to eBGP peers.
    //
    // Topology: S1(AS65001) -> S2(AS65001) -> S3(AS65002)
    //                          iBGP           eBGP
    //
    // Verify LOCAL_PREF is not sent to eBGP peers:
    // - S1 originates route with LOCAL_PREF=200
    // - S2 receives via iBGP with LOCAL_PREF=200
    // - S3 receives via eBGP with LOCAL_PREF=100 (set by policy, NOT from S2)
    let [server1, server2, server3] = &mut create_asn_chain([65001, 65001, 65002], None).await;

    // S1 originates a route with LOCAL_PREF=200
    announce_route(
        server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            local_pref: Some(200), // Explicitly set LOCAL_PREF to 200,
            ..Default::default()
        })),
    )
    .await;

    // Verify S2 first (iBGP): receives route with LOCAL_PREF=200 (preserved from S1)
    poll_rib(&[(
        server2,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![],                     // iBGP: empty AS_PATH
                next_hop: "192.168.1.1".to_string(), // iBGP: NEXT_HOP preserved
                peer_address: server1.address.to_string(),
                origin: Some(Origin::Igp),
                local_pref: Some(200), // LOCAL_PREF=200 preserved via iBGP
                ..Default::default()
            },
        )],
    )])
    .await;

    // Verify S3 (eBGP): receives route with LOCAL_PREF=100 (set by DefaultLocalPref policy, NOT from S2)
    //                   This proves LOCAL_PREF was NOT sent in UPDATE from S2 to S3
    poll_rib(&[(
        server3,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                ..PathParams::from_peer(server2) // eBGP: AS prepended, NEXT_HOP rewritten, LOCAL_PREF=100
            },
        )],
    )])
    .await;
}

#[tokio::test]
async fn test_med_propagation_over_ibgp() {
    // RFC 4271 Section 5.1.4: MULTI_EXIT_DISC handling
    //
    // "If received over EBGP, the MULTI_EXIT_DISC attribute MAY be propagated
    //  over IBGP to other BGP speakers within the same AS."
    //
    // Topology: S1(AS65000) -> S2(AS65001) -> S3(AS65001)
    //                          eBGP           iBGP
    //
    // Verify MED is propagated through iBGP:
    // - S1 originates route with MED=50 (external AS)
    // - S2 receives via eBGP with MED=50
    // - S3 receives via iBGP with MED=50 (proves it was propagated)
    let [server1, server2, server3] = &mut create_asn_chain([65000, 65001, 65001], None).await;

    // S1 originates a route with MED=50
    announce_route(
        server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            med: Some(50), // Set MED=50,
            ..Default::default()
        })),
    )
    .await;

    // Verify:
    // S2 (eBGP): receives route with MED=50
    // S3 (iBGP): receives route with MED=50 (proves MED was propagated over iBGP)
    poll_rib(&[
        (
            server2,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    med: Some(50), // MED=50 received from S1
                    ..PathParams::from_peer(server1)
                },
            )],
        ),
        (
            server3,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    as_path: vec![as_sequence(vec![65000])], // iBGP preserves AS_PATH
                    next_hop: server1.address.to_string(),   // iBGP preserves NEXT_HOP
                    peer_address: server2.address.to_string(),
                    origin: Some(Origin::Igp),
                    local_pref: Some(100), // LOCAL_PREF preserved from S2
                    med: Some(50),         // MED=50 propagated over iBGP (proves propagation)
                    ..Default::default()
                },
            )],
        ),
    ])
    .await;
}

#[tokio::test]
async fn test_med_not_propagated_to_other_as() {
    // RFC 4271 Section 5.1.4: MULTI_EXIT_DISC must not cross AS boundaries
    //
    // "The MULTI_EXIT_DISC attribute received from a neighboring AS MUST NOT
    //  be propagated to other neighboring ASes."
    //
    // Topology: S1(AS65000) -> S2(AS65001) -> S3(AS65002)
    //                          eBGP           eBGP
    //
    // Verify MED is NOT propagated to other neighboring ASes:
    // - S1 originates route with MED=50
    // - S2 receives via eBGP with MED=50
    // - S3 receives via eBGP with MED=None (MED was NOT propagated to different AS)
    let [server1, server2, server3] = &mut create_asn_chain([65000, 65001, 65002], None).await;

    // S1 originates a route with MED=50
    announce_route(
        server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            med: Some(50), // Set MED=50,
            ..Default::default()
        })),
    )
    .await;

    // Verify S2 first (eBGP): receives route with MED=50
    poll_rib(&[(
        server2,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                med: Some(50), // MED=50 received from S1
                ..PathParams::from_peer(server1)
            },
        )],
    )])
    .await;

    // Verify S3 (eBGP to different AS): receives route with MED=None
    // This proves MED was NOT propagated to other neighboring AS (AS65002)
    poll_rib(&[(
        server3,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![as_sequence(vec![65001, 65000])], // eBGP: S2 prepended AS65001
                ..PathParams::from_peer(server2)                // eBGP: NEXT_HOP rewritten, MED=None
            },
        )],
    )])
    .await;
}

#[tokio::test]
async fn test_med_not_propagated_via_ibgp_to_other_as() {
    // RFC 4271 Section 5.1.4: MED from one AS must not reach another AS, even via iBGP
    //
    // Topology: S1(AS65000) -> S2(AS65001) -> S3(AS65001)
    //                          eBGP           iBGP      |
    //                                                   eBGP
    //                                                    |
    //                                                 S4(AS65002)
    //
    // Route learned via eBGP, propagated via iBGP, then to different AS:
    // - S1 originates with MED=50
    // - S2 receives via eBGP (source=Ebgp, MED=50)
    // - S3 receives via iBGP (source=Ibgp, MED=50) <- source changed!
    // - S4 must receive with MED=None (route from AS65000 can't have MED in AS65002)
    let [server1, server2, server3, server4] = chain_servers(
        [
            start_test_server(test_config(65000, 1)).await,
            start_test_server(test_config(65001, 2)).await,
            start_test_server(test_config(65001, 3)).await, // Same AS as S2
            start_test_server(test_config(65002, 4)).await,
        ],
        PeerConfig::default(),
    )
    .await;

    announce_route(
        &server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            med: Some(50),
            ..Default::default()
        })),
    )
    .await;

    // S2 (eBGP from S1): MED=50
    poll_rib(&[(
        &server2,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                med: Some(50),
                ..PathParams::from_peer(&server1)
            },
        )],
    )])
    .await;

    // S3 (iBGP from S2): MED=50 (iBGP preserves)
    poll_rib(&[(
        &server3,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![as_sequence(vec![65000])],
                next_hop: server1.address.to_string(),
                peer_address: server2.address.to_string(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                med: Some(50), // Preserved via iBGP
                ..Default::default()
            },
        )],
    )])
    .await;

    // S4 (eBGP from S3): MED MUST be None
    // BUG: Currently sends MED=50 because source changed to Ibgp at S3
    poll_rib(&[(
        &server4,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![as_sequence(vec![65001, 65000])],
                // MED must be None - route originated from AS65000
                ..PathParams::from_peer(&server3)
            },
        )],
    )])
    .await;
}

#[tokio::test]
async fn test_atomic_aggregate_propagation() {
    // RFC 4271 Section 5.1.6: ATOMIC_AGGREGATE propagation
    //
    // "A BGP speaker that receives a route with the ATOMIC_AGGREGATE attribute
    //  SHOULD NOT remove the attribute when propagating the route to other speakers."
    //
    // Topology: S1(AS65001) -> S2(AS65002) -> S3(AS65002)
    //                          eBGP           iBGP
    //
    // Verify ATOMIC_AGGREGATE is propagated in both eBGP and iBGP:
    // - S1 originates route with ATOMIC_AGGREGATE=true
    // - S2 receives via eBGP with ATOMIC_AGGREGATE=true
    // - S3 receives via iBGP with ATOMIC_AGGREGATE=true (proves propagation)
    let [server1, server2, server3] = &mut create_asn_chain([65001, 65002, 65002], None).await;

    // S1 originates a route with ATOMIC_AGGREGATE=true
    announce_route(
        server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            atomic_aggregate: true, // ATOMIC_AGGREGATE=true,
            ..Default::default()
        })),
    )
    .await;

    // Verify S2 (eBGP): receives route with ATOMIC_AGGREGATE=true
    poll_rib(&[(
        server2,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                atomic_aggregate: true, // ATOMIC_AGGREGATE=true (received from S1)
                ..PathParams::from_peer(server1)
            },
        )],
    )])
    .await;

    // Verify S3 (iBGP): receives route with ATOMIC_AGGREGATE=true
    // This proves ATOMIC_AGGREGATE was propagated over iBGP
    poll_rib(&[(
        server3,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![as_sequence(vec![65001])], // iBGP: AS_PATH preserved
                next_hop: server1.address.to_string(),   // iBGP: NEXT_HOP preserved
                peer_address: server2.address.to_string(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),  // LOCAL_PREF preserved from S2
                atomic_aggregate: true, // ATOMIC_AGGREGATE=true (propagated from S1 -> S2 -> S3)
                ..Default::default()
            },
        )],
    )])
    .await;
}

#[tokio::test]
async fn test_unknown_optional_attribute_handling_transitive() {
    test_unknown_optional_attribute_handling(
        attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
        vec![UnknownAttribute {
            attr_type: 200,
            flags: (attr_flags::OPTIONAL | attr_flags::TRANSITIVE | attr_flags::PARTIAL) as u32,
            value: vec![0xde, 0xad, 0xbe, 0xef],
        }],
    )
    .await;
}

#[tokio::test]
async fn test_unknown_optional_attribute_handling_non_transitive() {
    test_unknown_optional_attribute_handling(attr_flags::OPTIONAL, vec![]).await;
}

async fn test_unknown_optional_attribute_handling(
    attr_flags: u8,
    expected_unknown_attrs: Vec<UnknownAttribute>,
) {
    // Topology: FakePeer(S1) -> S2(AS65002) -> S3(AS65003)
    //                            iBGP            eBGP
    let [server2, server3] = &mut create_asn_chain([65002, 65003], Some(300)).await;

    // Add passive peer for FakePeer connection
    server2
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

    let mut server1 = FakePeer::connect(None, server2).await;
    server1
        .handshake_open(65002, std::net::Ipv4Addr::new(1, 1, 1, 1), 300)
        .await;
    server1.handshake_keepalive().await;

    let origin_attr = build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::ORIGIN, 1, &[0]);
    let as_path_attr = build_attr_bytes(attr_flags::TRANSITIVE, attr_type_code::AS_PATH, 0, &[]);
    let next_hop_attr = build_attr_bytes(
        attr_flags::TRANSITIVE,
        attr_type_code::NEXT_HOP,
        4,
        &[10, 0, 0, 1],
    );
    let unknown_attr = build_attr_bytes(attr_flags, 200, 4, &[0xde, 0xad, 0xbe, 0xef]);

    let nlri = vec![24, 192, 168, 1];
    let msg = build_raw_update(
        &[],
        &[&origin_attr, &as_path_attr, &next_hop_attr, &unknown_attr],
        &nlri,
        None,
    );

    server1.send_raw(&msg).await;

    poll_rib(&[(
        server3,
        vec![expected_route(
            "192.168.1.0/24",
            PathParams {
                unknown_attributes: expected_unknown_attrs,
                ..PathParams::from_peer(server2)
            },
        )],
    )])
    .await;
}

#[tokio::test]
async fn test_med_comparison_restricted_to_same_as() {
    // RFC 4271 Section 9.1.2.2(c): MED is only comparable between routes
    // from the same neighboring AS.
    //
    // Topology:  S1(AS65001, MED=100) ---\
    //            S2(AS65001, MED=50)  ----+--- S4(AS65004)
    //            S3(AS65002, MED=10)  ---/
    //
    // S4 receives three routes for 10.0.0.0/24:
    // - From S1 (AS65001): MED=100
    // - From S2 (AS65001): MED=50  <- wins among AS65001 routes
    // - From S3 (AS65002): MED=10  <- lowest MED but different AS
    //
    // Expected winner: S2 (AS65001, MED=50)
    // - S1 vs S2: same AS, MED compared -> S2 wins (50 < 100)
    // - S2 vs S3: different AS, MED NOT compared -> falls to peer address -> S2 wins (127.0.0.2 < 127.0.0.3)
    let server1 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.1:0",
        Ipv4Addr::new(1, 1, 1, 1),
        90,
    ))
    .await;
    let server2 = start_test_server(BgpConfig::new(
        65001,
        "127.0.0.2:0",
        Ipv4Addr::new(2, 2, 2, 2),
        90,
    ))
    .await;
    let server3 = start_test_server(BgpConfig::new(
        65002,
        "127.0.0.3:0",
        Ipv4Addr::new(3, 3, 3, 3),
        90,
    ))
    .await;
    let server4 = start_test_server(BgpConfig::new(
        65004,
        "127.0.0.4:0",
        Ipv4Addr::new(4, 4, 4, 4),
        90,
    ))
    .await;

    // Connect S1, S2, S3 to S4 (star topology)
    // Active-active peering - both sides call add_peer()
    server1.add_peer(&server4).await;
    server4.add_peer(&server1).await;
    server2.add_peer(&server4).await;
    server4.add_peer(&server2).await;
    server3.add_peer(&server4).await;
    server4.add_peer(&server3).await;

    // RFC 8212: eBGP peers need explicit accept-all policies
    apply_permit_all_routes(&server1, &server4).await;
    apply_permit_all_routes(&server2, &server4).await;
    apply_permit_all_routes(&server3, &server4).await;

    // Wait for all peers to establish
    poll_until(
        || async {
            verify_peers(
                &server4,
                vec![
                    server1.to_peer(BgpState::Established),
                    server2.to_peer(BgpState::Established),
                    server3.to_peer(BgpState::Established),
                ],
            )
            .await
        },
        "Timeout waiting for peers to establish",
    )
    .await;

    // All announce same prefix with different MEDs
    announce_route(
        &server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            med: Some(100),
            ..Default::default()
        })),
    )
    .await;

    announce_route(
        &server2,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.2.1".to_string(),
            med: Some(50),
            ..Default::default()
        })),
    )
    .await;

    announce_route(
        &server3,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.3.1".to_string(),
            med: Some(10),
            ..Default::default()
        })),
    )
    .await;

    // S4 should select S2's route (AS65001, MED=50)
    // This proves: MED compared within AS65001 (S2 beat S1)
    //              MED NOT compared across ASes (S2 beat S3 despite higher MED)
    poll_rib(&[(
        &server4,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![as_sequence(vec![65001])],
                med: Some(50),
                ..PathParams::from_peer(&server2)
            },
        )],
    )])
    .await;
}

#[tokio::test]
async fn test_normal_community_propagation() {
    let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

    let communities = vec![
        community::from_asn_value(65001, 100),
        community::from_asn_value(65001, 200),
        community::from_asn_value(65001, 300),
    ];

    announce_route(
        &server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            communities: communities.clone(),
            ..Default::default()
        })),
    )
    .await;

    poll_rib(&[(
        &server2,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                communities,
                ..PathParams::from_peer(&server1)
            },
        )],
    )])
    .await;
}

#[tokio::test]
async fn test_well_known_communities() {
    let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

    // Add routes with well-known communities (should be filtered)
    announce_route(
        &server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            communities: vec![community::NO_ADVERTISE],
            ..Default::default()
        })),
    )
    .await;

    announce_route(
        &server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.2.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            communities: vec![community::NO_EXPORT],
            ..Default::default()
        })),
    )
    .await;

    announce_route(
        &server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.3.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            communities: vec![community::NO_EXPORT_SUBCONFED],
            ..Default::default()
        })),
    )
    .await;

    // Add normal route (should propagate)
    announce_route(
        &server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.4.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Wait for route to propagate, then verify stability
    poll_until_stable(
        || async {
            let Ok(routes) = server2
                .client
                .list_routes(ListRoutesRequest::default())
                .await
            else {
                return false;
            };

            routes_match(
                &routes,
                &[expected_route(
                    "10.4.0.0/24",
                    PathParams::from_peer(&server1),
                )],
                ExpectPathId::Present,
            ) && server1
                .client
                .get_peer(server2.address.to_string())
                .await
                .ok()
                .and_then(|(_, stats)| stats)
                .is_some_and(|s| s.update_sent == 1)
        },
        std::time::Duration::from_secs(3),
        "Only normal route should propagate with 1 UPDATE",
    )
    .await;
}

#[tokio::test]
async fn test_extended_communities_filtering() {
    // RFC 4360: Transitive propagate everywhere, non-transitive filtered on eBGP only
    let transitive = from_two_octet_as(SUBTYPE_ROUTE_TARGET, 65001, 100);
    let non_transitive = from_two_octet_as(SUBTYPE_ROUTE_TARGET, 65001, 200)
        | ((TYPE_NON_TRANSITIVE_BIT as u64) << 56);

    let announced_next_hop = "192.168.1.1".to_string();

    let tests = vec![
        (
            "ebgp",
            65001,
            65002,
            vec![as_sequence(vec![65001])],
            vec![ExtendedCommunity {
                community: Some(Community::TwoOctetAs(TwoOctetAsSpecific {
                    is_transitive: true,
                    sub_type: SUBTYPE_ROUTE_TARGET as u32,
                    asn: 65001,
                    local_admin: 100,
                })),
            }],
        ),
        (
            "ibgp",
            65001,
            65001,
            vec![],
            vec![
                ExtendedCommunity {
                    community: Some(Community::TwoOctetAs(TwoOctetAsSpecific {
                        is_transitive: true,
                        sub_type: SUBTYPE_ROUTE_TARGET as u32,
                        asn: 65001,
                        local_admin: 100,
                    })),
                },
                ExtendedCommunity {
                    community: Some(Community::TwoOctetAs(TwoOctetAsSpecific {
                        is_transitive: false,
                        sub_type: SUBTYPE_ROUTE_TARGET as u32,
                        asn: 65001,
                        local_admin: 200,
                    })),
                },
            ],
        ),
    ];

    for (name, asn1, asn2, expected_as_path, expected_communities) in tests {
        let [server1, server2] = &mut create_asn_chain([asn1, asn2], None).await;

        let expected_next_hop = if asn1 == asn2 {
            announced_next_hop.clone()
        } else {
            server1.address.to_string()
        };

        announce_route(
            server1,
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: announced_next_hop.clone(),
                extended_communities: vec![transitive, non_transitive],
                ..Default::default()
            })),
        )
        .await;

        poll_rib(&[(
            server2,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    as_path: expected_as_path,
                    next_hop: expected_next_hop,
                    peer_address: server1.address.to_string(),
                    local_pref: Some(100),
                    extended_communities: expected_communities,
                    ..Default::default()
                },
            )],
        )])
        .await;

        println!("{} test passed", name);
    }
}

#[tokio::test]
async fn test_large_community_propagation() {
    let (server1, server2) = setup_two_peered_servers(PeerConfig::default()).await;

    let large_comms = vec![
        LargeCommunity::new(65536, 100, 200),
        LargeCommunity::new(4200000000, 1, 2),
        LargeCommunity::new(0, 0, 0),
    ];

    announce_route(
        &server1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            large_communities: large_comms.clone(),
            ..Default::default()
        })),
    )
    .await;

    // Build expected large communities in proto format
    let expected_large_comms = vec![
        proto::LargeCommunity {
            global_admin: 65536,
            local_data_1: 100,
            local_data_2: 200,
        },
        proto::LargeCommunity {
            global_admin: 4200000000,
            local_data_1: 1,
            local_data_2: 2,
        },
        proto::LargeCommunity {
            global_admin: 0,
            local_data_1: 0,
            local_data_2: 0,
        },
    ];

    poll_rib(&[(
        &server2,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                large_communities: expected_large_comms,
                ..PathParams::from_peer(&server1)
            },
        )],
    )])
    .await;
}

/// RFC 6793: Test route propagation with large ASNs (4-byte) and boundary conditions
#[tokio::test]
async fn test_asn_route_propagation() {
    let test_cases = [
        ("large_asns", [4200000001, 4200000002]),
        ("boundary", [65535, 65536]),
    ];

    for (name, asns) in test_cases {
        let [s1, s2] = &mut create_asn_chain(asns, None).await;
        verify_peers(s1, vec![s2.to_peer(BgpState::Established)]).await;
        announce_and_verify_route(
            s1,
            &[s2],
            RouteParams::Ip(Box::new(IpRouteParams {
                prefix: "10.0.0.0/24".to_string(),
                next_hop: "192.168.1.1".to_string(),
                ..Default::default()
            })),
            PathParams {
                as_path: vec![as_sequence(vec![asns[0]])],
                next_hop: s1.address.to_string(),
                peer_address: s1.address.to_string(),
                local_pref: Some(100),
                origin: Some(bgpgg::grpc::proto::Origin::Igp),
                ..Default::default()
            },
        )
        .await;

        // Debug info for test failures
        if cfg!(test) {
            println!("✓ {}: route propagated correctly", name);
        }
    }
}

/// RFC 6793: Test routes propagate through mixed AS path with both small and large ASNs
#[tokio::test]
async fn test_mixed_asn_propagation() {
    // Chain: large ASN -> small ASN -> large ASN
    let [s1, s2, s3] = &mut create_asn_chain([4200000001, 65001, 4200000003], None).await;

    // Announce route on s1
    announce_route(
        s1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Verify route reaches s3 with correct AS path and next_hop rewritten to s2
    poll_rib(&[(
        s3,
        vec![expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![as_sequence(vec![65001, 4200000001])],
                ..PathParams::from_peer(s2)
            },
        )],
    )])
    .await;
}

/// RFC 6793: Test 4-byte ASN route propagation to OLD and NEW speakers
///
/// Topology: originator (NEW) -> server -> old_speaker
///                                       -> new_speaker
///
/// Verifies that server correctly propagates routes with large ASNs:
/// - To OLD speakers: AS_TRANS substitution + AS4_PATH/AS4_AGGREGATOR
/// - To NEW speakers: native 4-byte encoding, no AS4_* attributes
#[tokio::test]
async fn test_four_octet_asn_propagation() {
    let mut config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 300);
    // Add passive peers for all FakePeer connections
    for addr in ["127.0.0.1", "127.0.0.2", "127.0.0.3"] {
        add_passive_peer(&mut config, addr);
    }
    let server = start_test_server(config).await;

    // RFC 8212: eBGP peers need explicit accept-all policies
    for addr in ["127.0.0.1", "127.0.0.2", "127.0.0.3"] {
        apply_permit_all(&server, addr).await;
    }

    let mut old_speaker = FakePeer::connect_and_handshake(
        None,
        &server,
        65002,
        Ipv4Addr::new(2, 2, 2, 2),
        None, // No capability 65
    )
    .await;

    let mut originator = FakePeer::connect_and_handshake(
        Some("127.0.0.2"),
        &server,
        4200000002,
        Ipv4Addr::new(3, 3, 3, 3),
        Some(vec![build_capability_4byte_asn(4200000002)]),
    )
    .await;

    let mut new_speaker = FakePeer::connect_and_handshake(
        Some("127.0.0.3"),
        &server,
        4200000003,
        Ipv4Addr::new(4, 4, 4, 4),
        Some(vec![build_capability_4byte_asn(4200000003)]),
    )
    .await;

    // Originator sends UPDATE with large ASNs in AS_PATH and AGGREGATOR
    let aggregator_asn = 4200000010u32;
    let aggregator_ip = Ipv4Addr::new(192, 168, 1, 100);

    originator
        .send_raw(&build_raw_update(
            &[],
            &[
                &attr_origin_igp(),
                &attr_as_path_4byte(vec![4200000002]),
                &attr_next_hop(Ipv4Addr::new(192, 168, 1, 1)),
                &attr_aggregator(aggregator_asn, aggregator_ip),
            ],
            &[24, 10, 0, 0], // 10.0.0.0/24
            None,
        ))
        .await;

    // Verify OLD speaker receives AS_TRANS conversion
    let old_update = old_speaker.read_update().await;

    // AS_PATH: large ASNs substituted with AS_TRANS
    let as_path = old_update.as_path().expect("UPDATE should have AS_PATH");
    assert_eq!(as_path[0].asn_list, vec![65001, AS_TRANS as u32]);

    // AS4_PATH: original large ASNs preserved
    let as4_path = old_update.as4_path().expect("UPDATE should have AS4_PATH");
    assert_eq!(as4_path[0].asn_list, vec![65001, 4200000002]);

    // AGGREGATOR: large ASN substituted with AS_TRANS
    let aggregator = old_update
        .aggregator()
        .expect("UPDATE should have AGGREGATOR");
    assert_eq!(aggregator.asn, AS_TRANS as u32);
    assert_eq!(aggregator.ip_addr, aggregator_ip);

    // AS4_AGGREGATOR: original large ASN preserved
    let as4_aggregator = old_update
        .as4_aggregator()
        .expect("UPDATE should have AS4_AGGREGATOR");
    assert_eq!(as4_aggregator.asn, aggregator_asn);
    assert_eq!(as4_aggregator.ip_addr, aggregator_ip);

    // Verify NEW speaker receives native 4-byte encoding
    let new_update = new_speaker.read_update().await;

    // AS_PATH: native 4-byte encoding (no AS_TRANS)
    let as_path = new_update.as_path().expect("UPDATE should have AS_PATH");
    assert_eq!(as_path[0].asn_list, vec![65001, 4200000002]);
    for segment in &as_path {
        for asn in &segment.asn_list {
            assert_ne!(*asn, AS_TRANS as u32);
        }
    }

    // AS4_PATH: not present (only used for OLD speakers)
    assert!(new_update.as4_path().is_none());

    // AGGREGATOR: unchanged (no AS_TRANS substitution)
    let aggregator = new_update
        .aggregator()
        .expect("UPDATE should have AGGREGATOR");
    assert_eq!(aggregator.asn, aggregator_asn);
    assert_eq!(aggregator.ip_addr, aggregator_ip);

    // AS4_AGGREGATOR: not present (only used for OLD speakers)
    assert!(new_update.as4_aggregator().is_none());
}

/// RFC 6793: Test server ignores malformed AS4_PATH (longer than AS_PATH)
#[tokio::test]
async fn test_four_octet_asn_malformed_as4_path() {
    let mut config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 300);
    for addr in ["127.0.0.1", "127.0.0.2"] {
        add_passive_peer(&mut config, addr);
    }
    let server = start_test_server(config).await;

    // RFC 8212: eBGP peers need explicit accept-all policies
    for addr in ["127.0.0.1", "127.0.0.2"] {
        apply_permit_all(&server, addr).await;
    }

    let mut fake_peer =
        FakePeer::connect_and_handshake(None, &server, 65002, Ipv4Addr::new(2, 2, 2, 2), None)
            .await;

    let mut receiver = FakePeer::connect_and_handshake(
        Some("127.0.0.2"),
        &server,
        65003,
        Ipv4Addr::new(3, 3, 3, 3),
        None,
    )
    .await;

    // AS_PATH: [AS_TRANS, AS_TRANS] (2 ASNs)
    // AS4_PATH: [65002, 4200000001, 4200000002] (3 ASNs - malformed! longer than AS_PATH)
    // Expected: AS4_PATH discarded, AS_TRANS values remain
    let mut as_path_value = Vec::new();
    as_path_value.push(2); // AS_SEQUENCE
    as_path_value.push(2); // 2 ASNs
    as_path_value.extend_from_slice(&AS_TRANS.to_be_bytes());
    as_path_value.extend_from_slice(&AS_TRANS.to_be_bytes());

    let mut as4_path_value = Vec::new();
    as4_path_value.push(2); // AS_SEQUENCE
    as4_path_value.push(3); // 3 ASNs - malformed!
    as4_path_value.extend_from_slice(&65002u32.to_be_bytes());
    as4_path_value.extend_from_slice(&4200000001u32.to_be_bytes());
    as4_path_value.extend_from_slice(&4200000002u32.to_be_bytes());

    fake_peer
        .send_raw(&build_raw_update(
            &[],
            &[
                &attr_origin_igp(),
                &build_attr_bytes(
                    attr_flags::TRANSITIVE,
                    attr_type_code::AS_PATH,
                    as_path_value.len() as u8,
                    &as_path_value,
                ),
                &attr_next_hop(Ipv4Addr::new(192, 168, 1, 1)),
                &build_attr_bytes(
                    attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                    attr_type_code::AS4_PATH,
                    as4_path_value.len() as u8,
                    &as4_path_value,
                ),
            ],
            &[24, 10, 0, 0],
            None,
        ))
        .await;

    // Verify receiver gets UPDATE with AS4_PATH discarded
    let update = receiver.read_update().await;

    // AS_PATH: server AS prepended + AS_TRANS values remain (malformed AS4_PATH was discarded)
    let as_path = update.as_path().expect("UPDATE should have AS_PATH");
    assert_eq!(
        as_path[0].asn_list,
        vec![65001, AS_TRANS as u32, AS_TRANS as u32]
    );

    // AS4_PATH: discarded (was malformed - longer than AS_PATH)
    assert!(update.as4_path().is_none());
}

/// RFC 6793: Test server ignores malformed AS4_AGGREGATOR (invalid length)
#[tokio::test]
async fn test_four_octet_asn_malformed_as4_aggregator() {
    let mut config = BgpConfig::new(65001, "127.0.0.1:0", Ipv4Addr::new(1, 1, 1, 1), 300);
    for addr in ["127.0.0.1", "127.0.0.2"] {
        add_passive_peer(&mut config, addr);
    }
    let server = start_test_server(config).await;

    // RFC 8212: eBGP peers need explicit accept-all policies
    for addr in ["127.0.0.1", "127.0.0.2"] {
        apply_permit_all(&server, addr).await;
    }

    let mut fake_peer =
        FakePeer::connect_and_handshake(None, &server, 65002, Ipv4Addr::new(2, 2, 2, 2), None)
            .await;

    let mut receiver = FakePeer::connect_and_handshake(
        Some("127.0.0.2"),
        &server,
        65003,
        Ipv4Addr::new(3, 3, 3, 3),
        None,
    )
    .await;

    // Send UPDATE with malformed AS4_AGGREGATOR (wrong length - 6 bytes instead of 8)
    let mut as4_agg_data = Vec::new();
    as4_agg_data.extend_from_slice(&4200000001u32.to_be_bytes()[0..2]); // Only 2 bytes
    as4_agg_data.extend_from_slice(&Ipv4Addr::new(192, 168, 1, 100).octets());

    fake_peer
        .send_raw(&build_raw_update(
            &[],
            &[
                &attr_origin_igp(),
                &attr_as_path_2byte(vec![65002]),
                &attr_next_hop(Ipv4Addr::new(192, 168, 1, 1)),
                &build_attr_bytes(
                    attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                    attr_type_code::AS4_AGGREGATOR,
                    as4_agg_data.len() as u8,
                    &as4_agg_data,
                ),
            ],
            &[24, 10, 0, 0],
            None,
        ))
        .await;

    // Verify receiver gets UPDATE with AS4_AGGREGATOR discarded
    let update = receiver.read_update().await;

    // AS_PATH: server AS prepended to original path
    let as_path = update.as_path().expect("UPDATE should have AS_PATH");
    assert_eq!(as_path[0].asn_list, vec![65001, 65002]);

    // AS4_AGGREGATOR: discarded (was malformed - wrong length)
    assert!(update.as4_aggregator().is_none());
}

#[tokio::test]
async fn test_best_path_selection() {
    // Table-driven test covering all tiebreaker steps from Path::cmp().
    // 3-server iBGP mesh (all ASN 65001). s1 and s2 announce the same prefix
    // with different attributes. s3 receives both and selects the best.
    // Each case uses a unique prefix so all cases coexist without interference.
    //
    // s1: router_id=1.1.1.1, s2: router_id=2.2.2.2, s3: router_id=3.3.3.3
    let [server1, server2, server3] = mesh_servers(
        [
            start_test_server(test_config(65001, 1)).await,
            start_test_server(test_config(65001, 2)).await,
            start_test_server(test_config(65001, 3)).await,
        ],
        PeerConfig::default(),
    )
    .await;

    struct Case {
        name: &'static str,
        prefix: &'static str,
        s1_next_hop: &'static str,
        s1_origin: Origin,
        s1_as_path: Vec<AsPathSegment>,
        s1_local_pref: Option<u32>,
        s1_med: Option<u32>,
        s1_communities: Vec<u32>,
        s1_originator_id: Option<&'static str>,
        s1_cluster_list: Vec<&'static str>,
        s2_next_hop: &'static str,
        s2_origin: Origin,
        s2_as_path: Vec<AsPathSegment>,
        s2_local_pref: Option<u32>,
        s2_med: Option<u32>,
        s2_communities: Vec<u32>,
        s2_originator_id: Option<&'static str>,
        s2_cluster_list: Vec<&'static str>,
        /// true = s1 wins, false = s2 wins
        s1_wins: bool,
    }

    let cases = vec![
        // Step 1: Higher LOCAL_PREF wins
        Case {
            name: "local_pref",
            prefix: "10.1.0.0/24",
            s1_next_hop: "192.168.1.1",
            s1_origin: Origin::Igp,
            s1_as_path: vec![],
            s1_local_pref: Some(200),
            s1_med: None,
            s1_communities: vec![],
            s1_originator_id: None,
            s1_cluster_list: vec![],
            s2_next_hop: "192.168.2.1",
            s2_origin: Origin::Igp,
            s2_as_path: vec![],
            s2_local_pref: Some(100),
            s2_med: None,
            s2_communities: vec![],
            s2_originator_id: None,
            s2_cluster_list: vec![],
            s1_wins: true,
        },
        // Step 2: Shorter AS_PATH wins
        Case {
            name: "as_path_length",
            prefix: "10.2.0.0/24",
            s1_next_hop: "192.168.1.2",
            s1_origin: Origin::Igp,
            s1_as_path: vec![as_sequence(vec![65002])],
            s1_local_pref: Some(100),
            s1_med: None,
            s1_communities: vec![],
            s1_originator_id: None,
            s1_cluster_list: vec![],
            s2_next_hop: "192.168.2.2",
            s2_origin: Origin::Igp,
            s2_as_path: vec![as_sequence(vec![65002, 65003])],
            s2_local_pref: Some(100),
            s2_med: None,
            s2_communities: vec![],
            s2_originator_id: None,
            s2_cluster_list: vec![],
            s1_wins: true,
        },
        // Step 3: Lower ORIGIN wins (IGP < INCOMPLETE)
        Case {
            name: "origin",
            prefix: "10.3.0.0/24",
            s1_next_hop: "192.168.1.3",
            s1_origin: Origin::Igp,
            s1_as_path: vec![],
            s1_local_pref: Some(100),
            s1_med: None,
            s1_communities: vec![],
            s1_originator_id: None,
            s1_cluster_list: vec![],
            s2_next_hop: "192.168.2.3",
            s2_origin: Origin::Incomplete,
            s2_as_path: vec![],
            s2_local_pref: Some(100),
            s2_med: None,
            s2_communities: vec![],
            s2_originator_id: None,
            s2_cluster_list: vec![],
            s1_wins: true,
        },
        // Step 4: Lower MED wins (same neighboring AS)
        Case {
            name: "med",
            prefix: "10.4.0.0/24",
            s1_next_hop: "192.168.1.4",
            s1_origin: Origin::Igp,
            s1_as_path: vec![as_sequence(vec![65002])],
            s1_local_pref: Some(100),
            s1_med: Some(50),
            s1_communities: vec![],
            s1_originator_id: None,
            s1_cluster_list: vec![],
            s2_next_hop: "192.168.2.4",
            s2_origin: Origin::Igp,
            s2_as_path: vec![as_sequence(vec![65002])],
            s2_local_pref: Some(100),
            s2_med: Some(100),
            s2_communities: vec![],
            s2_originator_id: None,
            s2_cluster_list: vec![],
            s1_wins: true,
        },
        // Step 6: Shorter CLUSTER_LIST wins
        Case {
            name: "cluster_list",
            prefix: "10.6.0.0/24",
            s1_next_hop: "192.168.1.6",
            s1_origin: Origin::Igp,
            s1_as_path: vec![],
            s1_local_pref: Some(100),
            s1_med: None,
            s1_communities: vec![],
            s1_originator_id: Some("5.5.5.5"),
            s1_cluster_list: vec!["10.10.10.1", "10.10.10.2"],
            s2_next_hop: "192.168.2.6",
            s2_origin: Origin::Igp,
            s2_as_path: vec![],
            s2_local_pref: Some(100),
            s2_med: None,
            s2_communities: vec![],
            s2_originator_id: Some("5.5.5.5"),
            s2_cluster_list: vec!["10.10.10.3"],
            s1_wins: false,
        },
        // Step 7: Lower ORIGINATOR_ID wins (same CLUSTER_LIST length)
        Case {
            name: "originator_id",
            prefix: "10.7.0.0/24",
            s1_next_hop: "192.168.1.7",
            s1_origin: Origin::Igp,
            s1_as_path: vec![],
            s1_local_pref: Some(100),
            s1_med: None,
            s1_communities: vec![],
            s1_originator_id: Some("2.2.2.2"),
            s1_cluster_list: vec!["9.9.9.9"],
            s2_next_hop: "192.168.2.7",
            s2_origin: Origin::Igp,
            s2_as_path: vec![],
            s2_local_pref: Some(100),
            s2_med: None,
            s2_communities: vec![],
            s2_originator_id: Some("1.1.1.1"),
            s2_cluster_list: vec!["9.9.9.9"],
            s1_wins: false,
        },
        // Step 8: Lower BGP ID wins (no ORIGINATOR_ID set)
        Case {
            name: "bgp_id",
            prefix: "10.8.0.0/24",
            s1_next_hop: "192.168.1.8",
            s1_origin: Origin::Igp,
            s1_as_path: vec![],
            s1_local_pref: Some(100),
            s1_med: None,
            s1_communities: vec![],
            s1_originator_id: None,
            s1_cluster_list: vec![],
            s2_next_hop: "192.168.2.8",
            s2_origin: Origin::Igp,
            s2_as_path: vec![],
            s2_local_pref: Some(100),
            s2_med: None,
            s2_communities: vec![],
            s2_originator_id: None,
            s2_cluster_list: vec![],
            s1_wins: true,
        },
        // RFC 9494: LLGR_STALE routes are least preferred
        Case {
            name: "llgr_stale",
            prefix: "10.9.0.0/24",
            s1_next_hop: "192.168.1.9",
            s1_origin: Origin::Igp,
            s1_as_path: vec![],
            s1_local_pref: Some(200),
            s1_med: None,
            s1_communities: vec![community::LLGR_STALE],
            s1_originator_id: None,
            s1_cluster_list: vec![],
            s2_next_hop: "192.168.2.9",
            s2_origin: Origin::Igp,
            s2_as_path: vec![],
            s2_local_pref: Some(100),
            s2_med: None,
            s2_communities: vec![],
            s2_originator_id: None,
            s2_cluster_list: vec![],
            s1_wins: false,
        },
    ];

    // Announce all routes from s1, then all from s2
    for case in &cases {
        server1
            .client
            .add_route(AddRouteRequest {
                route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                    prefix: case.prefix.to_string(),
                    next_hop: case.s1_next_hop.to_string(),
                    origin: case.s1_origin as i32,
                    as_path: case.s1_as_path.clone(),
                    local_pref: case.s1_local_pref,
                    med: case.s1_med,
                    communities: case.s1_communities.clone(),
                    originator_id: case.s1_originator_id.map(str::to_string),
                    cluster_list: case.s1_cluster_list.iter().map(|s| s.to_string()).collect(),
                    ..Default::default()
                }))),
            })
            .await
            .unwrap();
    }
    for case in &cases {
        server2
            .client
            .add_route(AddRouteRequest {
                route: Some(add_route_request::Route::Ip(Box::new(AddIpRouteRequest {
                    prefix: case.prefix.to_string(),
                    next_hop: case.s2_next_hop.to_string(),
                    origin: case.s2_origin as i32,
                    as_path: case.s2_as_path.clone(),
                    local_pref: case.s2_local_pref,
                    med: case.s2_med,
                    communities: case.s2_communities.clone(),
                    originator_id: case.s2_originator_id.map(str::to_string),
                    cluster_list: case.s2_cluster_list.iter().map(|s| s.to_string()).collect(),
                    ..Default::default()
                }))),
            })
            .await
            .unwrap();
    }

    // Verify s3 selected the expected winner for each case
    let s1_addr = server1.address.to_string();
    let s2_addr = server2.address.to_string();
    for case in &cases {
        let expected_peer = if case.s1_wins { &s1_addr } else { &s2_addr };
        poll_until(
            || async {
                let Ok(routes) = server3
                    .client
                    .list_routes(ListRoutesRequest::default())
                    .await
                else {
                    return false;
                };
                let Some(route) = routes.iter().find(|r| route_has_prefix(r, case.prefix)) else {
                    return false;
                };
                let Some(best) = route.paths.first() else {
                    return false;
                };
                best.peer_address == *expected_peer
            },
            &format!(
                "Timeout: {} - expected winner peer {}",
                case.name, expected_peer
            ),
        )
        .await;
    }
}
