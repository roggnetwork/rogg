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

//! Route Reflector tests (RFC 4456)

mod utils;
pub use utils::*;

use bgpgg::bgp::msg_update::{attr_flags, attr_type_code};
use bgpgg::grpc::proto::{
    remove_route_request, BgpState, ListRoutesRequest, LsAttribute, LsNlri, LsNlriType,
    LsNodeAttribute, LsNodeDescriptor, LsProtocolId, Origin, RemoveRouteRequest, SessionConfig,
};
use std::net::Ipv4Addr;

/// RFC 4456 Section 8: ORIGINATOR_ID loop detection.
/// A route arriving with ORIGINATOR_ID equal to the RR's own router-id must be rejected.
///
/// Topology: Client(rid=1.1.1.1) -- RR(rid=2.2.2.2) -- Client2(rid=3.3.3.3)
/// Client announces a route with originator_id=2.2.2.2 (RR's router-id).
/// RR detects the loop and rejects the route. Client2 never sees it.
#[tokio::test]
async fn test_rr_originator_id_loop_detection() {
    let asn = 65001;
    let client = start_test_server(test_config(asn, 1)).await;
    let rr = start_test_server(test_config(asn, 2)).await;
    let client2 = start_test_server(test_config(asn, 3)).await;

    setup_rr(
        vec![&rr],
        vec![vec![&client, &client2]],
        vec![],
        SessionConfig::default(),
    )
    .await;

    // Announce a route with originator_id matching the RR's router-id (loop!)
    announce_route(
        &client,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            originator_id: Some("2.2.2.2".to_string()),
            ..Default::default()
        })),
    )
    .await;

    // Also announce a clean route to prove the path works
    announce_route(
        &client,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Wait for the clean route to propagate (proves RR processed updates from Client)
    poll_route_exists(
        &client2,
        expected_route(
            "10.1.0.0/24",
            PathParams {
                next_hop: "192.168.1.1".to_string(),
                peer_address: rr.address.to_string(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                originator_id: Some("1.1.1.1".to_string()),
                cluster_list: vec!["2.2.2.2".to_string()],
                ..Default::default()
            },
        ),
    )
    .await;

    // The poisoned route (originator_id=RR's rid) should never appear on Client2
    poll_while(
        || async {
            let Ok(routes) = client2
                .client
                .list_routes(ListRoutesRequest::default())
                .await
            else {
                return false;
            };
            routes.len() == 1 && route_has_prefix(&routes[0], "10.1.0.0/24")
        },
        Duration::from_secs(2),
        "Poisoned route with RR's own ORIGINATOR_ID should not appear on Client2",
    )
    .await;
}

/// eBGP route sent to iBGP clients and non-clients without RR attributes.
/// When an eBGP peer sends a route to the RR, the RR forwards it to all
/// iBGP peers. Since the route came from eBGP (not iBGP), ORIGINATOR_ID
/// and CLUSTER_LIST should NOT be added.
///
/// Topology: eBGP(65002) -- RR(65001) -- Client(65001)
///                                    \-- NC(65001)
#[tokio::test]
async fn test_rr_ebgp_route_reflected_to_clients() {
    let client = start_test_server(test_config(65001, 1)).await;
    let rr = start_test_server(test_config(65001, 2)).await;
    let ebgp_peer = start_test_server(test_config(65002, 3)).await;
    let nc = start_test_server(test_config(65001, 4)).await;

    setup_rr(
        vec![&rr],
        vec![vec![&client]],
        vec![&ebgp_peer, &nc],
        SessionConfig::default(),
    )
    .await;

    announce_route(
        &ebgp_peer,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.3.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Both client and non-client should receive route WITHOUT RR attributes
    // (route came from eBGP, not iBGP - no reflection attributes needed)
    let route = expected_route(
        "10.0.0.0/24",
        PathParams {
            as_path: vec![as_sequence(vec![65002])],
            next_hop: ebgp_peer.address.to_string(),
            peer_address: rr.address.to_string(),
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            originator_id: None,
            cluster_list: vec![],
            ..Default::default()
        },
    );

    poll_rib(&[(&client, vec![route.clone()]), (&nc, vec![route])]).await;
}

/// RR locally originated routes are sent to clients without RR attributes.
/// When the RR itself originates a route via add_route (RouteSource::Local),
/// ORIGINATOR_ID and CLUSTER_LIST should NOT be added since the route
/// is not being reflected from an iBGP peer.
///
/// Topology: Client1(65001) -- RR(65001) -- Client2(65001)
/// RR announces a route via add_route.
#[tokio::test]
async fn test_rr_locally_originated_route() {
    let asn = 65001;
    let client1 = start_test_server(test_config(asn, 1)).await;
    let rr = start_test_server(test_config(asn, 2)).await;
    let client2 = start_test_server(test_config(asn, 3)).await;

    setup_rr(
        vec![&rr],
        vec![vec![&client1, &client2]],
        vec![],
        SessionConfig::default(),
    )
    .await;

    // RR itself originates a route
    announce_route(
        &rr,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.2.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Both clients should receive route WITHOUT ORIGINATOR_ID/CLUSTER_LIST
    // (route is locally originated by the RR, not reflected from an iBGP peer)
    let route = expected_route(
        "10.0.0.0/24",
        PathParams {
            next_hop: "192.168.2.1".to_string(),
            peer_address: rr.address.to_string(),
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            originator_id: None,
            cluster_list: vec![],
            ..Default::default()
        },
    );

    poll_rib(&[(&client1, vec![route.clone()]), (&client2, vec![route])]).await;
}

/// Test that Route Reflector reflects routes between iBGP clients.
/// Topology: Client1 -- RR -- Client2 (all ASN 65001), LS enabled.
/// Without RR, Client2 would not receive routes from Client1 (iBGP split horizon).
/// With RR, Client2 receives routes reflected by the RR with ORIGINATOR_ID + CLUSTER_LIST.
/// Also verifies BGP-LS route reflection with correct RR attributes.
#[tokio::test]
async fn test_route_reflector_basic() {
    let asn = 65001;
    let client1 = start_test_server(test_config(asn, 1)).await;
    let rr = start_test_server(test_config(asn, 2)).await;
    let client2 = start_test_server(test_config(asn, 3)).await;

    let ls_config = SessionConfig {
        afi_safis: vec![afi_safi_ipv4_unicast(), afi_safi_link_state()],
        ..Default::default()
    };
    setup_rr(vec![&rr], vec![vec![&client1, &client2]], vec![], ls_config).await;

    announce_route(
        &client1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // RFC 4456: RR sets ORIGINATOR_ID to originator's router-id and prepends
    // its cluster_id to CLUSTER_LIST when reflecting to clients
    poll_route_exists(
        &client2,
        expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![],
                next_hop: "192.168.1.1".to_string(),
                peer_address: rr.address.to_string(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                originator_id: Some("1.1.1.1".to_string()),
                cluster_list: vec!["2.2.2.2".to_string()],
                ..Default::default()
            },
        ),
    )
    .await;

    // BGP-LS reflection: inject LS route on client1, verify client2 gets it with RR attributes
    let ls_nlri = LsNlri {
        nlri_type: LsNlriType::LsNode as i32,
        protocol_id: LsProtocolId::LsDirect as i32,
        local_node: Some(LsNodeDescriptor {
            as_number: Some(65001),
            igp_router_id: vec![10, 0, 0, 1],
            ..Default::default()
        }),
        ..Default::default()
    };
    announce_route(
        &client1,
        RouteParams::Ls(Box::new(LsRouteParams {
            nlri: Some(ls_nlri.clone()),
            attribute: Some(LsAttribute {
                node: Some(LsNodeAttribute {
                    name: Some("client1-node".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            next_hop: None,
        })),
    )
    .await;

    poll_route_exists(
        &client2,
        expected_route(
            ls_nlri,
            PathParams {
                peer_address: rr.address.to_string(),
                next_hop: "0.0.0.0".to_string(),
                local_pref: Some(100),
                ls_attribute: Some(LsAttribute {
                    node: Some(LsNodeAttribute {
                        name: Some("client1-node".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                originator_id: Some("1.1.1.1".to_string()),
                cluster_list: vec!["2.2.2.2".to_string()],
                ..Default::default()
            },
        ),
    )
    .await;
}

/// Test RFC 4456 mixed topology: client routes reflected to everyone,
/// non-client routes reflected to clients only.
///
/// Topology (all ASN 65001 / iBGP):
///   Client (127.0.0.1, rid=1.1.1.1) -- rr_client=true on RR
///          |
///          RR (127.0.0.2, rid=2.2.2.2)
///         / \
///   NC1 (127.0.0.3, rid=3.3.3.3) -- rr_client=false
///   NC2 (127.0.0.4, rid=4.4.4.4) -- rr_client=false
#[tokio::test]
async fn test_route_reflector_mixed_topology() {
    let asn = 65001;
    let c1 = start_test_server(test_config(asn, 1)).await;
    let rr = start_test_server(test_config(asn, 2)).await;
    let nc1 = start_test_server(test_config(asn, 3)).await;
    let nc2 = start_test_server(test_config(asn, 4)).await;

    setup_rr(
        vec![&rr],
        vec![vec![&c1]],
        vec![&nc1, &nc2],
        SessionConfig::default(),
    )
    .await;

    // Phase 1: Client announces route -> reflected to everyone (clients + non-clients)
    announce_route(
        &c1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.1.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    let client_route = vec![expected_route(
        "10.1.0.0/24",
        PathParams {
            as_path: vec![],
            next_hop: "192.168.1.1".to_string(),
            peer_address: rr.address.to_string(),
            origin: Some(Origin::Igp),
            local_pref: Some(100),
            originator_id: Some("1.1.1.1".to_string()),
            cluster_list: vec!["2.2.2.2".to_string()],
            ..Default::default()
        },
    )];

    poll_rib(&[(&nc1, client_route.clone()), (&nc2, client_route.clone())]).await;

    // Phase 2: Non-client announces route -> reflected to clients only
    announce_route(
        &nc1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.2.0.0/24".to_string(),
            next_hop: "192.168.3.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Client should receive nc1's route via RR
    poll_route_exists(
        &c1,
        expected_route(
            "10.2.0.0/24",
            PathParams {
                as_path: vec![],
                next_hop: "192.168.3.1".to_string(),
                peer_address: rr.address.to_string(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                originator_id: Some("3.3.3.3".to_string()),
                cluster_list: vec!["2.2.2.2".to_string()],
                ..Default::default()
            },
        ),
    )
    .await;

    // NC2 should NOT receive nc1's route (non-client -> non-client is not reflected)
    // We already confirmed Client got it (so RR processed the route), now verify NC2 stability
    poll_while(
        || async {
            let Ok(routes) = nc2.client.list_routes(ListRoutesRequest::default()).await else {
                return false;
            };
            // NC2 should only have the client route, not NC1's route
            routes.len() == 1 && route_has_prefix(&routes[0], "10.1.0.0/24")
        },
        Duration::from_secs(2),
        "NC2 should not receive non-client route from NC1",
    )
    .await;
}

/// RFC 4456 Section 8: Two RRs in the same cluster (same cluster_id) must not
/// reflect routes to each other. RR1 prepends cluster_id to CLUSTER_LIST; RR2
/// sees its own cluster_id and rejects the route.
///
/// Topology: Client1 -- RR1(cluster=9.9.9.9) -- RR2(cluster=9.9.9.9) -- Client2
#[tokio::test]
async fn test_rr_cluster_loop_detection() {
    let asn = 65001;
    let client1 = start_test_server(test_config(asn, 1)).await;

    let mut rr1_config = test_config(asn, 2);
    rr1_config.cluster_id = Some(Ipv4Addr::new(9, 9, 9, 9));
    let rr1 = start_test_server(rr1_config).await;

    let mut rr2_config = test_config(asn, 3);
    rr2_config.cluster_id = Some(Ipv4Addr::new(9, 9, 9, 9));
    let rr2 = start_test_server(rr2_config).await;

    let client2 = start_test_server(test_config(asn, 4)).await;

    setup_rr(
        vec![&rr1, &rr2],
        vec![vec![&client1], vec![&client2]],
        vec![],
        SessionConfig::default(),
    )
    .await;

    // Client1 announces route -> RR1 reflects to RR2 with CLUSTER_LIST=[9.9.9.9]
    // RR2 sees 9.9.9.9 (its own cluster_id) -> rejects
    announce_route(
        &client1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // Route should exist on RR1 (accepted from its client)
    poll_route_exists(
        &rr1,
        expected_route(
            "10.0.0.0/24",
            PathParams {
                next_hop: "192.168.1.1".to_string(),
                peer_address: client1.address.to_string(),
                local_pref: Some(100),
                ..Default::default()
            },
        ),
    )
    .await;

    // RR2 rejected the route (cluster loop), so neither RR2 nor Client2 should have it
    poll_while(
        || async {
            let Ok(rr2_routes) = rr2.client.list_routes(ListRoutesRequest::default()).await else {
                return false;
            };
            let Ok(client2_routes) = client2
                .client
                .list_routes(ListRoutesRequest::default())
                .await
            else {
                return false;
            };
            rr2_routes.is_empty() && client2_routes.is_empty()
        },
        Duration::from_secs(2),
        "Route should not appear on RR2 or Client2 (same-cluster loop prevention)",
    )
    .await;
}

/// RFC 4456: ORIGINATOR_ID and CLUSTER_LIST are non-transitive and must be
/// stripped when advertising to eBGP peers.
///
/// Topology: Client(65001) -- RR(65001) -- eBGP(65002)
#[tokio::test]
async fn test_rr_ebgp_attribute_stripping() {
    let client = start_test_server(test_config(65001, 1)).await;
    let rr = start_test_server(test_config(65001, 2)).await;
    let ebgp_peer = start_test_server(test_config(65002, 3)).await;

    setup_rr(
        vec![&rr],
        vec![vec![&client]],
        vec![&ebgp_peer],
        SessionConfig::default(),
    )
    .await;

    announce_route(
        &client,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // eBGP peer should receive route WITHOUT ORIGINATOR_ID/CLUSTER_LIST
    poll_route_exists(
        &ebgp_peer,
        expected_route(
            "10.0.0.0/24",
            PathParams {
                originator_id: None,
                cluster_list: vec![],
                ..PathParams::from_peer(&rr)
            },
        ),
    )
    .await;
}

/// RFC 4456: When cluster_id is explicitly configured, RR uses it instead of
/// router_id in CLUSTER_LIST.
///
/// Topology: Client1 -- RR(cluster_id=9.9.9.9, rid=2.2.2.2) -- Client2
#[tokio::test]
async fn test_rr_custom_cluster_id() {
    let asn = 65001;
    let client1 = start_test_server(test_config(asn, 1)).await;

    let mut rr_config = test_config(asn, 2);
    rr_config.cluster_id = Some(Ipv4Addr::new(9, 9, 9, 9));
    let rr = start_test_server(rr_config).await;

    let client2 = start_test_server(test_config(asn, 3)).await;

    setup_rr(
        vec![&rr],
        vec![vec![&client1, &client2]],
        vec![],
        SessionConfig::default(),
    )
    .await;

    announce_route(
        &client1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // CLUSTER_LIST should contain 9.9.9.9 (custom cluster_id), not 2.2.2.2 (router_id)
    poll_route_exists(
        &client2,
        expected_route(
            "10.0.0.0/24",
            PathParams {
                next_hop: "192.168.1.1".to_string(),
                peer_address: rr.address.to_string(),
                local_pref: Some(100),
                originator_id: Some("1.1.1.1".to_string()),
                cluster_list: vec!["9.9.9.9".to_string()],
                ..Default::default()
            },
        ),
    )
    .await;
}

/// RFC 4456: Route traversing two RRs accumulates both cluster_ids in
/// CLUSTER_LIST. ORIGINATOR_ID is preserved from the first RR.
///
/// Topology: Client1 -- RR1 -- RR2 -- Client2
#[tokio::test]
async fn test_rr_multi_hop_cluster_list() {
    let asn = 65001;
    let client1 = start_test_server(test_config(asn, 1)).await;
    let rr1 = start_test_server(test_config(asn, 2)).await;
    let rr2 = start_test_server(test_config(asn, 3)).await;
    let client2 = start_test_server(test_config(asn, 4)).await;

    setup_rr(
        vec![&rr1, &rr2],
        vec![vec![&client1], vec![&client2]],
        vec![],
        SessionConfig::default(),
    )
    .await;

    announce_route(
        &client1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    // ORIGINATOR_ID=1.1.1.1 (preserved from first RR)
    // CLUSTER_LIST=[3.3.3.3, 2.2.2.2] (each RR prepended its own)
    poll_route_exists(
        &client2,
        expected_route(
            "10.0.0.0/24",
            PathParams {
                next_hop: "192.168.1.1".to_string(),
                peer_address: rr2.address.to_string(),
                local_pref: Some(100),
                originator_id: Some("1.1.1.1".to_string()),
                cluster_list: vec!["3.3.3.3".to_string(), "2.2.2.2".to_string()],
                ..Default::default()
            },
        ),
    )
    .await;
}

/// RFC 4456: Route withdrawals must be reflected the same way as announcements.
///
/// Topology: Client1 -- RR -- Client2
#[tokio::test]
async fn test_rr_withdrawal_reflection() {
    let asn = 65001;
    let client1 = start_test_server(test_config(asn, 1)).await;
    let rr = start_test_server(test_config(asn, 2)).await;
    let client2 = start_test_server(test_config(asn, 3)).await;

    setup_rr(
        vec![&rr],
        vec![vec![&client1, &client2]],
        vec![],
        SessionConfig::default(),
    )
    .await;

    announce_route(
        &client1,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.1.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    poll_route_exists(
        &client2,
        expected_route(
            "10.0.0.0/24",
            PathParams {
                next_hop: "192.168.1.1".to_string(),
                peer_address: rr.address.to_string(),
                local_pref: Some(100),
                originator_id: Some("1.1.1.1".to_string()),
                cluster_list: vec!["2.2.2.2".to_string()],
                ..Default::default()
            },
        ),
    )
    .await;

    // Withdraw and verify reflected withdrawal
    client1
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::Prefix("10.0.0.0/24".to_string())),
        })
        .await
        .unwrap();
    poll_route_withdrawal(&[&client2]).await;
}

/// ORIGINATOR_ID and CLUSTER_LIST are non-transitive: they must be stripped
/// on eBGP receive. If a buggy eBGP peer sends them, the RR should not leak
/// them into the iBGP mesh. Uses FakePeer to inject raw UPDATE bytes
/// bypassing our outgoing logic.
///
/// Topology: FakePeer(65002) -raw UPDATE-> RR(65001) -- Client(65001)
#[tokio::test]
async fn test_rr_strips_nontransitive_attrs_from_ebgp() {
    let client = start_test_server(test_config(65001, 1)).await;
    let rr = start_test_server(test_config(65001, 2)).await;

    setup_rr(
        vec![&rr],
        vec![vec![&client]],
        vec![],
        SessionConfig::default(),
    )
    .await;

    // Create FakePeer as eBGP peer; RR connects out to it
    let mut fake = FakePeer::new("127.0.0.3:0", 65002).await;
    let fake_port = fake.port();
    rr.client
        .add_peer(
            "127.0.0.3".to_string(),
            Some(SessionConfig {
                port: Some(fake_port as u32),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

    // RFC 8212: eBGP peers need explicit accept-all policies
    apply_permit_all(&rr, "127.0.0.3").await;

    fake.accept().await;
    fake.accept_handshake_open(65002, Ipv4Addr::new(3, 3, 3, 3), 300)
        .await;
    fake.handshake_keepalive().await;

    // Send raw UPDATE with bogus ORIGINATOR_ID and CLUSTER_LIST
    let update = build_raw_update(
        &[],
        &[
            &attr_origin_igp(),
            &attr_as_path_2byte(vec![65002]),
            &attr_next_hop(Ipv4Addr::new(127, 0, 0, 3)),
            // Bogus non-transitive attrs that should be stripped on eBGP receive
            &build_attr_bytes(
                attr_flags::OPTIONAL,
                attr_type_code::ORIGINATOR_ID,
                4,
                &[99, 99, 99, 99],
            ),
            &build_attr_bytes(
                attr_flags::OPTIONAL,
                attr_type_code::CLUSTER_LIST,
                4,
                &[88, 88, 88, 88],
            ),
        ],
        &[24, 10, 0, 0], // 10.0.0.0/24
        None,
    );
    fake.send_raw(&update).await;

    // Client should receive route WITHOUT the bogus RR attributes
    poll_route_exists(
        &client,
        expected_route(
            "10.0.0.0/24",
            PathParams {
                as_path: vec![as_sequence(vec![65002])],
                next_hop: "127.0.0.3".to_string(),
                peer_address: rr.address.to_string(),
                origin: Some(Origin::Igp),
                local_pref: Some(100),
                originator_id: None,
                cluster_list: vec![],
                ..Default::default()
            },
        ),
    )
    .await;
}

/// RR with next_hop_self rewrites NEXT_HOP to the RR's address for clients that
/// have it configured, while clients without it still receive the original eBGP
/// NEXT_HOP. Both behaviors verified in the same topology.
///
/// Topology: client_nhs(65001) \
///                               RR(65001) -- ebgp_peer(65002)
///           client(65001)     /
///
/// client_nhs: rr_client + next_hop_self -> sees RR's address
/// client:     rr_client only             -> sees eBGP peer's address
#[tokio::test]
async fn test_rr_next_hop_self() {
    let client_nhs = start_test_server(test_config(65001, 1)).await;
    let rr = start_test_server(test_config(65001, 2)).await;
    let ebgp_peer = start_test_server(test_config(65002, 3)).await;
    let client = start_test_server(test_config(65001, 4)).await;

    // client_nhs: rr_client + next_hop_self
    rr.add_peer_with_config(
        &client_nhs,
        SessionConfig {
            rr_client: Some(true),
            next_hop_self: Some(true),
            ..Default::default()
        },
    )
    .await;
    client_nhs.add_peer(&rr).await;

    // client: rr_client only (no next_hop_self)
    rr.add_peer_with_config(
        &client,
        SessionConfig {
            rr_client: Some(true),
            ..Default::default()
        },
    )
    .await;
    client.add_peer(&rr).await;

    // eBGP peer
    rr.add_peer(&ebgp_peer).await;
    ebgp_peer.add_peer(&rr).await;

    // RFC 8212: eBGP peers need explicit accept-all policies
    apply_permit_all_routes(&rr, &ebgp_peer).await;

    poll_until(
        || async {
            verify_peers(
                &rr,
                vec![
                    client_nhs.to_peer(BgpState::Established),
                    client.to_peer(BgpState::Established),
                    ebgp_peer.to_peer(BgpState::Established),
                ],
            )
            .await
        },
        "Timeout waiting for RR topology to establish",
    )
    .await;

    announce_route(
        &ebgp_peer,
        RouteParams::Ip(Box::new(IpRouteParams {
            prefix: "10.0.0.0/24".to_string(),
            next_hop: "192.168.3.1".to_string(),
            ..Default::default()
        })),
    )
    .await;

    let path_base = PathParams {
        as_path: vec![as_sequence(vec![65002])],
        peer_address: rr.address.to_string(),
        origin: Some(Origin::Igp),
        local_pref: Some(100),
        originator_id: None,
        cluster_list: vec![],
        ..Default::default()
    };

    poll_rib(&[
        (
            &client_nhs,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    next_hop: rr.address.to_string(), // rewritten to RR's address
                    ..path_base.clone()
                },
            )],
        ),
        (
            &client,
            vec![expected_route(
                "10.0.0.0/24",
                PathParams {
                    next_hop: ebgp_peer.address.to_string(), // original eBGP NH preserved
                    ..path_base.clone()
                },
            )],
        ),
    ])
    .await;
}
