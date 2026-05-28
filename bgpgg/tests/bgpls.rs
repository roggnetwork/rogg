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

//! BGP-LS integration tests (RFC 9552)

mod utils;
pub use utils::*;

use bgpgg::grpc::proto::{
    remove_route_request, AfiSafiConfig, BgpState, ListRoutesRequest, LsAttribute, LsLinkAttribute,
    LsLinkDescriptor, LsNlri, LsNlriType, LsNodeAttribute, LsNodeDescriptor, LsPrefixAttribute,
    LsPrefixDescriptor, LsProtocolId, RemoveRouteRequest, Route, SessionConfig,
};

fn ls_peer_config() -> PeerConfig {
    PeerConfig {
        afi_safis: vec![AfiSafiConfig {
            afi: 16388,
            safi: 71,
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn ls_session_config() -> SessionConfig {
    SessionConfig {
        afi_safis: vec![AfiSafiConfig {
            afi: 16388,
            safi: 71,
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn make_ls_node_nlri(as_number: u32, router_id: &[u8]) -> LsNlri {
    LsNlri {
        nlri_type: LsNlriType::LsNode as i32,
        protocol_id: LsProtocolId::LsDirect as i32,
        local_node: Some(LsNodeDescriptor {
            as_number: Some(as_number),
            igp_router_id: router_id.to_vec(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn make_ls_link_nlri(
    local_as: u32,
    local_rid: &[u8],
    remote_as: u32,
    remote_rid: &[u8],
    interface_addr: &str,
    neighbor_addr: &str,
) -> LsNlri {
    LsNlri {
        nlri_type: LsNlriType::LsLink as i32,
        protocol_id: LsProtocolId::LsDirect as i32,
        local_node: Some(LsNodeDescriptor {
            as_number: Some(local_as),
            igp_router_id: local_rid.to_vec(),
            ..Default::default()
        }),
        remote_node: Some(LsNodeDescriptor {
            as_number: Some(remote_as),
            igp_router_id: remote_rid.to_vec(),
            ..Default::default()
        }),
        link_descriptors: Some(LsLinkDescriptor {
            ipv4_interface_addr: Some(interface_addr.to_string()),
            ipv4_neighbor_addr: Some(neighbor_addr.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn make_ls_prefix_v4_nlri(as_number: u32, router_id: &[u8], prefix_bytes: &[u8]) -> LsNlri {
    LsNlri {
        nlri_type: LsNlriType::LsPrefixV4 as i32,
        protocol_id: LsProtocolId::LsDirect as i32,
        local_node: Some(LsNodeDescriptor {
            as_number: Some(as_number),
            igp_router_id: router_id.to_vec(),
            ..Default::default()
        }),
        prefix_descriptors: Some(LsPrefixDescriptor {
            ip_reachability: prefix_bytes.to_vec(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn make_ls_node_attr(name: &str) -> LsAttribute {
    LsAttribute {
        node: Some(LsNodeAttribute {
            name: Some(name.to_string()),
            ipv4_router_id: Some("10.0.0.1".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn make_ls_link_attr(igp_metric: u32) -> LsAttribute {
    LsAttribute {
        link: Some(LsLinkAttribute {
            igp_metric: Some(igp_metric),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn make_ls_prefix_attr(metric: u32) -> LsAttribute {
    LsAttribute {
        prefix: Some(LsPrefixAttribute {
            metric: Some(metric),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn get_ls_routes(server: &TestServer) -> Vec<Route> {
    server
        .client
        .list_routes(ListRoutesRequest {
            afi: Some(16388),
            safi: Some(71),
            ..Default::default()
        })
        .await
        .unwrap()
}

/// Build PathParams for an LS route received from `source` peer with given ls_attribute.
fn ls_path_params(source: &TestServer, ls_attribute: LsAttribute) -> PathParams {
    PathParams {
        ls_attribute: Some(ls_attribute),
        ..PathParams::from_peer(source)
    }
}

/// LS routes propagate only to peers with LS capability negotiated.
/// Hub peers with spoke_a (LS enabled) and spoke_b (no LS).
/// LS route injected on hub should reach spoke_a but not spoke_b.
#[tokio::test]
async fn test_ls_capability_negotiation_and_filtering() {
    let hub = start_test_server(test_config(65001, 1)).await;
    let spoke_a = start_test_server(test_config(65002, 2)).await;
    let spoke_b = start_test_server(test_config(65003, 3)).await;

    // Hub -> spoke_a: LS enabled
    hub.add_peer_with_config(&spoke_a, ls_session_config())
        .await;
    spoke_a
        .add_peer_with_config(&hub, ls_session_config())
        .await;

    // Hub -> spoke_b: default (no LS)
    hub.add_peer(&spoke_b).await;
    spoke_b.add_peer(&hub).await;

    // RFC 8212: eBGP peers need explicit accept-all policies
    apply_permit_all_routes(&hub, &spoke_a).await;
    apply_permit_all_routes(&hub, &spoke_b).await;

    poll_peers(&spoke_a, vec![hub.to_peer(BgpState::Established)]).await;
    poll_peers(&spoke_b, vec![hub.to_peer(BgpState::Established)]).await;

    let nlri = make_ls_node_nlri(65001, &[10, 0, 0, 1]);
    announce_route(
        &hub,
        RouteParams::Ls(Box::new(LsRouteParams {
            nlri: Some(nlri.clone()),
            attribute: Some(make_ls_node_attr("hub-router")),
            next_hop: Some(hub.address.to_string()),
        })),
    )
    .await;

    // spoke_a should receive the LS route with correct attributes
    poll_route_exists(
        &spoke_a,
        expected_route(nlri, ls_path_params(&hub, make_ls_node_attr("hub-router"))),
    )
    .await;

    // spoke_b should NOT receive LS routes (no LS capability)
    poll_while(
        || async { get_ls_routes(&spoke_b).await.is_empty() },
        Duration::from_secs(2),
        "spoke_b should not receive LS routes",
    )
    .await;
}

/// Inject LS route, verify propagated, withdraw, verify removed.
#[tokio::test]
async fn test_ls_route_withdrawal() {
    let (server1, server2) = setup_two_peered_servers(ls_peer_config()).await;

    let nlri = make_ls_node_nlri(65002, &[10, 0, 0, 2]);

    announce_route(
        &server2,
        RouteParams::Ls(Box::new(LsRouteParams {
            nlri: Some(nlri.clone()),
            attribute: Some(make_ls_node_attr("router2")),
            next_hop: Some(server2.address.to_string()),
        })),
    )
    .await;

    poll_route_exists(
        &server1,
        expected_route(
            nlri.clone(),
            ls_path_params(&server2, make_ls_node_attr("router2")),
        ),
    )
    .await;

    server2
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::LsNlri(Box::new(nlri))),
        })
        .await
        .unwrap();

    poll_until(
        || async { get_ls_routes(&server1).await.is_empty() },
        "Timeout waiting for LS route withdrawal",
    )
    .await;
}

/// Inject Node, Link, and PrefixV4 NLRIs. All three should propagate.
#[tokio::test]
async fn test_ls_multiple_nlri_types() {
    let (server1, server2) = setup_two_peered_servers(ls_peer_config()).await;
    let next_hop = Some(server2.address.to_string());

    let node_nlri = make_ls_node_nlri(65002, &[10, 0, 0, 2]);
    let link_nlri = make_ls_link_nlri(
        65002,
        &[10, 0, 0, 2],
        65001,
        &[10, 0, 0, 1],
        "192.168.1.2",
        "192.168.1.1",
    );
    // ip_reachability: prefix length (24) + 3 bytes for 10.10.10.0/24
    let prefix_nlri = make_ls_prefix_v4_nlri(65002, &[10, 0, 0, 2], &[24, 10, 10, 10]);

    announce_route(
        &server2,
        RouteParams::Ls(Box::new(LsRouteParams {
            nlri: Some(node_nlri.clone()),
            attribute: Some(make_ls_node_attr("router2")),
            next_hop: next_hop.clone(),
        })),
    )
    .await;

    announce_route(
        &server2,
        RouteParams::Ls(Box::new(LsRouteParams {
            nlri: Some(link_nlri.clone()),
            attribute: Some(make_ls_link_attr(10)),
            next_hop: next_hop.clone(),
        })),
    )
    .await;

    announce_route(
        &server2,
        RouteParams::Ls(Box::new(LsRouteParams {
            nlri: Some(prefix_nlri.clone()),
            attribute: Some(make_ls_prefix_attr(100)),
            next_hop,
        })),
    )
    .await;

    poll_rib(&[(
        &server1,
        vec![
            expected_route(
                node_nlri.clone(),
                ls_path_params(&server2, make_ls_node_attr("router2")),
            ),
            expected_route(link_nlri, ls_path_params(&server2, make_ls_link_attr(10))),
            expected_route(
                prefix_nlri,
                ls_path_params(&server2, make_ls_prefix_attr(100)),
            ),
        ],
    )])
    .await;

    // Withdraw one NLRI, verify the other two remain
    server2
        .client
        .remove_route(RemoveRouteRequest {
            key: Some(remove_route_request::Key::LsNlri(Box::new(node_nlri))),
        })
        .await
        .unwrap();

    poll_until(
        || async { get_ls_routes(&server1).await.len() == 2 },
        "Timeout waiting for partial LS withdrawal",
    )
    .await;
}

/// Same NLRI with updated attribute should replace, not duplicate.
#[tokio::test]
async fn test_ls_route_replace() {
    let (server1, server2) = setup_two_peered_servers(ls_peer_config()).await;

    let nlri = make_ls_node_nlri(65002, &[10, 0, 0, 2]);
    let next_hop = Some(server2.address.to_string());

    announce_route(
        &server2,
        RouteParams::Ls(Box::new(LsRouteParams {
            nlri: Some(nlri.clone()),
            attribute: Some(make_ls_node_attr("router2")),
            next_hop: next_hop.clone(),
        })),
    )
    .await;

    poll_route_exists(
        &server1,
        expected_route(
            nlri.clone(),
            ls_path_params(&server2, make_ls_node_attr("router2")),
        ),
    )
    .await;

    // Re-inject same NLRI with different attribute
    announce_route(
        &server2,
        RouteParams::Ls(Box::new(LsRouteParams {
            nlri: Some(nlri.clone()),
            attribute: Some(make_ls_node_attr("router2-updated")),
            next_hop,
        })),
    )
    .await;

    poll_route_exists(
        &server1,
        expected_route(
            nlri,
            ls_path_params(&server2, make_ls_node_attr("router2-updated")),
        ),
    )
    .await;

    // Verify only 1 route (replaced, not duplicated)
    let routes = get_ls_routes(&server1).await;
    assert_eq!(
        routes.len(),
        1,
        "expected 1 LS route after replace, got {}",
        routes.len()
    );
}

/// When peer is removed, its LS routes should be withdrawn.
#[tokio::test]
async fn test_ls_session_down_cleanup() {
    let (server1, server2) = setup_two_peered_servers(ls_peer_config()).await;

    let nlri = make_ls_node_nlri(65002, &[10, 0, 0, 2]);
    announce_route(
        &server2,
        RouteParams::Ls(Box::new(LsRouteParams {
            nlri: Some(nlri.clone()),
            attribute: Some(make_ls_node_attr("router2")),
            next_hop: Some(server2.address.to_string()),
        })),
    )
    .await;

    poll_route_exists(
        &server1,
        expected_route(nlri, ls_path_params(&server2, make_ls_node_attr("router2"))),
    )
    .await;

    // Remove peer to trigger route cleanup (avoids GR timer delay from kill)
    server1.remove_peer(&server2).await;

    poll_until(
        || async { get_ls_routes(&server1).await.is_empty() },
        "Timeout waiting for LS route cleanup after peer removal",
    )
    .await;
}

/// RFC 9552 Section 8.2.2: LS NLRIs without BGP-LS Attribute (type 29) SHOULD
/// be preserved and propagated so consumers detect loss of link-state info
/// rather than assuming deletion.
#[tokio::test]
async fn test_ls_nlri_without_attribute_propagates() {
    let (server1, server2) = setup_two_peered_servers(ls_peer_config()).await;

    let nlri = make_ls_node_nlri(65002, &[10, 0, 0, 2]);

    // Inject LS route WITHOUT BGP-LS Attribute (type 29)
    announce_route(
        &server2,
        RouteParams::Ls(Box::new(LsRouteParams {
            nlri: Some(nlri.clone()),
            attribute: None,
            next_hop: Some(server2.address.to_string()),
        })),
    )
    .await;

    // Route should propagate with no ls_attribute
    poll_route_exists(
        &server1,
        expected_route(
            nlri,
            PathParams {
                ls_attribute: None,
                ..PathParams::from_peer(&server2)
            },
        ),
    )
    .await;
}
