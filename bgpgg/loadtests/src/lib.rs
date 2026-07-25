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

pub mod receiver;
pub mod route_generator;
pub mod sender;

#[cfg(test)]
mod load_test;

// Re-export for convenience
pub use route_generator::calculate_expected_best_paths;

use bgpgg::bgp::msg::{AddPathMask, BgpMessage, Message, MessageFormat};
use bgpgg::bgp::msg_keepalive::KeepaliveMessage;
use bgpgg::bgp::msg_open::OpenMessage;
use bgpgg::bgp::msg_update::{NextHopAddr, UpdateMessage};
use bgpgg::bgp::msg_update_types::{AsPathSegment, AsPathSegmentType, Origin};
use bgpgg::net::{IpNetwork, Ipv4Net};
use bgpgg::rib::{Path, PathAttrs, RouteSource};
use bgpgg::rpki::vrp::RpkiValidation;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Perform BGP handshake (OPEN + KEEPALIVE exchange)
pub async fn bgp_handshake(
    stream: &mut TcpStream,
    local_asn: u16,
    local_router_id: Ipv4Addr,
    peer_asn: u16,
    hold_time: u16,
) -> io::Result<()> {
    // Send OPEN with Four-Octet ASN capability (RFC 6793)
    let open = OpenMessage::with_four_octet_asn_capability(
        local_asn.into(),
        hold_time,
        u32::from(local_router_id),
    );
    stream.write_all(&open.serialize()).await?;

    // Read peer's OPEN (use_4byte_asn=true since we advertised the capability)
    let msg = bgpgg::bgp::msg::read_bgp_message(
        &mut *stream,
        MessageFormat {
            use_4byte_asn: true,
            add_path: AddPathMask::NONE,
            is_ebgp: false,
            enhanced_rr: false,
        },
    )
    .await
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to read OPEN: {:?}", e),
        )
    })?;

    match msg {
        BgpMessage::Open(peer_open) => {
            if peer_open.asn != peer_asn as u32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Expected ASN {}, got {}", peer_asn, peer_open.asn),
                ));
            }
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Expected OPEN message",
            ));
        }
    }

    // Send KEEPALIVE
    let keepalive = KeepaliveMessage {};
    stream.write_all(&keepalive.serialize()).await?;

    // Read peer's KEEPALIVE (use_4byte_asn=true for consistency)
    let msg = bgpgg::bgp::msg::read_bgp_message(
        &mut *stream,
        MessageFormat {
            use_4byte_asn: true,
            add_path: AddPathMask::NONE,
            is_ebgp: false,
            enhanced_rr: false,
        },
    )
    .await
    .map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to read KEEPALIVE: {:?}", e),
        )
    })?;

    match msg {
        BgpMessage::Keepalive(_) => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected KEEPALIVE message",
        )),
    }
}

/// Generate sequential test routes starting from a base prefix
pub fn generate_test_routes(
    base_address: Ipv4Addr,
    count: usize,
    prefix_len: u8,
) -> Vec<IpNetwork> {
    let mut routes = Vec::with_capacity(count);
    let base = u32::from(base_address);

    // Calculate increment based on prefix length
    // For /24, increment by 256 (2^(32-24))
    let increment = 1u32 << (32 - prefix_len);

    for i in 0..count {
        let addr = base.wrapping_add((i as u32).wrapping_mul(increment));
        routes.push(IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::from(addr),
            prefix_length: prefix_len,
        }));
    }

    routes
}

/// Create an UPDATE message with the given routes
pub fn create_update_message(
    routes: Vec<IpNetwork>,
    next_hop: Ipv4Addr,
    as_path: Vec<u16>,
    origin: Origin,
    med: Option<u32>,
    local_pref: Option<u32>,
    communities: Vec<u32>,
) -> Vec<u8> {
    let as_path_segments = if as_path.is_empty() {
        vec![]
    } else {
        vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: as_path.len() as u8,
            asn_list: as_path.iter().map(|&asn| asn as u32).collect(),
        }]
    };

    let path = Path {
        local_path_id: None,
        remote_path_id: None,
        stale: false,
        rpki_state: RpkiValidation::NotFound,
        attrs: Arc::new(PathAttrs {
            origin,
            as_path: as_path_segments,
            next_hop: NextHopAddr::Ipv4(next_hop),
            source: RouteSource::Local,
            local_pref,
            med,
            atomic_aggregate: false,
            aggregator: None,
            communities,
            extended_communities: vec![],
            large_communities: vec![],
            unknown_attrs: vec![],
            originator_id: None,
            cluster_list: vec![],
            ls_attr: None,
        }),
    };

    let update = UpdateMessage::new(
        &path,
        routes,
        MessageFormat {
            use_4byte_asn: true,
            add_path: AddPathMask::NONE,
            is_ebgp: false,
            enhanced_rr: false,
        },
    );
    update.serialize()
}

/// Transform a path to match what would be exported to an eBGP peer
/// (prepend local ASN, rewrite next_hop, remove local_pref and MED)
pub fn transform_path_for_ebgp_export(
    path: &Path,
    local_asn: u16,
    local_router_id: Ipv4Addr,
) -> Path {
    let mut exported = path.clone();
    let attrs = exported.attrs_mut();

    // Prepend local ASN to AS_PATH
    if !attrs.as_path.is_empty() {
        let first_segment = &attrs.as_path[0];
        if first_segment.segment_type == AsPathSegmentType::AsSequence {
            // Prepend to existing AS_SEQUENCE
            let mut new_asn_list = vec![local_asn as u32];
            new_asn_list.extend_from_slice(&first_segment.asn_list);
            attrs.as_path[0] = AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: new_asn_list.len() as u8,
                asn_list: new_asn_list,
            };
        } else {
            // Create new AS_SEQUENCE with local ASN
            let mut new_segments = vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![local_asn as u32],
            }];
            new_segments.extend_from_slice(&attrs.as_path);
            attrs.as_path = new_segments;
        }
    } else {
        // Empty AS_PATH, create new segment
        attrs.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 1,
            asn_list: vec![local_asn as u32],
        }];
    }

    // Rewrite next_hop to local router ID
    attrs.next_hop = NextHopAddr::Ipv4(local_router_id);

    // Remove local_pref (not used in eBGP)
    attrs.local_pref = None;

    // Remove MED (typically not propagated across AS boundaries)
    attrs.med = None;

    exported
}

/// Convert proto::Path (from gRPC) to rib::Path for comparison
pub fn proto_path_to_rib_path(proto_path: &bgpgg::grpc::proto::Path) -> Result<Path, String> {
    // Convert origin
    let origin = match proto_path.origin {
        0 => Origin::IGP,
        1 => Origin::EGP,
        2 => Origin::INCOMPLETE,
        _ => return Err(format!("Invalid origin: {}", proto_path.origin)),
    };

    // Convert AS_PATH
    let as_path: Vec<AsPathSegment> = proto_path
        .as_path
        .iter()
        .map(|seg| {
            let segment_type = match seg.segment_type() {
                bgpgg::grpc::proto::AsPathSegmentType::AsSet => AsPathSegmentType::AsSet,
                bgpgg::grpc::proto::AsPathSegmentType::AsSequence => AsPathSegmentType::AsSequence,
            };
            AsPathSegment {
                segment_type,
                segment_len: seg.asns.len() as u8,
                asn_list: seg.asns.clone(),
            }
        })
        .collect();

    // Parse next hop
    let next_hop: Ipv4Addr = proto_path
        .next_hop
        .parse()
        .map_err(|_| format!("Invalid next_hop: {}", proto_path.next_hop))?;

    // Parse peer address for source
    let peer_ip: IpAddr = proto_path
        .peer_address
        .parse()
        .map_err(|_| format!("Invalid peer_address: {}", proto_path.peer_address))?;
    // For load tests, derive bgp_id from peer_ip
    let bgp_id = match peer_ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    };
    let source = RouteSource::Ebgp { peer_ip, bgp_id };

    // Convert communities
    let communities: Vec<u32> = proto_path.communities.clone();

    Ok(Path {
        local_path_id: None,
        remote_path_id: None,
        stale: false,
        rpki_state: RpkiValidation::NotFound,
        attrs: Arc::new(PathAttrs {
            origin,
            as_path,
            next_hop: NextHopAddr::Ipv4(next_hop),
            source,
            local_pref: proto_path.local_pref,
            med: proto_path.med,
            atomic_aggregate: proto_path.atomic_aggregate,
            aggregator: None,
            communities,
            extended_communities: vec![],
            large_communities: vec![],
            unknown_attrs: vec![],
            originator_id: None,
            cluster_list: vec![],
            ls_attr: None,
        }),
    })
}
