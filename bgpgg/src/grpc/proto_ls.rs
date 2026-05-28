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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::proto;
use crate::bgp::bgpls::LsTlv;
use crate::bgp::bgpls_attr::{
    build_ls_attr, LinkAttrTlv, LsAttr, LsAttrTlv, NodeAttrTlv, PrefixAttrTlv,
};
use crate::bgp::bgpls_nlri::{
    build_ls_nlri, LinkDescriptor, LsDescriptors, LsNlri, LsNlriType, LsProtocolId, NodeDescriptor,
    PrefixDescriptor,
};

// Proto enum values are 0-based, wire values are 1-based.
// Proto LS_NODE=0 -> wire Node=1, etc.

fn proto_nlri_type(val: i32) -> Result<LsNlriType, String> {
    match val {
        0 => Ok(LsNlriType::Node),
        1 => Ok(LsNlriType::Link),
        2 => Ok(LsNlriType::PrefixV4),
        3 => Ok(LsNlriType::PrefixV6),
        _ => Err(format!("invalid LS NLRI type: {val}")),
    }
}

fn nlri_type_to_proto(wire: u16) -> i32 {
    match wire {
        1 => proto::LsNlriType::LsNode as i32,
        2 => proto::LsNlriType::LsLink as i32,
        3 => proto::LsNlriType::LsPrefixV4 as i32,
        4 => proto::LsNlriType::LsPrefixV6 as i32,
        _ => -1,
    }
}

fn proto_protocol_id(val: i32) -> Result<LsProtocolId, String> {
    match val {
        0 => Ok(LsProtocolId::IsIsL1),
        1 => Ok(LsProtocolId::IsIsL2),
        2 => Ok(LsProtocolId::OspfV2),
        3 => Ok(LsProtocolId::Direct),
        4 => Ok(LsProtocolId::Static),
        5 => Ok(LsProtocolId::OspfV3),
        _ => Err(format!("invalid LS protocol ID: {val}")),
    }
}

fn protocol_id_to_proto(wire: u8) -> i32 {
    match wire {
        1 => proto::LsProtocolId::LsIsisL1 as i32,
        2 => proto::LsProtocolId::LsIsisL2 as i32,
        3 => proto::LsProtocolId::LsOspfv2 as i32,
        4 => proto::LsProtocolId::LsDirect as i32,
        5 => proto::LsProtocolId::LsStatic as i32,
        6 => proto::LsProtocolId::LsOspfv3 as i32,
        _ => 0,
    }
}

fn proto_to_node_descriptor(proto: &proto::LsNodeDescriptor) -> NodeDescriptor {
    NodeDescriptor {
        as_number: proto.as_number,
        bgp_ls_id: proto.bgp_ls_id,
        ospf_area_id: proto.ospf_area_id,
        igp_router_id: if proto.igp_router_id.is_empty() {
            None
        } else {
            Some(proto.igp_router_id.clone())
        },
        unknown: vec![],
    }
}

fn node_descriptor_to_proto(nd: &NodeDescriptor) -> proto::LsNodeDescriptor {
    proto::LsNodeDescriptor {
        as_number: nd.as_number,
        bgp_ls_id: nd.bgp_ls_id,
        ospf_area_id: nd.ospf_area_id,
        igp_router_id: nd.igp_router_id.clone().unwrap_or_default(),
    }
}

fn proto_to_link_descriptor(proto: &proto::LsLinkDescriptor) -> LinkDescriptor {
    LinkDescriptor {
        link_local_id: proto.link_local_id,
        link_remote_id: proto.link_remote_id,
        ipv4_interface_addr: proto
            .ipv4_interface_addr
            .as_ref()
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
            .map(|a| a.octets()),
        ipv4_neighbor_addr: proto
            .ipv4_neighbor_addr
            .as_ref()
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
            .map(|a| a.octets()),
        ipv6_interface_addr: proto
            .ipv6_interface_addr
            .as_ref()
            .and_then(|s| s.parse::<Ipv6Addr>().ok())
            .map(|a| a.octets()),
        ipv6_neighbor_addr: proto
            .ipv6_neighbor_addr
            .as_ref()
            .and_then(|s| s.parse::<Ipv6Addr>().ok())
            .map(|a| a.octets()),
        multi_topology_id: if proto.multi_topology_id.is_empty() {
            None
        } else {
            Some(proto.multi_topology_id.iter().map(|&v| v as u16).collect())
        },
        unknown: proto
            .unknown
            .iter()
            .map(|t| LsTlv {
                tlv_type: t.r#type as u16,
                value: t.value.clone(),
            })
            .collect(),
    }
}

fn link_descriptor_to_proto(ld: &LinkDescriptor) -> proto::LsLinkDescriptor {
    proto::LsLinkDescriptor {
        link_local_id: ld.link_local_id,
        link_remote_id: ld.link_remote_id,
        ipv4_interface_addr: ld
            .ipv4_interface_addr
            .map(|a| Ipv4Addr::from(a).to_string()),
        ipv4_neighbor_addr: ld.ipv4_neighbor_addr.map(|a| Ipv4Addr::from(a).to_string()),
        ipv6_interface_addr: ld
            .ipv6_interface_addr
            .map(|a| Ipv6Addr::from(a).to_string()),
        ipv6_neighbor_addr: ld.ipv6_neighbor_addr.map(|a| Ipv6Addr::from(a).to_string()),
        multi_topology_id: ld
            .multi_topology_id
            .as_ref()
            .map(|ids| ids.iter().map(|&id| id as u32).collect())
            .unwrap_or_default(),
        unknown: ld
            .unknown
            .iter()
            .map(|t| proto::LsTlv {
                r#type: t.tlv_type as u32,
                value: t.value.clone(),
            })
            .collect(),
    }
}

fn proto_to_prefix_descriptor(proto: &proto::LsPrefixDescriptor) -> PrefixDescriptor {
    PrefixDescriptor {
        multi_topology_id: if proto.multi_topology_id.is_empty() {
            None
        } else {
            Some(proto.multi_topology_id.iter().map(|&v| v as u16).collect())
        },
        ospf_route_type: proto.ospf_route_type.map(|v| v as u8),
        ip_reachability: if proto.ip_reachability.is_empty() {
            None
        } else {
            Some(proto.ip_reachability.clone())
        },
        unknown: proto
            .unknown
            .iter()
            .map(|t| LsTlv {
                tlv_type: t.r#type as u16,
                value: t.value.clone(),
            })
            .collect(),
    }
}

fn prefix_descriptor_to_proto(pd: &PrefixDescriptor) -> proto::LsPrefixDescriptor {
    proto::LsPrefixDescriptor {
        multi_topology_id: pd
            .multi_topology_id
            .as_ref()
            .map(|ids| ids.iter().map(|&id| id as u32).collect())
            .unwrap_or_default(),
        ospf_route_type: pd.ospf_route_type.map(|v| v as u32),
        ip_reachability: pd.ip_reachability.clone().unwrap_or_default(),
        unknown: pd
            .unknown
            .iter()
            .map(|t| proto::LsTlv {
                r#type: t.tlv_type as u32,
                value: t.value.clone(),
            })
            .collect(),
    }
}

/// Convert a proto LsNlri to an internal LsNlri with encoded raw bytes.
pub fn proto_to_ls_nlri(proto_nlri: &proto::LsNlri) -> Result<LsNlri, String> {
    let nlri_type = proto_nlri_type(proto_nlri.nlri_type)?;
    let protocol_id = proto_protocol_id(proto_nlri.protocol_id)?;
    let identifier = proto_nlri.identifier;

    let local_node = proto_nlri
        .local_node
        .as_ref()
        .map(proto_to_node_descriptor)
        .unwrap_or_default();

    let descriptors = match nlri_type {
        LsNlriType::Node => LsDescriptors::Node { local_node },
        LsNlriType::Link => {
            let remote_node = proto_nlri
                .remote_node
                .as_ref()
                .map(proto_to_node_descriptor)
                .unwrap_or_default();
            let link_descriptors = proto_nlri
                .link_descriptors
                .as_ref()
                .map(proto_to_link_descriptor)
                .unwrap_or_default();
            LsDescriptors::Link {
                local_node,
                remote_node,
                link_descriptors,
            }
        }
        LsNlriType::PrefixV4 => {
            let prefix_descriptors = proto_nlri
                .prefix_descriptors
                .as_ref()
                .map(proto_to_prefix_descriptor)
                .unwrap_or_default();
            LsDescriptors::PrefixV4 {
                local_node,
                prefix_descriptors,
            }
        }
        LsNlriType::PrefixV6 => {
            let prefix_descriptors = proto_nlri
                .prefix_descriptors
                .as_ref()
                .map(proto_to_prefix_descriptor)
                .unwrap_or_default();
            LsDescriptors::PrefixV6 {
                local_node,
                prefix_descriptors,
            }
        }
    };

    Ok(build_ls_nlri(
        nlri_type,
        protocol_id,
        identifier,
        descriptors,
        None,
    ))
}

/// Convert an internal LsNlri to proto. Returns None for unknown/opaque NLRIs.
pub fn ls_nlri_to_proto(nlri: &LsNlri) -> proto::LsNlri {
    let body = nlri.body.as_ref();

    let nlri_type = nlri_type_to_proto(nlri.nlri_type);
    let protocol_id = body
        .map(|b| protocol_id_to_proto(b.protocol_id))
        .unwrap_or(0);
    let identifier = body.map(|b| b.identifier).unwrap_or(0);

    let (local_node, remote_node, link_descriptors, prefix_descriptors) =
        match body.map(|b| &b.descriptors) {
            Some(LsDescriptors::Node { local_node }) => {
                (Some(node_descriptor_to_proto(local_node)), None, None, None)
            }
            Some(LsDescriptors::Link {
                local_node,
                remote_node,
                link_descriptors,
            }) => (
                Some(node_descriptor_to_proto(local_node)),
                Some(node_descriptor_to_proto(remote_node)),
                Some(link_descriptor_to_proto(link_descriptors)),
                None,
            ),
            Some(LsDescriptors::PrefixV4 {
                local_node,
                prefix_descriptors,
            })
            | Some(LsDescriptors::PrefixV6 {
                local_node,
                prefix_descriptors,
            }) => (
                Some(node_descriptor_to_proto(local_node)),
                None,
                None,
                Some(prefix_descriptor_to_proto(prefix_descriptors)),
            ),
            None => (None, None, None, None),
        };

    proto::LsNlri {
        nlri_type,
        protocol_id,
        identifier,
        local_node,
        remote_node,
        link_descriptors,
        prefix_descriptors,
    }
}

/// Convert a proto LsAttribute to an internal LsAttr.
/// Uses typed fields when present, falls back to raw TLVs.
pub fn proto_to_ls_attr(proto_attr: &proto::LsAttribute) -> LsAttr {
    let mut tlvs = Vec::new();

    // Convert typed node attributes
    if let Some(node) = &proto_attr.node {
        if let Some(flags) = node.flag_bits {
            tlvs.push(LsAttrTlv::Node(NodeAttrTlv::FlagBits(flags as u8)));
        }
        if let Some(opaque) = &node.opaque {
            tlvs.push(LsAttrTlv::Node(NodeAttrTlv::Opaque(opaque.clone())));
        }
        if let Some(name) = &node.name {
            tlvs.push(LsAttrTlv::Node(NodeAttrTlv::Name(name.clone())));
        }
        if !node.isis_area_id.is_empty() {
            tlvs.push(LsAttrTlv::Node(NodeAttrTlv::IsisAreaId(
                node.isis_area_id.clone(),
            )));
        }
        if let Some(ipv4) = &node.ipv4_router_id {
            if let Ok(addr) = ipv4.parse::<Ipv4Addr>() {
                tlvs.push(LsAttrTlv::Node(NodeAttrTlv::Ipv4RouterId(addr)));
            }
        }
        if let Some(ipv6) = &node.ipv6_router_id {
            if let Ok(addr) = ipv6.parse::<Ipv6Addr>() {
                tlvs.push(LsAttrTlv::Node(NodeAttrTlv::Ipv6RouterId(addr)));
            }
        }
    }

    // Convert typed link attributes
    if let Some(link) = &proto_attr.link {
        if let Some(s) = &link.ipv4_router_id_local {
            if let Ok(addr) = s.parse::<Ipv4Addr>() {
                tlvs.push(LsAttrTlv::Link(LinkAttrTlv::Ipv4RouterIdLocal(addr)));
            }
        }
        if let Some(s) = &link.ipv6_router_id_local {
            if let Ok(addr) = s.parse::<Ipv6Addr>() {
                tlvs.push(LsAttrTlv::Link(LinkAttrTlv::Ipv6RouterIdLocal(addr)));
            }
        }
        if let Some(s) = &link.ipv4_router_id_remote {
            if let Ok(addr) = s.parse::<Ipv4Addr>() {
                tlvs.push(LsAttrTlv::Link(LinkAttrTlv::Ipv4RouterIdRemote(addr)));
            }
        }
        if let Some(s) = &link.ipv6_router_id_remote {
            if let Ok(addr) = s.parse::<Ipv6Addr>() {
                tlvs.push(LsAttrTlv::Link(LinkAttrTlv::Ipv6RouterIdRemote(addr)));
            }
        }
        if let Some(ag) = link.admin_group {
            tlvs.push(LsAttrTlv::Link(LinkAttrTlv::AdminGroup(ag)));
        }
        if let Some(bw) = link.max_link_bandwidth {
            tlvs.push(LsAttrTlv::Link(LinkAttrTlv::MaxLinkBw(bw.to_bits())));
        }
        if let Some(bw) = link.max_reservable_bandwidth {
            tlvs.push(LsAttrTlv::Link(LinkAttrTlv::MaxRsvblLinkBw(bw.to_bits())));
        }
        if link.unreserved_bandwidth.len() == 8 {
            let mut arr = [0u32; 8];
            for (i, &bw) in link.unreserved_bandwidth.iter().enumerate() {
                arr[i] = bw.to_bits();
            }
            tlvs.push(LsAttrTlv::Link(LinkAttrTlv::UnreservedBw(arr)));
        }
        if let Some(metric) = link.te_default_metric {
            tlvs.push(LsAttrTlv::Link(LinkAttrTlv::TeDefaultMetric(metric)));
        }
        if let Some(prot) = link.link_protection {
            tlvs.push(LsAttrTlv::Link(LinkAttrTlv::LinkProtection(prot as u16)));
        }
        if let Some(mask) = link.mpls_protocol_mask {
            tlvs.push(LsAttrTlv::Link(LinkAttrTlv::MplsProtocolMask(mask as u8)));
        }
        if let Some(metric) = link.igp_metric {
            tlvs.push(LsAttrTlv::Link(LinkAttrTlv::IgpMetric(metric)));
        }
        if !link.srlg.is_empty() {
            tlvs.push(LsAttrTlv::Link(LinkAttrTlv::Srlg(link.srlg.clone())));
        }
        if let Some(opaque) = &link.opaque {
            tlvs.push(LsAttrTlv::Link(LinkAttrTlv::Opaque(opaque.clone())));
        }
        if let Some(name) = &link.name {
            tlvs.push(LsAttrTlv::Link(LinkAttrTlv::Name(name.clone())));
        }
    }

    // Convert typed prefix attributes
    if let Some(prefix) = &proto_attr.prefix {
        if let Some(flags) = prefix.igp_flags {
            tlvs.push(LsAttrTlv::Prefix(PrefixAttrTlv::IgpFlags(flags as u8)));
        }
        if !prefix.igp_route_tag.is_empty() {
            tlvs.push(LsAttrTlv::Prefix(PrefixAttrTlv::IgpRouteTag(
                prefix.igp_route_tag.clone(),
            )));
        }
        if !prefix.igp_extended_route_tag.is_empty() {
            tlvs.push(LsAttrTlv::Prefix(PrefixAttrTlv::IgpExtendedRouteTag(
                prefix.igp_extended_route_tag.clone(),
            )));
        }
        if let Some(metric) = prefix.metric {
            tlvs.push(LsAttrTlv::Prefix(PrefixAttrTlv::Metric(metric)));
        }
        if let Some(addr_str) = &prefix.ospf_forwarding_addr {
            if let Ok(addr) = addr_str.parse::<IpAddr>() {
                tlvs.push(LsAttrTlv::Prefix(PrefixAttrTlv::OspfFwdAddr(addr)));
            }
        }
        if let Some(opaque) = &prefix.opaque {
            tlvs.push(LsAttrTlv::Prefix(PrefixAttrTlv::Opaque(opaque.clone())));
        }
    }

    // Append raw unknown TLVs from the tlvs field that aren't covered by typed fields
    for raw_tlv in &proto_attr.tlvs {
        tlvs.push(LsAttrTlv::Unknown(LsTlv {
            tlv_type: raw_tlv.r#type as u16,
            value: raw_tlv.value.clone(),
        }));
    }

    build_ls_attr(tlvs)
}

/// Convert an internal LsAttr to proto LsAttribute with typed fields populated.
pub fn ls_attr_to_proto(attr: &LsAttr) -> proto::LsAttribute {
    let mut node = proto::LsNodeAttribute::default();
    let mut link = proto::LsLinkAttribute::default();
    let mut prefix = proto::LsPrefixAttribute::default();
    let mut raw_tlvs = Vec::new();

    let mut has_node = false;
    let mut has_link = false;
    let mut has_prefix = false;

    for tlv in &attr.tlvs {
        match tlv {
            LsAttrTlv::Node(n) => {
                has_node = true;
                match n {
                    NodeAttrTlv::FlagBits(v) => node.flag_bits = Some(*v as u32),
                    NodeAttrTlv::Opaque(v) => node.opaque = Some(v.clone()),
                    NodeAttrTlv::Name(v) => node.name = Some(v.clone()),
                    NodeAttrTlv::IsisAreaId(v) => node.isis_area_id = v.clone(),
                    NodeAttrTlv::Ipv4RouterId(v) => node.ipv4_router_id = Some(v.to_string()),
                    NodeAttrTlv::Ipv6RouterId(v) => node.ipv6_router_id = Some(v.to_string()),
                }
            }
            LsAttrTlv::Link(l) => {
                has_link = true;
                match l {
                    LinkAttrTlv::Ipv4RouterIdLocal(v) => {
                        link.ipv4_router_id_local = Some(v.to_string())
                    }
                    LinkAttrTlv::Ipv6RouterIdLocal(v) => {
                        link.ipv6_router_id_local = Some(v.to_string())
                    }
                    LinkAttrTlv::Ipv4RouterIdRemote(v) => {
                        link.ipv4_router_id_remote = Some(v.to_string())
                    }
                    LinkAttrTlv::Ipv6RouterIdRemote(v) => {
                        link.ipv6_router_id_remote = Some(v.to_string())
                    }
                    LinkAttrTlv::AdminGroup(v) => link.admin_group = Some(*v),
                    LinkAttrTlv::MaxLinkBw(v) => link.max_link_bandwidth = Some(f32::from_bits(*v)),
                    LinkAttrTlv::MaxRsvblLinkBw(v) => {
                        link.max_reservable_bandwidth = Some(f32::from_bits(*v))
                    }
                    LinkAttrTlv::UnreservedBw(arr) => {
                        link.unreserved_bandwidth =
                            arr.iter().map(|v| f32::from_bits(*v)).collect();
                    }
                    LinkAttrTlv::TeDefaultMetric(v) => link.te_default_metric = Some(*v),
                    LinkAttrTlv::LinkProtection(v) => link.link_protection = Some(*v as u32),
                    LinkAttrTlv::MplsProtocolMask(v) => link.mpls_protocol_mask = Some(*v as u32),
                    LinkAttrTlv::IgpMetric(v) => link.igp_metric = Some(*v),
                    LinkAttrTlv::Srlg(v) => link.srlg = v.clone(),
                    LinkAttrTlv::Opaque(v) => link.opaque = Some(v.clone()),
                    LinkAttrTlv::Name(v) => link.name = Some(v.clone()),
                }
            }
            LsAttrTlv::Prefix(p) => {
                has_prefix = true;
                match p {
                    PrefixAttrTlv::IgpFlags(v) => prefix.igp_flags = Some(*v as u32),
                    PrefixAttrTlv::IgpRouteTag(v) => prefix.igp_route_tag = v.clone(),
                    PrefixAttrTlv::IgpExtendedRouteTag(v) => {
                        prefix.igp_extended_route_tag = v.clone()
                    }
                    PrefixAttrTlv::Metric(v) => prefix.metric = Some(*v),
                    PrefixAttrTlv::OspfFwdAddr(v) => {
                        prefix.ospf_forwarding_addr = Some(v.to_string())
                    }
                    PrefixAttrTlv::Opaque(v) => prefix.opaque = Some(v.clone()),
                }
            }
            LsAttrTlv::Unknown(t) => {
                raw_tlvs.push(proto::LsTlv {
                    r#type: t.tlv_type as u32,
                    value: t.value.clone(),
                });
            }
        }
    }

    proto::LsAttribute {
        tlvs: raw_tlvs,
        node: if has_node { Some(node) } else { None },
        link: if has_link { Some(link) } else { None },
        prefix: if has_prefix { Some(prefix) } else { None },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proto_to_ls_nlri_node_roundtrip() {
        let proto_nlri = proto::LsNlri {
            nlri_type: proto::LsNlriType::LsNode as i32,
            protocol_id: proto::LsProtocolId::LsDirect as i32,
            identifier: 42,
            local_node: Some(proto::LsNodeDescriptor {
                as_number: Some(65001),
                bgp_ls_id: None,
                ospf_area_id: None,
                igp_router_id: vec![10, 0, 0, 1],
            }),
            remote_node: None,
            link_descriptors: None,
            prefix_descriptors: None,
        };

        let internal = proto_to_ls_nlri(&proto_nlri).expect("should parse");
        assert_eq!(internal.nlri_type, LsNlriType::Node as u16);
        let body = internal.body.as_ref().expect("should have body");
        assert_eq!(body.protocol_id, LsProtocolId::Direct as u8);
        assert_eq!(body.identifier, 42);
        if let LsDescriptors::Node { local_node } = &body.descriptors {
            assert_eq!(local_node.as_number, Some(65001));
            assert_eq!(
                local_node.igp_router_id.as_deref(),
                Some(&[10, 0, 0, 1][..])
            );
        } else {
            panic!("expected Node descriptors");
        }

        // Round-trip back to proto
        let back = ls_nlri_to_proto(&internal);
        assert_eq!(back.nlri_type, proto_nlri.nlri_type);
        assert_eq!(back.protocol_id, proto_nlri.protocol_id);
        assert_eq!(back.identifier, proto_nlri.identifier);
        let ln = back.local_node.as_ref().expect("should have local_node");
        assert_eq!(ln.as_number, Some(65001));
        assert_eq!(ln.igp_router_id, vec![10, 0, 0, 1]);
    }

    #[test]
    fn test_proto_to_ls_nlri_link_roundtrip() {
        let proto_nlri = proto::LsNlri {
            nlri_type: proto::LsNlriType::LsLink as i32,
            protocol_id: proto::LsProtocolId::LsOspfv2 as i32,
            identifier: 100,
            local_node: Some(proto::LsNodeDescriptor {
                as_number: Some(65001),
                bgp_ls_id: None,
                ospf_area_id: Some(0),
                igp_router_id: vec![1, 1, 1, 1],
            }),
            remote_node: Some(proto::LsNodeDescriptor {
                as_number: Some(65001),
                bgp_ls_id: None,
                ospf_area_id: Some(0),
                igp_router_id: vec![2, 2, 2, 2],
            }),
            link_descriptors: Some(proto::LsLinkDescriptor {
                link_local_id: Some(1),
                link_remote_id: Some(2),
                ipv4_interface_addr: Some("10.0.0.1".to_string()),
                ipv4_neighbor_addr: Some("10.0.0.2".to_string()),
                ipv6_interface_addr: None,
                ipv6_neighbor_addr: None,
                multi_topology_id: vec![],
                unknown: vec![],
            }),
            prefix_descriptors: None,
        };

        let internal = proto_to_ls_nlri(&proto_nlri).expect("should parse");
        assert_eq!(internal.nlri_type, LsNlriType::Link as u16);
        let body = internal.body.as_ref().expect("should have body");
        if let LsDescriptors::Link {
            local_node,
            remote_node,
            link_descriptors,
        } = &body.descriptors
        {
            assert_eq!(local_node.as_number, Some(65001));
            assert_eq!(
                remote_node.igp_router_id.as_deref(),
                Some(&[2, 2, 2, 2][..])
            );
            assert_eq!(link_descriptors.link_local_id, Some(1));
            assert_eq!(link_descriptors.ipv4_interface_addr, Some([10, 0, 0, 1]));
        } else {
            panic!("expected Link descriptors");
        }

        let back = ls_nlri_to_proto(&internal);
        assert_eq!(back.nlri_type, proto_nlri.nlri_type);
        let ld = back
            .link_descriptors
            .as_ref()
            .expect("should have link desc");
        assert_eq!(ld.ipv4_interface_addr, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_proto_to_ls_attr_roundtrip() {
        let proto_attr = proto::LsAttribute {
            tlvs: vec![],
            node: Some(proto::LsNodeAttribute {
                flag_bits: Some(0x01),
                opaque: None,
                name: Some("router1".to_string()),
                isis_area_id: vec![],
                ipv4_router_id: Some("10.0.0.1".to_string()),
                ipv6_router_id: None,
            }),
            link: None,
            prefix: None,
        };

        let internal = proto_to_ls_attr(&proto_attr);
        assert_eq!(internal.tlvs.len(), 3); // FlagBits + Name + Ipv4RouterId

        let back = ls_attr_to_proto(&internal);
        let node = back.node.as_ref().expect("should have node");
        assert_eq!(node.flag_bits, Some(0x01));
        assert_eq!(node.name, Some("router1".to_string()));
        assert_eq!(node.ipv4_router_id, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_ls_attr_link_bandwidth_roundtrip() {
        let proto_attr = proto::LsAttribute {
            tlvs: vec![],
            node: None,
            link: Some(proto::LsLinkAttribute {
                ipv4_router_id_local: None,
                ipv6_router_id_local: None,
                ipv4_router_id_remote: None,
                ipv6_router_id_remote: None,
                admin_group: Some(0xFF),
                max_link_bandwidth: Some(1_000_000.0),
                max_reservable_bandwidth: Some(500_000.0),
                unreserved_bandwidth: vec![],
                te_default_metric: None,
                link_protection: None,
                mpls_protocol_mask: None,
                igp_metric: Some(10),
                srlg: vec![100, 200],
                opaque: None,
                name: Some("eth0".to_string()),
            }),
            prefix: None,
        };

        let internal = proto_to_ls_attr(&proto_attr);
        let back = ls_attr_to_proto(&internal);
        let link = back.link.as_ref().expect("should have link");
        assert_eq!(link.admin_group, Some(0xFF));
        assert_eq!(link.igp_metric, Some(10));
        assert_eq!(link.srlg, vec![100, 200]);
        assert_eq!(link.name, Some("eth0".to_string()));
        // Float round-trip
        assert!((link.max_link_bandwidth.unwrap() - 1_000_000.0).abs() < 0.1);
    }
}
