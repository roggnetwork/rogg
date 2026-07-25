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

use super::bgpls::{LsAttrTlvType, LsTlv};
use crate::log::warn;

const TLV_HEADER_LEN: usize = 4; // Type(2) + Length(2)

/// BGP-LS Attribute (path attribute type 29, optional transitive).
///
/// Carries node/link/prefix properties as a sequence of typed TLVs.
/// Raw bytes are always preserved for opaque propagation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LsAttr {
    pub raw: Vec<u8>,
    pub tlvs: Vec<LsAttrTlv>,
}

/// A parsed TLV from the BGP-LS Attribute (RFC 9552 Section 5.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LsAttrTlv {
    Node(NodeAttrTlv),
    Link(LinkAttrTlv),
    Prefix(PrefixAttrTlv),
    Unknown(LsTlv),
}

/// Node Attribute TLVs (RFC 9552 Section 5.3.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeAttrTlv {
    FlagBits(u8),
    Opaque(Vec<u8>),
    Name(String),
    IsisAreaId(Vec<u8>),
    Ipv4RouterId(Ipv4Addr),
    Ipv6RouterId(Ipv6Addr),
}

/// Link Attribute TLVs (RFC 9552 Section 5.3.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LinkAttrTlv {
    Ipv4RouterIdLocal(Ipv4Addr),
    Ipv6RouterIdLocal(Ipv6Addr),
    Ipv4RouterIdRemote(Ipv4Addr),
    Ipv6RouterIdRemote(Ipv6Addr),
    AdminGroup(u32),
    MaxLinkBw(u32),
    MaxRsvblLinkBw(u32),
    UnreservedBw([u32; 8]),
    TeDefaultMetric(u32),
    LinkProtection(u16),
    MplsProtocolMask(u8),
    IgpMetric(u32),
    Srlg(Vec<u32>),
    Opaque(Vec<u8>),
    Name(String),
}

/// Prefix Attribute TLVs (RFC 9552 Section 5.3.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PrefixAttrTlv {
    IgpFlags(u8),
    IgpRouteTag(Vec<u32>),
    IgpExtendedRouteTag(Vec<u64>),
    Metric(u32),
    OspfFwdAddr(IpAddr),
    Opaque(Vec<u8>),
}

/// Parse a BGP-LS Attribute from raw path attribute value bytes.
///
/// Returns None if the TLV structure is malformed (triggers Attribute Discard
/// per RFC 9552 Section 8.2). Unknown TLVs are preserved for propagation.
/// TLV ordering is not validated -- RFC 9552 says SHOULD be ascending but
/// unordered is not malformed for the attribute.
pub fn parse_ls_attr(data: &[u8]) -> Option<LsAttr> {
    if data.is_empty() {
        return Some(LsAttr {
            raw: Vec::new(),
            tlvs: Vec::new(),
        });
    }

    let tlvs = parse_attr_tlv_list(data)?;

    Some(LsAttr {
        raw: data.to_vec(),
        tlvs,
    })
}

/// Build an LsAttr from typed TLVs (for gRPC injection / tests).
/// Encodes each TLV to set the raw field.
pub fn build_ls_attr(tlvs: Vec<LsAttrTlv>) -> LsAttr {
    let mut raw = Vec::new();
    for tlv in &tlvs {
        write_attr_tlv(&mut raw, tlv);
    }
    LsAttr { raw, tlvs }
}

fn write_tlv(buf: &mut Vec<u8>, tlv_type: LsAttrTlvType, value: &[u8]) {
    buf.extend_from_slice(&(tlv_type as u16).to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
}

fn write_tlv_raw(buf: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
    buf.extend_from_slice(&tlv_type.to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
}

fn write_attr_tlv(buf: &mut Vec<u8>, tlv: &LsAttrTlv) {
    match tlv {
        LsAttrTlv::Node(node) => write_node_tlv(buf, node),
        LsAttrTlv::Link(link) => write_link_tlv(buf, link),
        LsAttrTlv::Prefix(prefix) => write_prefix_tlv(buf, prefix),
        LsAttrTlv::Unknown(tlv) => write_tlv_raw(buf, tlv.tlv_type, &tlv.value),
    }
}

fn write_node_tlv(buf: &mut Vec<u8>, tlv: &NodeAttrTlv) {
    match tlv {
        NodeAttrTlv::FlagBits(flags) => write_tlv(buf, LsAttrTlvType::NodeFlagBits, &[*flags]),
        NodeAttrTlv::Opaque(data) => write_tlv(buf, LsAttrTlvType::OpaqueNodeAttr, data),
        NodeAttrTlv::Name(name) => write_tlv(buf, LsAttrTlvType::NodeName, name.as_bytes()),
        NodeAttrTlv::IsisAreaId(area) => write_tlv(buf, LsAttrTlvType::IsisAreaId, area),
        NodeAttrTlv::Ipv4RouterId(addr) => {
            write_tlv(buf, LsAttrTlvType::Ipv4RouterIdLocal, &addr.octets())
        }
        NodeAttrTlv::Ipv6RouterId(addr) => {
            write_tlv(buf, LsAttrTlvType::Ipv6RouterIdLocal, &addr.octets())
        }
    }
}

fn write_link_tlv(buf: &mut Vec<u8>, tlv: &LinkAttrTlv) {
    match tlv {
        LinkAttrTlv::Ipv4RouterIdLocal(addr) => {
            write_tlv(buf, LsAttrTlvType::Ipv4RouterIdLocal, &addr.octets())
        }
        LinkAttrTlv::Ipv6RouterIdLocal(addr) => {
            write_tlv(buf, LsAttrTlvType::Ipv6RouterIdLocal, &addr.octets())
        }
        LinkAttrTlv::Ipv4RouterIdRemote(addr) => {
            write_tlv(buf, LsAttrTlvType::Ipv4RouterIdRemote, &addr.octets())
        }
        LinkAttrTlv::Ipv6RouterIdRemote(addr) => {
            write_tlv(buf, LsAttrTlvType::Ipv6RouterIdRemote, &addr.octets())
        }
        LinkAttrTlv::AdminGroup(val) => {
            write_tlv(buf, LsAttrTlvType::AdminGroup, &val.to_be_bytes())
        }
        LinkAttrTlv::MaxLinkBw(val) => write_tlv(buf, LsAttrTlvType::MaxLinkBw, &val.to_be_bytes()),
        LinkAttrTlv::MaxRsvblLinkBw(val) => {
            write_tlv(buf, LsAttrTlvType::MaxRsvblLinkBw, &val.to_be_bytes())
        }
        LinkAttrTlv::UnreservedBw(val) => {
            let bytes: Vec<u8> = val.iter().flat_map(|v| v.to_be_bytes()).collect();
            write_tlv(buf, LsAttrTlvType::UnreservedBw, &bytes)
        }
        LinkAttrTlv::TeDefaultMetric(val) => {
            write_tlv(buf, LsAttrTlvType::TeDefaultMetric, &val.to_be_bytes())
        }
        LinkAttrTlv::LinkProtection(val) => {
            write_tlv(buf, LsAttrTlvType::LinkProtection, &val.to_be_bytes())
        }
        LinkAttrTlv::MplsProtocolMask(val) => {
            write_tlv(buf, LsAttrTlvType::MplsProtocolMask, &[*val])
        }
        LinkAttrTlv::IgpMetric(val) => {
            let bytes = val.to_be_bytes();
            let start = bytes.iter().position(|&b| b != 0).unwrap_or(3).min(3);
            write_tlv(buf, LsAttrTlvType::IgpMetric, &bytes[start..])
        }
        LinkAttrTlv::Srlg(groups) => {
            let bytes: Vec<u8> = groups.iter().flat_map(|g| g.to_be_bytes()).collect();
            write_tlv(buf, LsAttrTlvType::Srlg, &bytes)
        }
        LinkAttrTlv::Opaque(data) => write_tlv(buf, LsAttrTlvType::OpaqueLinkAttr, data),
        LinkAttrTlv::Name(name) => write_tlv(buf, LsAttrTlvType::LinkName, name.as_bytes()),
    }
}

fn write_prefix_tlv(buf: &mut Vec<u8>, tlv: &PrefixAttrTlv) {
    match tlv {
        PrefixAttrTlv::IgpFlags(flags) => write_tlv(buf, LsAttrTlvType::IgpFlags, &[*flags]),
        PrefixAttrTlv::IgpRouteTag(tags) => {
            let bytes: Vec<u8> = tags.iter().flat_map(|t| t.to_be_bytes()).collect();
            write_tlv(buf, LsAttrTlvType::IgpRouteTag, &bytes)
        }
        PrefixAttrTlv::IgpExtendedRouteTag(tags) => {
            let bytes: Vec<u8> = tags.iter().flat_map(|t| t.to_be_bytes()).collect();
            write_tlv(buf, LsAttrTlvType::IgpExtendedRouteTag, &bytes)
        }
        PrefixAttrTlv::Metric(val) => {
            write_tlv(buf, LsAttrTlvType::PrefixMetric, &val.to_be_bytes())
        }
        PrefixAttrTlv::OspfFwdAddr(addr) => match addr {
            IpAddr::V4(v4) => write_tlv(buf, LsAttrTlvType::OspfFwdAddr, &v4.octets()),
            IpAddr::V6(v6) => write_tlv(buf, LsAttrTlvType::OspfFwdAddr, &v6.octets()),
        },
        PrefixAttrTlv::Opaque(data) => write_tlv(buf, LsAttrTlvType::OpaquePrefixAttr, data),
    }
}

/// Parse a raw TLV into a typed LsAttrTlv variant.
/// Returns None if a known TLV has an invalid length (malformed attribute).
fn parse_attr_tlv(tlv_type: u16, value: &[u8]) -> Option<LsAttrTlv> {
    let known = match LsAttrTlvType::from_u16(tlv_type) {
        Some(known) => known,
        None => {
            return Some(LsAttrTlv::Unknown(LsTlv {
                tlv_type,
                value: value.to_vec(),
            }))
        }
    };

    let tlv = match known {
        // Node (Section 5.3.1)
        LsAttrTlvType::NodeFlagBits => {
            check_len(known, value, 1)?;
            LsAttrTlv::Node(NodeAttrTlv::FlagBits(value[0]))
        }
        LsAttrTlvType::OpaqueNodeAttr => LsAttrTlv::Node(NodeAttrTlv::Opaque(value.to_vec())),
        LsAttrTlvType::NodeName => {
            let name = String::from_utf8(value.to_vec()).ok()?;
            LsAttrTlv::Node(NodeAttrTlv::Name(name))
        }
        LsAttrTlvType::IsisAreaId => LsAttrTlv::Node(NodeAttrTlv::IsisAreaId(value.to_vec())),
        LsAttrTlvType::Ipv4RouterIdLocal => {
            check_len(known, value, 4)?;
            // TLV 1028 appears in both Node and Link contexts.
            // We default to Node here; the consumer can re-interpret based on NLRI type.
            LsAttrTlv::Node(NodeAttrTlv::Ipv4RouterId(Ipv4Addr::new(
                value[0], value[1], value[2], value[3],
            )))
        }
        LsAttrTlvType::Ipv6RouterIdLocal => {
            check_len(known, value, 16)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(value);
            LsAttrTlv::Node(NodeAttrTlv::Ipv6RouterId(Ipv6Addr::from(octets)))
        }
        // Link (Section 5.3.2)
        LsAttrTlvType::Ipv4RouterIdRemote => {
            check_len(known, value, 4)?;
            LsAttrTlv::Link(LinkAttrTlv::Ipv4RouterIdRemote(Ipv4Addr::new(
                value[0], value[1], value[2], value[3],
            )))
        }
        LsAttrTlvType::Ipv6RouterIdRemote => {
            check_len(known, value, 16)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(value);
            LsAttrTlv::Link(LinkAttrTlv::Ipv6RouterIdRemote(Ipv6Addr::from(octets)))
        }
        LsAttrTlvType::AdminGroup => {
            check_len(known, value, 4)?;
            LsAttrTlv::Link(LinkAttrTlv::AdminGroup(u32::from_be_bytes([
                value[0], value[1], value[2], value[3],
            ])))
        }
        LsAttrTlvType::MaxLinkBw => {
            check_len(known, value, 4)?;
            LsAttrTlv::Link(LinkAttrTlv::MaxLinkBw(u32::from_be_bytes([
                value[0], value[1], value[2], value[3],
            ])))
        }
        LsAttrTlvType::MaxRsvblLinkBw => {
            check_len(known, value, 4)?;
            LsAttrTlv::Link(LinkAttrTlv::MaxRsvblLinkBw(u32::from_be_bytes([
                value[0], value[1], value[2], value[3],
            ])))
        }
        LsAttrTlvType::UnreservedBw => {
            check_len(known, value, 32)?;
            let mut bw = [0u32; 8];
            for (idx, chunk) in value.chunks_exact(4).enumerate() {
                bw[idx] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            LsAttrTlv::Link(LinkAttrTlv::UnreservedBw(bw))
        }
        LsAttrTlvType::TeDefaultMetric => {
            check_len(known, value, 4)?;
            LsAttrTlv::Link(LinkAttrTlv::TeDefaultMetric(u32::from_be_bytes([
                value[0], value[1], value[2], value[3],
            ])))
        }
        LsAttrTlvType::LinkProtection => {
            check_len(known, value, 2)?;
            LsAttrTlv::Link(LinkAttrTlv::LinkProtection(u16::from_be_bytes([
                value[0], value[1],
            ])))
        }
        LsAttrTlvType::MplsProtocolMask => {
            check_len(known, value, 1)?;
            LsAttrTlv::Link(LinkAttrTlv::MplsProtocolMask(value[0]))
        }
        LsAttrTlvType::IgpMetric => {
            if value.is_empty() || value.len() > 3 {
                warn!(
                    ?known,
                    len = value.len(),
                    "BGP-LS attribute TLV invalid length (expected 1-3)"
                );
                return None;
            }
            let mut metric: u32 = 0;
            for &byte in value {
                metric = (metric << 8) | byte as u32;
            }
            LsAttrTlv::Link(LinkAttrTlv::IgpMetric(metric))
        }
        LsAttrTlvType::Srlg => {
            check_multiple(known, value, 4)?;
            let groups = value
                .chunks_exact(4)
                .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect();
            LsAttrTlv::Link(LinkAttrTlv::Srlg(groups))
        }
        LsAttrTlvType::OpaqueLinkAttr => LsAttrTlv::Link(LinkAttrTlv::Opaque(value.to_vec())),
        LsAttrTlvType::LinkName => {
            let name = String::from_utf8(value.to_vec()).ok()?;
            LsAttrTlv::Link(LinkAttrTlv::Name(name))
        }
        // Prefix (Section 5.3.3)
        LsAttrTlvType::IgpFlags => {
            check_len(known, value, 1)?;
            LsAttrTlv::Prefix(PrefixAttrTlv::IgpFlags(value[0]))
        }
        LsAttrTlvType::IgpRouteTag => {
            check_multiple(known, value, 4)?;
            let tags = value
                .chunks_exact(4)
                .map(|chunk| u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                .collect();
            LsAttrTlv::Prefix(PrefixAttrTlv::IgpRouteTag(tags))
        }
        LsAttrTlvType::IgpExtendedRouteTag => {
            check_multiple(known, value, 8)?;
            let tags = value
                .chunks_exact(8)
                .map(|chunk| {
                    u64::from_be_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                        chunk[7],
                    ])
                })
                .collect();
            LsAttrTlv::Prefix(PrefixAttrTlv::IgpExtendedRouteTag(tags))
        }
        LsAttrTlvType::PrefixMetric => {
            check_len(known, value, 4)?;
            LsAttrTlv::Prefix(PrefixAttrTlv::Metric(u32::from_be_bytes([
                value[0], value[1], value[2], value[3],
            ])))
        }
        LsAttrTlvType::OspfFwdAddr => {
            let addr = match value.len() {
                4 => IpAddr::V4(Ipv4Addr::new(value[0], value[1], value[2], value[3])),
                16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(value);
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                _ => {
                    warn!(
                        ?known,
                        len = value.len(),
                        "BGP-LS attribute TLV invalid length (expected 4 or 16)"
                    );
                    return None;
                }
            };
            LsAttrTlv::Prefix(PrefixAttrTlv::OspfFwdAddr(addr))
        }
        LsAttrTlvType::OpaquePrefixAttr => LsAttrTlv::Prefix(PrefixAttrTlv::Opaque(value.to_vec())),
    };

    Some(tlv)
}

fn check_len(tlv_type: LsAttrTlvType, value: &[u8], expected: usize) -> Option<()> {
    if value.len() != expected {
        warn!(
            ?tlv_type,
            actual = value.len(),
            expected,
            "BGP-LS attribute TLV invalid length"
        );
        return None;
    }
    Some(())
}

fn check_multiple(tlv_type: LsAttrTlvType, value: &[u8], multiple: usize) -> Option<()> {
    if !value.len().is_multiple_of(multiple) {
        warn!(
            ?tlv_type,
            actual = value.len(),
            multiple,
            "BGP-LS attribute TLV invalid length"
        );
        return None;
    }
    Some(())
}

/// Parse raw bytes into a list of typed LsAttrTlv.
/// Returns None if the TLV framing is malformed.
fn parse_attr_tlv_list(bytes: &[u8]) -> Option<Vec<LsAttrTlv>> {
    let mut tlvs = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if bytes.len() - cursor < TLV_HEADER_LEN {
            warn!(
                offset = cursor,
                remaining = bytes.len() - cursor,
                "BGP-LS attribute TLV truncated"
            );
            return None;
        }

        let tlv_type = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        let tlv_len = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize;
        cursor += TLV_HEADER_LEN;

        if cursor + tlv_len > bytes.len() {
            warn!(
                tlv_type,
                tlv_len,
                remaining = bytes.len() - cursor,
                "BGP-LS attribute TLV length exceeds available bytes"
            );
            return None;
        }

        let value = &bytes[cursor..cursor + tlv_len];
        tlvs.push(parse_attr_tlv(tlv_type, value)?);
        cursor += tlv_len;
    }

    Some(tlvs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tlv_bytes(tlv_type: u16, value: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&tlv_type.to_be_bytes());
        bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(value);
        bytes
    }

    #[test]
    fn test_round_trip() {
        let ipv6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let cases: Vec<(&str, LsAttrTlv)> = vec![
            // Node (Section 5.3.1)
            (
                "node flag bits",
                LsAttrTlv::Node(NodeAttrTlv::FlagBits(0x80)),
            ),
            (
                "opaque node",
                LsAttrTlv::Node(NodeAttrTlv::Opaque(vec![0xCA, 0xFE])),
            ),
            (
                "node name",
                LsAttrTlv::Node(NodeAttrTlv::Name("spine-01".to_string())),
            ),
            (
                "isis area id",
                LsAttrTlv::Node(NodeAttrTlv::IsisAreaId(vec![49, 0, 0])),
            ),
            (
                "ipv4 router-id",
                LsAttrTlv::Node(NodeAttrTlv::Ipv4RouterId(Ipv4Addr::new(10, 0, 0, 1))),
            ),
            (
                "ipv6 router-id",
                LsAttrTlv::Node(NodeAttrTlv::Ipv6RouterId(ipv6)),
            ),
            // Link (Section 5.3.2)
            // TLV 1028/1029 encode identically for Node and Link; parse always yields Node.
            // Link::Ipv4RouterIdLocal and Link::Ipv6RouterIdLocal round-trip as Node variants.
            (
                "link ipv4 remote",
                LsAttrTlv::Link(LinkAttrTlv::Ipv4RouterIdRemote(Ipv4Addr::new(10, 0, 0, 2))),
            ),
            (
                "link ipv6 remote",
                LsAttrTlv::Link(LinkAttrTlv::Ipv6RouterIdRemote(ipv6)),
            ),
            (
                "admin group",
                LsAttrTlv::Link(LinkAttrTlv::AdminGroup(0xFF)),
            ),
            (
                "max link bw",
                LsAttrTlv::Link(LinkAttrTlv::MaxLinkBw(0x4E6E6B28)),
            ),
            (
                "max rsvbl bw",
                LsAttrTlv::Link(LinkAttrTlv::MaxRsvblLinkBw(0x4E6E6B28)),
            ),
            (
                "unreserved bw",
                LsAttrTlv::Link(LinkAttrTlv::UnreservedBw([1, 2, 3, 4, 5, 6, 7, 8])),
            ),
            (
                "te default metric",
                LsAttrTlv::Link(LinkAttrTlv::TeDefaultMetric(100)),
            ),
            (
                "link protection",
                LsAttrTlv::Link(LinkAttrTlv::LinkProtection(4)),
            ),
            (
                "mpls mask",
                LsAttrTlv::Link(LinkAttrTlv::MplsProtocolMask(0x03)),
            ),
            ("igp metric", LsAttrTlv::Link(LinkAttrTlv::IgpMetric(50))),
            ("srlg", LsAttrTlv::Link(LinkAttrTlv::Srlg(vec![1, 2, 3]))),
            ("srlg empty", LsAttrTlv::Link(LinkAttrTlv::Srlg(vec![]))),
            (
                "opaque link",
                LsAttrTlv::Link(LinkAttrTlv::Opaque(vec![0xDE, 0xAD])),
            ),
            (
                "link name",
                LsAttrTlv::Link(LinkAttrTlv::Name("eth0".to_string())),
            ),
            // Prefix (Section 5.3.3)
            (
                "igp flags",
                LsAttrTlv::Prefix(PrefixAttrTlv::IgpFlags(0x00)),
            ),
            (
                "igp route tag",
                LsAttrTlv::Prefix(PrefixAttrTlv::IgpRouteTag(vec![42, 99])),
            ),
            (
                "igp route tag empty",
                LsAttrTlv::Prefix(PrefixAttrTlv::IgpRouteTag(vec![])),
            ),
            (
                "igp ext tag",
                LsAttrTlv::Prefix(PrefixAttrTlv::IgpExtendedRouteTag(vec![1])),
            ),
            (
                "prefix metric",
                LsAttrTlv::Prefix(PrefixAttrTlv::Metric(20)),
            ),
            (
                "ospf fwd v4",
                LsAttrTlv::Prefix(PrefixAttrTlv::OspfFwdAddr(IpAddr::V4(Ipv4Addr::new(
                    10, 0, 0, 1,
                )))),
            ),
            (
                "ospf fwd v6",
                LsAttrTlv::Prefix(PrefixAttrTlv::OspfFwdAddr(IpAddr::V6(ipv6))),
            ),
            (
                "opaque prefix",
                LsAttrTlv::Prefix(PrefixAttrTlv::Opaque(vec![0x01])),
            ),
            // Unknown
            (
                "unknown",
                LsAttrTlv::Unknown(LsTlv {
                    tlv_type: 65000,
                    value: vec![0xFA, 0xCE],
                }),
            ),
        ];

        for (name, input_tlv) in &cases {
            let attr = build_ls_attr(vec![input_tlv.clone()]);
            let parsed =
                parse_ls_attr(&attr.raw).unwrap_or_else(|| panic!("{name}: round-trip failed"));
            assert_eq!(parsed.tlvs.len(), 1, "{name}");
            assert_eq!(parsed.tlvs[0], *input_tlv, "{name}");
        }

        // All TLVs together in one attribute
        let all_tlvs: Vec<LsAttrTlv> = cases.iter().map(|(_, tlv)| tlv.clone()).collect();
        let attr = build_ls_attr(all_tlvs.clone());
        let parsed = parse_ls_attr(&attr.raw).expect("all-TLVs round-trip failed");
        assert_eq!(parsed.tlvs, all_tlvs);
    }

    #[test]
    fn test_igp_metric_variable_length() {
        let cases: Vec<(&str, Vec<u8>, u32)> = vec![
            ("1 byte", vec![10], 10),
            ("2 bytes", vec![0x01, 0x00], 256),
            ("3 bytes", vec![0x01, 0x00, 0x00], 65536),
            ("3 bytes max", vec![0xFF, 0xFF, 0xFF], 0x00FFFFFF),
        ];

        for (name, wire, expected) in cases {
            let data = make_tlv_bytes(LsAttrTlvType::IgpMetric as u16, &wire);
            let attr = parse_ls_attr(&data).unwrap_or_else(|| panic!("{name}: parse failed"));
            assert_eq!(
                attr.tlvs[0],
                LsAttrTlv::Link(LinkAttrTlv::IgpMetric(expected)),
                "{name}"
            );
        }
    }

    #[test]
    fn test_malformed_known_tlv_wrong_length() {
        let cases: Vec<(&str, u16, Vec<u8>)> = vec![
            (
                "node flags long",
                LsAttrTlvType::NodeFlagBits as u16,
                vec![0x80, 0x01],
            ),
            (
                "ipv4 rid short",
                LsAttrTlvType::Ipv4RouterIdLocal as u16,
                vec![10, 0, 0],
            ),
            (
                "ipv6 rid short",
                LsAttrTlvType::Ipv6RouterIdLocal as u16,
                vec![0x20; 15],
            ),
            (
                "admin group short",
                LsAttrTlvType::AdminGroup as u16,
                vec![0, 0, 1],
            ),
            ("max bw long", LsAttrTlvType::MaxLinkBw as u16, vec![0; 5]),
            (
                "max rsvbl bw short",
                LsAttrTlvType::MaxRsvblLinkBw as u16,
                vec![0; 3],
            ),
            (
                "unreserved bw short",
                LsAttrTlvType::UnreservedBw as u16,
                vec![0; 31],
            ),
            (
                "te metric short",
                LsAttrTlvType::TeDefaultMetric as u16,
                vec![0, 0],
            ),
            (
                "link prot short",
                LsAttrTlvType::LinkProtection as u16,
                vec![0x01],
            ),
            (
                "mpls mask long",
                LsAttrTlvType::MplsProtocolMask as u16,
                vec![0x03, 0x01],
            ),
            ("igp metric empty", LsAttrTlvType::IgpMetric as u16, vec![]),
            ("igp metric 4b", LsAttrTlvType::IgpMetric as u16, vec![0; 4]),
            ("srlg bad align", LsAttrTlvType::Srlg as u16, vec![0; 5]),
            ("igp flags long", LsAttrTlvType::IgpFlags as u16, vec![0, 0]),
            (
                "route tag bad",
                LsAttrTlvType::IgpRouteTag as u16,
                vec![0; 3],
            ),
            (
                "ext tag bad",
                LsAttrTlvType::IgpExtendedRouteTag as u16,
                vec![0; 7],
            ),
            (
                "prefix metric short",
                LsAttrTlvType::PrefixMetric as u16,
                vec![0, 0, 0],
            ),
            (
                "ospf fwd bad len",
                LsAttrTlvType::OspfFwdAddr as u16,
                vec![0; 8],
            ),
            (
                "ipv4 rid remote short",
                LsAttrTlvType::Ipv4RouterIdRemote as u16,
                vec![10, 0],
            ),
            (
                "ipv6 rid remote long",
                LsAttrTlvType::Ipv6RouterIdRemote as u16,
                vec![0; 17],
            ),
            (
                "node name invalid utf8",
                LsAttrTlvType::NodeName as u16,
                vec![0xFF, 0xFE],
            ),
            (
                "link name invalid utf8",
                LsAttrTlvType::LinkName as u16,
                vec![0xFF, 0xFE],
            ),
        ];

        for (name, tlv_type, value) in cases {
            let data = make_tlv_bytes(tlv_type, &value);
            assert!(parse_ls_attr(&data).is_none(), "{name}: should fail");
        }
    }

    #[test]
    fn test_malformed_tlv_discards_attribute() {
        // Valid TLV followed by malformed TLV -> attribute discard (RFC 9552 Section 8.2)
        let mut data = Vec::new();
        data.extend_from_slice(&make_tlv_bytes(LsAttrTlvType::NodeName as u16, b"ok"));
        data.extend_from_slice(&make_tlv_bytes(LsAttrTlvType::NodeFlagBits as u16, &[0, 0]));
        assert!(parse_ls_attr(&data).is_none());
    }

    #[test]
    fn test_malformed_framing() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("truncated header", vec![0x04, 0x00]),
            ("length overflow", {
                let mut data = Vec::new();
                data.extend_from_slice(&1024u16.to_be_bytes());
                data.extend_from_slice(&100u16.to_be_bytes());
                data.extend_from_slice(&[0x01, 0x02]);
                data
            }),
            ("trailing bytes", {
                let mut data = make_tlv_bytes(LsAttrTlvType::IgpMetric as u16, &[10]);
                data.extend_from_slice(&[0x00, 0x01, 0x02]);
                data
            }),
        ];

        for (name, data) in cases {
            assert!(parse_ls_attr(&data).is_none(), "{name}: should fail");
        }
    }

    #[test]
    fn test_empty_attribute() {
        let attr = parse_ls_attr(&[]).expect("empty should succeed");
        assert!(attr.tlvs.is_empty());
        assert!(attr.raw.is_empty());
    }

    #[test]
    fn test_unordered_tlvs_accepted() {
        // Descending type order -- valid per RFC 9552 (SHOULD not MUST for attributes)
        let mut data = Vec::new();
        data.extend_from_slice(&make_tlv_bytes(LsAttrTlvType::LinkName as u16, b"eth0"));
        data.extend_from_slice(&make_tlv_bytes(LsAttrTlvType::IgpMetric as u16, &[5]));

        let attr = parse_ls_attr(&data).expect("unordered should succeed");
        assert_eq!(attr.tlvs.len(), 2);
        assert_eq!(
            attr.tlvs[0],
            LsAttrTlv::Link(LinkAttrTlv::Name("eth0".to_string()))
        );
        assert_eq!(attr.tlvs[1], LsAttrTlv::Link(LinkAttrTlv::IgpMetric(5)));
    }
}
