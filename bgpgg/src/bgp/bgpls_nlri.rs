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

use crate::bgp::multiprotocol::Safi;
use std::collections::HashMap;
use std::fmt;

use super::bgpls::{LsTlv, LsTlvType};
use super::msg_notification::{BgpError, UpdateMessageError};
use super::utils::ParserError;
use crate::log::warn;

const TLV_HEADER_LEN: usize = 4; // Type(2) + Length(2)
const NLRI_BODY_HEADER_LEN: usize = 9; // Protocol-ID(1) + Identifier(8)

/// Errors encountered while parsing BGP-LS NLRI descriptor TLVs.
/// These are recoverable at the NLRI level: the malformed NLRI is discarded
/// but other NLRIs in the same UPDATE are processed normally.
#[derive(Debug)]
enum LsNlriError {
    BodyTooShort(usize),
    TlvTruncated {
        offset: usize,
        remaining: usize,
    },
    TlvOverflow {
        tlv_type: u16,
        len: usize,
        available: usize,
    },
    TlvOrdering {
        prev_type: u16,
        prev_len: usize,
        curr_type: u16,
        curr_len: usize,
    },
    MissingTlv(&'static str),
    DuplicateSubTlv(u16),
    InvalidLength {
        name: &'static str,
        actual: usize,
        expected: usize,
    },
    UnalignedLength {
        name: &'static str,
        actual: usize,
        alignment: usize,
    },
}

impl fmt::Display for LsNlriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LsNlriError::BodyTooShort(len) => write!(f, "body too short: {len} bytes"),
            LsNlriError::TlvTruncated { offset, remaining } => {
                write!(
                    f,
                    "TLV truncated at offset {offset}: {remaining} bytes remaining, need {TLV_HEADER_LEN}"
                )
            }
            LsNlriError::TlvOverflow {
                tlv_type,
                len,
                available,
            } => {
                write!(
                    f,
                    "TLV type {tlv_type} length {len} exceeds {available} available bytes"
                )
            }
            LsNlriError::TlvOrdering {
                prev_type,
                prev_len,
                curr_type,
                curr_len,
            } => {
                write!(
                    f,
                    "TLV ordering violation: type {prev_type}/len {prev_len} followed by type {curr_type}/len {curr_len}"
                )
            }
            LsNlriError::MissingTlv(name) => write!(f, "missing {name}"),
            LsNlriError::DuplicateSubTlv(tlv_type) => {
                write!(f, "duplicate Node Descriptor sub-TLV type {tlv_type}")
            }
            LsNlriError::InvalidLength {
                name,
                actual,
                expected,
            } => write!(f, "{name} length {actual}, expected {expected}"),
            LsNlriError::UnalignedLength {
                name,
                actual,
                alignment,
            } => {
                write!(f, "{name} length {actual} not a multiple of {alignment}")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LsNlriType {
    Node = 1,
    Link = 2,
    PrefixV4 = 3,
    PrefixV6 = 4,
}

impl LsNlriType {
    fn from_u16(val: u16) -> Option<LsNlriType> {
        match val {
            1 => Some(LsNlriType::Node),
            2 => Some(LsNlriType::Link),
            3 => Some(LsNlriType::PrefixV4),
            4 => Some(LsNlriType::PrefixV6),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LsProtocolId {
    IsIsL1 = 1,
    IsIsL2 = 2,
    OspfV2 = 3,
    Direct = 4,
    Static = 5,
    OspfV3 = 6,
}

impl LsProtocolId {
    fn from_u8(val: u8) -> Option<LsProtocolId> {
        match val {
            1 => Some(LsProtocolId::IsIsL1),
            2 => Some(LsProtocolId::IsIsL2),
            3 => Some(LsProtocolId::OspfV2),
            4 => Some(LsProtocolId::Direct),
            5 => Some(LsProtocolId::Static),
            6 => Some(LsProtocolId::OspfV3),
            _ => None,
        }
    }
}

/// RFC 4364: Route Distinguisher length in bytes.
pub const RD_LEN: usize = 8;

/// RFC 4364: 8-byte Route Distinguisher used to create distinct VPN-scoped routes.
pub type RouteDistinguisher = [u8; RD_LEN];

/// A single BGP-LS NLRI. Type + raw bytes always present; body parsed for known types.
///
/// For SAFI 72 (BGP-LS-VPN), the NLRI body is prefixed with an 8-byte Route
/// Distinguisher per RFC 9552 Section 5.2 Figure 6.  The `raw` field always
/// stores the body *without* the RD; the RD is kept separately so that the
/// same encode/decode helpers work for both SAFIs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LsNlri {
    pub nlri_type: u16,
    pub raw: Vec<u8>,
    pub body: Option<LsNlriBody>,
    /// Route Distinguisher for SAFI 72 NLRIs. None for SAFI 71.
    pub route_distinguisher: Option<RouteDistinguisher>,
}

impl LsNlri {
    /// True when this NLRI carries a Route Distinguisher (SAFI 72 / BGP-LS-VPN).
    pub fn is_vpn(&self) -> bool {
        self.route_distinguisher.is_some()
    }

    /// Returns the SAFI for this NLRI: LinkStateVpn if it has an RD, LinkState otherwise.
    pub fn safi(&self) -> Safi {
        if self.is_vpn() {
            Safi::LinkStateVpn
        } else {
            Safi::LinkState
        }
    }

    /// Set the Instance-ID (identifier) on a parsed NLRI and re-encode raw bytes.
    /// No-op if body is not parsed (opaque NLRI).
    pub fn set_identifier(&mut self, identifier: u64) {
        if let Some(ref mut body) = self.body {
            body.identifier = identifier;
            self.raw = encode_ls_nlri_body(body.protocol_id, body.identifier, &body.descriptors);
        }
    }
}

/// Parsed NLRI body: Protocol-ID + Identifier + type-specific descriptors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LsNlriBody {
    pub protocol_id: u8,
    pub identifier: u64,
    pub descriptors: LsDescriptors,
}

impl LsNlriBody {
    pub fn protocol_id(&self) -> Option<LsProtocolId> {
        LsProtocolId::from_u8(self.protocol_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LsDescriptors {
    Node {
        local_node: NodeDescriptor,
    },
    Link {
        local_node: NodeDescriptor,
        remote_node: NodeDescriptor,
        link_descriptors: LinkDescriptor,
    },
    PrefixV4 {
        local_node: NodeDescriptor,
        prefix_descriptors: PrefixDescriptor,
    },
    PrefixV6 {
        local_node: NodeDescriptor,
        prefix_descriptors: PrefixDescriptor,
    },
}

impl LsDescriptors {
    /// Returns a reference to the local node descriptor present in all NLRI types.
    pub fn local_node(&self) -> &NodeDescriptor {
        match self {
            LsDescriptors::Node { local_node } => local_node,
            LsDescriptors::Link { local_node, .. } => local_node,
            LsDescriptors::PrefixV4 { local_node, .. } => local_node,
            LsDescriptors::PrefixV6 { local_node, .. } => local_node,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct NodeDescriptor {
    pub as_number: Option<u32>,
    pub bgp_ls_id: Option<u32>,
    pub ospf_area_id: Option<u32>,
    pub igp_router_id: Option<Vec<u8>>,
    pub unknown: Vec<LsTlv>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct LinkDescriptor {
    pub link_local_id: Option<u32>,
    pub link_remote_id: Option<u32>,
    pub ipv4_interface_addr: Option<[u8; 4]>,
    pub ipv4_neighbor_addr: Option<[u8; 4]>,
    pub ipv6_interface_addr: Option<[u8; 16]>,
    pub ipv6_neighbor_addr: Option<[u8; 16]>,
    pub multi_topology_id: Option<Vec<u16>>,
    pub unknown: Vec<LsTlv>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct PrefixDescriptor {
    pub multi_topology_id: Option<Vec<u16>>,
    pub ospf_route_type: Option<u8>,
    pub ip_reachability: Option<Vec<u8>>,
    pub unknown: Vec<LsTlv>,
}

fn make_parser_error() -> ParserError {
    ParserError::BgpError {
        error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
        data: Vec::new(),
    }
}

/// Parse a list of BGP-LS NLRIs from MP_REACH_NLRI or MP_UNREACH_NLRI bytes.
///
/// Each NLRI: NLRI Type (2) + Total NLRI Length (2) + body.
/// For SAFI 72 (LinkStateVpn), each body starts with an 8-byte Route Distinguisher
/// before the Protocol-ID + Identifier + descriptor TLVs (RFC 9552 Section 5.2).
/// Unknown NLRI types are preserved as opaque per RFC 9552 Section 5.2.
/// Returns Err only for unrecoverable length errors that prevent parsing
/// the rest of the UPDATE.
pub fn parse_ls_nlri_list(bytes: &[u8], safi: Safi) -> Result<Vec<LsNlri>, ParserError> {
    let mut entries = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if bytes.len() - cursor < 4 {
            warn!(
                remaining = bytes.len() - cursor,
                "BGP-LS NLRI truncated: not enough bytes for type+length header"
            );
            return Err(make_parser_error());
        }

        let nlri_type = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        let total_len = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize;
        cursor += 4;

        if cursor + total_len > bytes.len() {
            warn!(
                nlri_type,
                total_len,
                remaining = bytes.len() - cursor,
                "BGP-LS NLRI length exceeds available bytes"
            );
            return Err(make_parser_error());
        }

        let full_body = &bytes[cursor..cursor + total_len];

        // For VPN SAFI, strip the 8-byte Route Distinguisher prefix.
        let (route_distinguisher, ls_body) = if safi == Safi::LinkStateVpn {
            if full_body.len() < RD_LEN {
                warn!(
                    nlri_type,
                    len = full_body.len(),
                    "BGP-LS VPN NLRI too short for Route Distinguisher"
                );
                cursor += total_len;
                continue;
            }
            let mut rd = RouteDistinguisher::default();
            rd.copy_from_slice(&full_body[..RD_LEN]);
            (Some(rd), &full_body[RD_LEN..])
        } else {
            (None, full_body)
        };

        let raw = ls_body.to_vec();
        let parsed = match LsNlriType::from_u16(nlri_type) {
            Some(known_type) => match parse_ls_nlri_body(known_type, ls_body) {
                Ok(nlri) => Some(nlri),
                Err(nlri_err) => {
                    warn!(
                        nlri_type = ?known_type,
                        "BGP-LS NLRI malformed, discarding: {nlri_err}"
                    );
                    None
                }
            },
            None => None,
        };

        entries.push(LsNlri {
            nlri_type,
            raw,
            body: parsed,
            route_distinguisher,
        });

        cursor += total_len;
    }

    Ok(entries)
}

/// Parse the body of a single known-type BGP-LS NLRI.
///
/// Body format: Protocol-ID (1) + Identifier (8) + descriptor TLVs.
fn parse_ls_nlri_body(nlri_type: LsNlriType, body: &[u8]) -> Result<LsNlriBody, LsNlriError> {
    if body.len() < NLRI_BODY_HEADER_LEN {
        return Err(LsNlriError::BodyTooShort(body.len()));
    }

    let protocol_id = body[0];
    let identifier = u64::from_be_bytes([
        body[1], body[2], body[3], body[4], body[5], body[6], body[7], body[8],
    ]);

    let descriptors = parse_ls_nlri_descriptors(nlri_type, &body[NLRI_BODY_HEADER_LEN..])?;

    Ok(LsNlriBody {
        protocol_id,
        identifier,
        descriptors,
    })
}

/// Parse TLVs into an LsDescriptors variant for the given NLRI type.
fn parse_ls_nlri_descriptors(
    nlri_type: LsNlriType,
    bytes: &[u8],
) -> Result<LsDescriptors, LsNlriError> {
    let tlvs = parse_tlv_list(bytes)?;
    validate_tlv_ordering(&tlvs)?;
    let mut tlv_map: HashMap<u16, Vec<LsTlv>> = HashMap::new();
    for tlv in tlvs {
        tlv_map.entry(tlv.tlv_type).or_default().push(tlv);
    }

    let local_node = match tlv_map.get(&(LsTlvType::LocalNodeDescriptors as u16)) {
        Some(tlvs) => parse_node_descriptor(&tlvs[0].value)?,
        None => return Err(LsNlriError::MissingTlv("Local Node Descriptors")),
    };

    match nlri_type {
        LsNlriType::Node => Ok(LsDescriptors::Node { local_node }),
        LsNlriType::Link => {
            let remote_node = match tlv_map.get(&(LsTlvType::RemoteNodeDescriptors as u16)) {
                Some(tlvs) => parse_node_descriptor(&tlvs[0].value)?,
                None => return Err(LsNlriError::MissingTlv("Remote Node Descriptors")),
            };

            Ok(LsDescriptors::Link {
                local_node,
                remote_node,
                link_descriptors: parse_link_descriptor(&tlv_map)?,
            })
        }
        LsNlriType::PrefixV4 => Ok(LsDescriptors::PrefixV4 {
            local_node,
            prefix_descriptors: parse_prefix_descriptor(&tlv_map)?,
        }),
        LsNlriType::PrefixV6 => Ok(LsDescriptors::PrefixV6 {
            local_node,
            prefix_descriptors: parse_prefix_descriptor(&tlv_map)?,
        }),
    }
}

/// Parse a sequence of TLVs from raw bytes.
fn parse_tlv_list(bytes: &[u8]) -> Result<Vec<LsTlv>, LsNlriError> {
    let mut tlvs = Vec::new();
    let mut cursor = 0;

    while cursor < bytes.len() {
        if bytes.len() - cursor < TLV_HEADER_LEN {
            return Err(LsNlriError::TlvTruncated {
                offset: cursor,
                remaining: bytes.len() - cursor,
            });
        }

        let tlv_type = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
        let tlv_len = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize;
        cursor += TLV_HEADER_LEN;

        if cursor + tlv_len > bytes.len() {
            return Err(LsNlriError::TlvOverflow {
                tlv_type,
                len: tlv_len,
                available: bytes.len() - cursor,
            });
        }

        tlvs.push(LsTlv {
            tlv_type,
            value: bytes[cursor..cursor + tlv_len].to_vec(),
        });
        cursor += tlv_len;
    }

    Ok(tlvs)
}

/// Validate canonical TLV ordering per RFC 9552 Section 5.1:
/// 1. Ascending by TLV Type
/// 2. Same type: ascending by Length
/// 3. Same type and length: ascending lexicographic Value
fn validate_tlv_ordering(tlvs: &[LsTlv]) -> Result<(), LsNlriError> {
    for window in tlvs.windows(2) {
        let prev = &window[0];
        let curr = &window[1];
        let ordering = prev
            .tlv_type
            .cmp(&curr.tlv_type)
            .then_with(|| prev.value.len().cmp(&curr.value.len()))
            .then_with(|| prev.value.cmp(&curr.value));
        if ordering == std::cmp::Ordering::Greater {
            return Err(LsNlriError::TlvOrdering {
                prev_type: prev.tlv_type,
                prev_len: prev.value.len(),
                curr_type: curr.tlv_type,
                curr_len: curr.value.len(),
            });
        }
    }
    Ok(())
}

/// At most one instance of each sub-TLV type (RFC 9552 Section 5.2.1.4).
fn validate_unique_tlv(tlvs: &[LsTlv]) -> Result<(), LsNlriError> {
    let mut seen_types = Vec::new();
    for tlv in tlvs {
        if seen_types.contains(&tlv.tlv_type) {
            return Err(LsNlriError::DuplicateSubTlv(tlv.tlv_type));
        }
        seen_types.push(tlv.tlv_type);
    }
    Ok(())
}

/// Parse Node Descriptor sub-TLVs (RFC 9552 Section 5.2.1.4).
fn parse_node_descriptor(bytes: &[u8]) -> Result<NodeDescriptor, LsNlriError> {
    let sub_tlvs = parse_tlv_list(bytes)?;

    validate_unique_tlv(&sub_tlvs)?;

    let mut descriptor = NodeDescriptor::default();

    for tlv in sub_tlvs {
        match LsTlvType::from_u16(tlv.tlv_type) {
            Some(LsTlvType::AutonomousSystem) => {
                if tlv.value.len() != 4 {
                    return Err(LsNlriError::InvalidLength {
                        name: "AS sub-TLV",
                        actual: tlv.value.len(),
                        expected: 4,
                    });
                }
                descriptor.as_number = Some(u32::from_be_bytes([
                    tlv.value[0],
                    tlv.value[1],
                    tlv.value[2],
                    tlv.value[3],
                ]));
            }
            Some(LsTlvType::BgpLsId) => {
                if tlv.value.len() != 4 {
                    return Err(LsNlriError::InvalidLength {
                        name: "BGP-LS ID sub-TLV",
                        actual: tlv.value.len(),
                        expected: 4,
                    });
                }
                descriptor.bgp_ls_id = Some(u32::from_be_bytes([
                    tlv.value[0],
                    tlv.value[1],
                    tlv.value[2],
                    tlv.value[3],
                ]));
            }
            Some(LsTlvType::OspfAreaId) => {
                if tlv.value.len() != 4 {
                    return Err(LsNlriError::InvalidLength {
                        name: "OSPF Area-ID sub-TLV",
                        actual: tlv.value.len(),
                        expected: 4,
                    });
                }
                descriptor.ospf_area_id = Some(u32::from_be_bytes([
                    tlv.value[0],
                    tlv.value[1],
                    tlv.value[2],
                    tlv.value[3],
                ]));
            }
            Some(LsTlvType::IgpRouterId) => {
                descriptor.igp_router_id = Some(tlv.value);
            }
            _ => {
                descriptor.unknown.push(tlv);
            }
        }
    }

    Ok(descriptor)
}

/// Parse Link Descriptor TLVs (RFC 9552 Table 4).
fn parse_link_descriptor(
    tlv_map: &HashMap<u16, Vec<LsTlv>>,
) -> Result<LinkDescriptor, LsNlriError> {
    let mut desc = LinkDescriptor::default();

    if let Some(tlvs) = tlv_map.get(&(LsTlvType::LinkLocalRemoteId as u16)) {
        let val = &tlvs[0].value;
        if val.len() != 8 {
            return Err(LsNlriError::InvalidLength {
                name: "Link Local/Remote ID",
                actual: val.len(),
                expected: 8,
            });
        }
        desc.link_local_id = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]));
        desc.link_remote_id = Some(u32::from_be_bytes([val[4], val[5], val[6], val[7]]));
    }
    if let Some(tlvs) = tlv_map.get(&(LsTlvType::Ipv4InterfaceAddr as u16)) {
        let val = &tlvs[0].value;
        if val.len() != 4 {
            return Err(LsNlriError::InvalidLength {
                name: "IPv4 Interface Address",
                actual: val.len(),
                expected: 4,
            });
        }
        desc.ipv4_interface_addr = Some([val[0], val[1], val[2], val[3]]);
    }
    if let Some(tlvs) = tlv_map.get(&(LsTlvType::Ipv4NeighborAddr as u16)) {
        let val = &tlvs[0].value;
        if val.len() != 4 {
            return Err(LsNlriError::InvalidLength {
                name: "IPv4 Neighbor Address",
                actual: val.len(),
                expected: 4,
            });
        }
        desc.ipv4_neighbor_addr = Some([val[0], val[1], val[2], val[3]]);
    }
    if let Some(tlvs) = tlv_map.get(&(LsTlvType::Ipv6InterfaceAddr as u16)) {
        let val = &tlvs[0].value;
        if val.len() != 16 {
            return Err(LsNlriError::InvalidLength {
                name: "IPv6 Interface Address",
                actual: val.len(),
                expected: 16,
            });
        }
        let mut addr = [0u8; 16];
        addr.copy_from_slice(val);
        desc.ipv6_interface_addr = Some(addr);
    }
    if let Some(tlvs) = tlv_map.get(&(LsTlvType::Ipv6NeighborAddr as u16)) {
        let val = &tlvs[0].value;
        if val.len() != 16 {
            return Err(LsNlriError::InvalidLength {
                name: "IPv6 Neighbor Address",
                actual: val.len(),
                expected: 16,
            });
        }
        let mut addr = [0u8; 16];
        addr.copy_from_slice(val);
        desc.ipv6_neighbor_addr = Some(addr);
    }
    if let Some(tlvs) = tlv_map.get(&(LsTlvType::MultiTopologyId as u16)) {
        let val = &tlvs[0].value;
        if val.len() % 2 != 0 {
            return Err(LsNlriError::UnalignedLength {
                name: "Multi-Topology ID",
                actual: val.len(),
                alignment: 2,
            });
        }
        desc.multi_topology_id = Some(
            val.chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect(),
        );
    }

    // Preserve unknown TLVs
    for (&tlv_type, tlvs) in tlv_map {
        if LsTlvType::from_u16(tlv_type).is_none() {
            desc.unknown.extend(tlvs.iter().cloned());
        }
    }

    Ok(desc)
}

/// Parse Prefix Descriptor TLVs (RFC 9552 Table 5).
fn parse_prefix_descriptor(
    tlv_map: &HashMap<u16, Vec<LsTlv>>,
) -> Result<PrefixDescriptor, LsNlriError> {
    let mut desc = PrefixDescriptor::default();

    if let Some(tlvs) = tlv_map.get(&(LsTlvType::MultiTopologyId as u16)) {
        let val = &tlvs[0].value;
        if val.len() % 2 != 0 {
            return Err(LsNlriError::UnalignedLength {
                name: "Multi-Topology ID",
                actual: val.len(),
                alignment: 2,
            });
        }
        desc.multi_topology_id = Some(
            val.chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect(),
        );
    }
    if let Some(tlvs) = tlv_map.get(&(LsTlvType::OspfRouteType as u16)) {
        let val = &tlvs[0].value;
        if val.len() != 1 {
            return Err(LsNlriError::InvalidLength {
                name: "OSPF Route Type",
                actual: val.len(),
                expected: 1,
            });
        }
        desc.ospf_route_type = Some(val[0]);
    }
    if let Some(tlvs) = tlv_map.get(&(LsTlvType::IpReachabilityInfo as u16)) {
        desc.ip_reachability = Some(tlvs[0].value.clone());
    }

    for (&tlv_type, tlvs) in tlv_map {
        if LsTlvType::from_u16(tlv_type).is_none() {
            desc.unknown.extend(tlvs.iter().cloned());
        }
    }

    Ok(desc)
}

/// Encode a list of BGP-LS NLRI entries to wire bytes for MP_REACH/MP_UNREACH.
/// For VPN NLRIs with a Route Distinguisher, the RD is prepended to the body
/// and included in the Total NLRI Length.
pub fn write_ls_nlri_list(entries: &[LsNlri]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in entries {
        let rd_len = if entry.route_distinguisher.is_some() {
            RD_LEN
        } else {
            0
        };
        bytes.extend_from_slice(&entry.nlri_type.to_be_bytes());
        bytes.extend_from_slice(&((entry.raw.len() + rd_len) as u16).to_be_bytes());
        if let Some(rd) = &entry.route_distinguisher {
            bytes.extend_from_slice(rd);
        }
        bytes.extend_from_slice(&entry.raw);
    }
    bytes
}

/// Build an LsNlri from structured data (for gRPC injection / tests).
/// Encodes the body to set the `raw` field. Pass a Route Distinguisher for SAFI 72.
pub fn build_ls_nlri(
    nlri_type: LsNlriType,
    protocol_id: LsProtocolId,
    identifier: u64,
    descriptors: LsDescriptors,
    route_distinguisher: Option<RouteDistinguisher>,
) -> LsNlri {
    let protocol_id = protocol_id as u8;
    let raw = encode_ls_nlri_body(protocol_id, identifier, &descriptors);
    LsNlri {
        nlri_type: nlri_type as u16,
        raw,
        body: Some(LsNlriBody {
            protocol_id,
            identifier,
            descriptors,
        }),
        route_distinguisher,
    }
}

/// Encode the NLRI body: Protocol-ID (1) + Identifier (8) + descriptor TLVs.
pub(crate) fn encode_ls_nlri_body(
    protocol_id: u8,
    identifier: u64,
    descriptors: &LsDescriptors,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(protocol_id);
    bytes.extend_from_slice(&identifier.to_be_bytes());

    match descriptors {
        LsDescriptors::Node { local_node } => {
            write_node_descriptor_tlv(&mut bytes, LsTlvType::LocalNodeDescriptors, local_node);
        }
        LsDescriptors::Link {
            local_node,
            remote_node,
            link_descriptors,
        } => {
            write_node_descriptor_tlv(&mut bytes, LsTlvType::LocalNodeDescriptors, local_node);
            write_node_descriptor_tlv(&mut bytes, LsTlvType::RemoteNodeDescriptors, remote_node);
            write_link_descriptor_tlvs(&mut bytes, link_descriptors);
        }
        LsDescriptors::PrefixV4 {
            local_node,
            prefix_descriptors,
        }
        | LsDescriptors::PrefixV6 {
            local_node,
            prefix_descriptors,
        } => {
            write_node_descriptor_tlv(&mut bytes, LsTlvType::LocalNodeDescriptors, local_node);
            write_prefix_descriptor_tlvs(&mut bytes, prefix_descriptors);
        }
    }

    bytes
}

/// Encode a NodeDescriptor into sub-TLVs and wrap in a container TLV (type 256/257).
fn write_node_descriptor_tlv(buf: &mut Vec<u8>, descriptor_type: LsTlvType, desc: &NodeDescriptor) {
    let mut inner = Vec::new();

    // Sub-TLVs must be in ascending order by type
    if let Some(asn) = desc.as_number {
        write_tlv(&mut inner, LsTlvType::AutonomousSystem, &asn.to_be_bytes());
    }
    if let Some(bgp_ls_id) = desc.bgp_ls_id {
        write_tlv(&mut inner, LsTlvType::BgpLsId, &bgp_ls_id.to_be_bytes());
    }
    if let Some(area_id) = desc.ospf_area_id {
        write_tlv(&mut inner, LsTlvType::OspfAreaId, &area_id.to_be_bytes());
    }
    if let Some(ref router_id) = desc.igp_router_id {
        write_tlv(&mut inner, LsTlvType::IgpRouterId, router_id);
    }
    for unknown_tlv in &desc.unknown {
        write_tlv_raw(&mut inner, unknown_tlv.tlv_type, &unknown_tlv.value);
    }

    write_tlv(buf, descriptor_type, &inner);
}

/// Write a single TLV with a known type: Type (2) + Length (2) + Value.
fn write_tlv(buf: &mut Vec<u8>, tlv_type: LsTlvType, value: &[u8]) {
    write_tlv_raw(buf, tlv_type as u16, value);
}

/// Write a single TLV with a raw u16 type code (for unknown/opaque TLVs).
fn write_tlv_raw(buf: &mut Vec<u8>, tlv_type: u16, value: &[u8]) {
    buf.extend_from_slice(&tlv_type.to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
}

/// Encode LinkDescriptor fields as TLVs in ascending type order.
fn write_link_descriptor_tlvs(buf: &mut Vec<u8>, desc: &LinkDescriptor) {
    if let (Some(local_id), Some(remote_id)) = (desc.link_local_id, desc.link_remote_id) {
        let mut val = Vec::with_capacity(8);
        val.extend_from_slice(&local_id.to_be_bytes());
        val.extend_from_slice(&remote_id.to_be_bytes());
        write_tlv(buf, LsTlvType::LinkLocalRemoteId, &val);
    }
    if let Some(addr) = desc.ipv4_interface_addr {
        write_tlv(buf, LsTlvType::Ipv4InterfaceAddr, &addr);
    }
    if let Some(addr) = desc.ipv4_neighbor_addr {
        write_tlv(buf, LsTlvType::Ipv4NeighborAddr, &addr);
    }
    if let Some(addr) = desc.ipv6_interface_addr {
        write_tlv(buf, LsTlvType::Ipv6InterfaceAddr, &addr);
    }
    if let Some(addr) = desc.ipv6_neighbor_addr {
        write_tlv(buf, LsTlvType::Ipv6NeighborAddr, &addr);
    }
    if let Some(ref mt_ids) = desc.multi_topology_id {
        let val: Vec<u8> = mt_ids.iter().flat_map(|id| id.to_be_bytes()).collect();
        write_tlv(buf, LsTlvType::MultiTopologyId, &val);
    }
    for unknown_tlv in &desc.unknown {
        write_tlv_raw(buf, unknown_tlv.tlv_type, &unknown_tlv.value);
    }
}

/// Encode PrefixDescriptor fields as TLVs in ascending type order.
fn write_prefix_descriptor_tlvs(buf: &mut Vec<u8>, desc: &PrefixDescriptor) {
    if let Some(ref mt_ids) = desc.multi_topology_id {
        let val: Vec<u8> = mt_ids.iter().flat_map(|id| id.to_be_bytes()).collect();
        write_tlv(buf, LsTlvType::MultiTopologyId, &val);
    }
    if let Some(route_type) = desc.ospf_route_type {
        write_tlv(buf, LsTlvType::OspfRouteType, &[route_type]);
    }
    if let Some(ref reachability) = desc.ip_reachability {
        write_tlv(buf, LsTlvType::IpReachabilityInfo, reachability);
    }
    for unknown_tlv in &desc.unknown {
        write_tlv_raw(buf, unknown_tlv.tlv_type, &unknown_tlv.value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_node(asn: u32, router_id: &[u8]) -> NodeDescriptor {
        NodeDescriptor {
            as_number: Some(asn),
            igp_router_id: Some(router_id.to_vec()),
            ..Default::default()
        }
    }

    fn unwrap_body(entry: &LsNlri) -> &LsNlriBody {
        entry.body.as_ref().expect("expected parsed body")
    }

    fn round_trip(entries: &[LsNlri]) -> Vec<LsNlri> {
        let wire = write_ls_nlri_list(entries);
        parse_ls_nlri_list(&wire, Safi::LinkState).expect("round-trip parse failed")
    }

    /// Wrap raw NLRI body bytes in the wire framing for parse_ls_nlri_list.
    fn wrap_nlri_raw(nlri_type: LsNlriType, body: Vec<u8>) -> Vec<u8> {
        let mut wire = Vec::new();
        wire.extend_from_slice(&(nlri_type as u16).to_be_bytes());
        wire.extend_from_slice(&(body.len() as u16).to_be_bytes());
        wire.extend_from_slice(&body);
        wire
    }

    /// Valid Node Descriptor with AS 65001 for use in Link/Prefix NLRI bodies.
    fn valid_local_node_tlv() -> Vec<u8> {
        let mut inner = Vec::new();
        write_tlv(
            &mut inner,
            LsTlvType::AutonomousSystem,
            &65001u32.to_be_bytes(),
        );
        let mut buf = Vec::new();
        write_tlv(&mut buf, LsTlvType::LocalNodeDescriptors, &inner);
        buf
    }

    /// Build a Node NLRI body with a single sub-TLV in LocalNodeDescriptors.
    fn node_body_with_subtlv(tlv_type: LsTlvType, value: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(LsProtocolId::Direct as u8);
        body.extend_from_slice(&1u64.to_be_bytes());
        let mut inner = Vec::new();
        write_tlv(&mut inner, tlv_type, value);
        write_tlv(&mut body, LsTlvType::LocalNodeDescriptors, &inner);
        body
    }

    /// Build a Link NLRI body with valid nodes + one extra link descriptor TLV.
    fn link_body_with_descriptor(tlv_type: LsTlvType, value: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(LsProtocolId::OspfV2 as u8);
        body.extend_from_slice(&1u64.to_be_bytes());
        body.extend_from_slice(&valid_local_node_tlv());
        // Remote node (type 257, must come after 256)
        let mut remote_inner = Vec::new();
        write_tlv(
            &mut remote_inner,
            LsTlvType::AutonomousSystem,
            &65002u32.to_be_bytes(),
        );
        write_tlv(&mut body, LsTlvType::RemoteNodeDescriptors, &remote_inner);
        write_tlv(&mut body, tlv_type, value);
        body
    }

    /// Build a PrefixV4 NLRI body with valid node + one extra prefix descriptor TLV.
    fn prefix_body_with_descriptor(tlv_type: LsTlvType, value: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(LsProtocolId::OspfV2 as u8);
        body.extend_from_slice(&1u64.to_be_bytes());
        body.extend_from_slice(&valid_local_node_tlv());
        write_tlv(&mut body, tlv_type, value);
        body
    }

    #[test]
    fn test_round_trip_all_nlri_types() {
        let cases: Vec<(&str, LsNlriType, LsProtocolId, u64, LsDescriptors)> = vec![
            (
                "node",
                LsNlriType::Node,
                LsProtocolId::Direct,
                100,
                LsDescriptors::Node {
                    local_node: NodeDescriptor {
                        as_number: Some(65001),
                        bgp_ls_id: Some(0),
                        ospf_area_id: Some(1),
                        igp_router_id: Some(vec![10, 0, 0, 1]),
                        unknown: vec![],
                    },
                },
            ),
            (
                "link all fields",
                LsNlriType::Link,
                LsProtocolId::OspfV2,
                200,
                LsDescriptors::Link {
                    local_node: sample_node(65001, &[10, 0, 0, 1]),
                    remote_node: sample_node(65002, &[10, 0, 0, 2]),
                    link_descriptors: LinkDescriptor {
                        link_local_id: Some(100),
                        link_remote_id: Some(200),
                        ipv4_interface_addr: Some([192, 168, 1, 1]),
                        ipv4_neighbor_addr: Some([192, 168, 1, 2]),
                        ipv6_interface_addr: Some([
                            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                        ]),
                        ipv6_neighbor_addr: Some([
                            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                        ]),
                        multi_topology_id: Some(vec![0, 2]),
                        unknown: vec![],
                    },
                },
            ),
            (
                "link only local/remote id",
                LsNlriType::Link,
                LsProtocolId::OspfV2,
                201,
                LsDescriptors::Link {
                    local_node: sample_node(65001, &[10, 0, 0, 1]),
                    remote_node: sample_node(65002, &[10, 0, 0, 2]),
                    link_descriptors: LinkDescriptor {
                        link_local_id: Some(100),
                        link_remote_id: Some(200),
                        ..Default::default()
                    },
                },
            ),
            (
                "link only ipv4 addrs",
                LsNlriType::Link,
                LsProtocolId::OspfV2,
                202,
                LsDescriptors::Link {
                    local_node: sample_node(65001, &[10, 0, 0, 1]),
                    remote_node: sample_node(65002, &[10, 0, 0, 2]),
                    link_descriptors: LinkDescriptor {
                        ipv4_interface_addr: Some([192, 168, 1, 1]),
                        ipv4_neighbor_addr: Some([192, 168, 1, 2]),
                        ..Default::default()
                    },
                },
            ),
            (
                "link only ipv6 addrs",
                LsNlriType::Link,
                LsProtocolId::OspfV2,
                203,
                LsDescriptors::Link {
                    local_node: sample_node(65001, &[10, 0, 0, 1]),
                    remote_node: sample_node(65002, &[10, 0, 0, 2]),
                    link_descriptors: LinkDescriptor {
                        ipv6_interface_addr: Some([
                            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                        ]),
                        ipv6_neighbor_addr: Some([
                            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                        ]),
                        ..Default::default()
                    },
                },
            ),
            (
                "link only multi-topology",
                LsNlriType::Link,
                LsProtocolId::OspfV2,
                204,
                LsDescriptors::Link {
                    local_node: sample_node(65001, &[10, 0, 0, 1]),
                    remote_node: sample_node(65002, &[10, 0, 0, 2]),
                    link_descriptors: LinkDescriptor {
                        multi_topology_id: Some(vec![0, 2]),
                        ..Default::default()
                    },
                },
            ),
            (
                "link empty descriptors",
                LsNlriType::Link,
                LsProtocolId::OspfV2,
                205,
                LsDescriptors::Link {
                    local_node: sample_node(65001, &[10, 0, 0, 1]),
                    remote_node: sample_node(65002, &[10, 0, 0, 2]),
                    link_descriptors: LinkDescriptor::default(),
                },
            ),
            (
                "prefix-v4 all fields",
                LsNlriType::PrefixV4,
                LsProtocolId::OspfV2,
                300,
                LsDescriptors::PrefixV4 {
                    local_node: sample_node(65001, &[10, 0, 0, 1]),
                    prefix_descriptors: PrefixDescriptor {
                        multi_topology_id: Some(vec![0]),
                        ospf_route_type: Some(1),
                        ip_reachability: Some(vec![24, 192, 168, 1]),
                        unknown: vec![],
                    },
                },
            ),
            (
                "prefix-v4 only ospf route type",
                LsNlriType::PrefixV4,
                LsProtocolId::OspfV2,
                301,
                LsDescriptors::PrefixV4 {
                    local_node: sample_node(65001, &[10, 0, 0, 1]),
                    prefix_descriptors: PrefixDescriptor {
                        ospf_route_type: Some(3),
                        ..Default::default()
                    },
                },
            ),
            (
                "prefix-v4 only multi-topology",
                LsNlriType::PrefixV4,
                LsProtocolId::OspfV2,
                302,
                LsDescriptors::PrefixV4 {
                    local_node: sample_node(65001, &[10, 0, 0, 1]),
                    prefix_descriptors: PrefixDescriptor {
                        multi_topology_id: Some(vec![0, 1, 2]),
                        ..Default::default()
                    },
                },
            ),
            (
                "prefix-v6",
                LsNlriType::PrefixV6,
                LsProtocolId::IsIsL2,
                400,
                LsDescriptors::PrefixV6 {
                    local_node: sample_node(65001, &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1]),
                    prefix_descriptors: PrefixDescriptor {
                        ip_reachability: Some(vec![48, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]),
                        ..Default::default()
                    },
                },
            ),
        ];

        for (name, nlri_type, protocol_id, identifier, descriptors) in cases {
            let entry = build_ls_nlri(
                nlri_type,
                protocol_id,
                identifier,
                descriptors.clone(),
                None,
            );
            let parsed = round_trip(std::slice::from_ref(&entry));
            let body = unwrap_body(&parsed[0]);
            assert_eq!(parsed[0].nlri_type, nlri_type as u16, "{name}: nlri_type");
            assert_eq!(body.protocol_id(), Some(protocol_id), "{name}: protocol_id");
            assert_eq!(body.identifier, identifier, "{name}: identifier");
            assert_eq!(body.descriptors, descriptors, "{name}: descriptors");
        }
    }

    #[test]
    fn test_unknown_nlri_type_preserved() {
        let opaque = LsNlri {
            nlri_type: 99,
            raw: vec![0xDE, 0xAD, 0xBE, 0xEF],
            body: None,
            route_distinguisher: None,
        };
        let parsed = round_trip(std::slice::from_ref(&opaque));
        assert_eq!(parsed[0].nlri_type, 99);
        assert_eq!(parsed[0].raw, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(parsed[0].body.is_none());
    }

    #[test]
    fn test_unknown_node_subtlv_preserved() {
        let entry = build_ls_nlri(
            LsNlriType::Node,
            LsProtocolId::Direct,
            1,
            LsDescriptors::Node {
                local_node: NodeDescriptor {
                    as_number: Some(65001),
                    unknown: vec![LsTlv {
                        tlv_type: 999,
                        value: vec![0xCA, 0xFE],
                    }],
                    ..Default::default()
                },
            },
            None,
        );
        let parsed = round_trip(std::slice::from_ref(&entry));
        match &unwrap_body(&parsed[0]).descriptors {
            LsDescriptors::Node { local_node } => {
                assert_eq!(local_node.unknown.len(), 1);
                assert_eq!(local_node.unknown[0].tlv_type, 999);
            }
            _ => panic!("expected Node"),
        }
    }

    #[test]
    fn test_unknown_link_descriptor_tlv_preserved() {
        let entry = build_ls_nlri(
            LsNlriType::Link,
            LsProtocolId::OspfV2,
            1,
            LsDescriptors::Link {
                local_node: sample_node(65001, &[10, 0, 0, 1]),
                remote_node: sample_node(65002, &[10, 0, 0, 2]),
                link_descriptors: LinkDescriptor {
                    unknown: vec![LsTlv {
                        tlv_type: 9999,
                        value: vec![0x01, 0x02, 0x03],
                    }],
                    ..Default::default()
                },
            },
            None,
        );
        let parsed = round_trip(std::slice::from_ref(&entry));
        match &unwrap_body(&parsed[0]).descriptors {
            LsDescriptors::Link {
                link_descriptors, ..
            } => {
                assert_eq!(link_descriptors.unknown.len(), 1);
                assert_eq!(link_descriptors.unknown[0].tlv_type, 9999);
            }
            _ => panic!("expected Link"),
        }
    }

    #[test]
    fn test_multiple_nlri_types_in_one_list() {
        let entries = vec![
            build_ls_nlri(
                LsNlriType::Node,
                LsProtocolId::Direct,
                1,
                LsDescriptors::Node {
                    local_node: sample_node(65001, &[10, 0, 0, 1]),
                },
                None,
            ),
            build_ls_nlri(
                LsNlriType::PrefixV4,
                LsProtocolId::OspfV2,
                2,
                LsDescriptors::PrefixV4 {
                    local_node: sample_node(65001, &[10, 0, 0, 1]),
                    prefix_descriptors: PrefixDescriptor {
                        ip_reachability: Some(vec![24, 10, 0, 1]),
                        ..Default::default()
                    },
                },
                None,
            ),
            LsNlri {
                nlri_type: 42,
                raw: vec![0xFF],
                body: None,
                route_distinguisher: None,
            },
        ];

        let parsed = round_trip(&entries);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].nlri_type, LsNlriType::Node as u16);
        assert_eq!(parsed[1].nlri_type, LsNlriType::PrefixV4 as u16);
        assert_eq!(parsed[2].nlri_type, 42);
        assert!(parsed[2].body.is_none());
    }

    #[test]
    fn test_tlv_ordering() {
        let cases = vec![
            (
                "type descending",
                500,
                vec![0x01, 0x02, 0x03],
                400,
                vec![0x01],
                true,
            ),
            (
                "same type, length descending",
                500,
                vec![0x01, 0x02, 0x03],
                500,
                vec![0x01],
                true,
            ),
            (
                "same type+len, value descending",
                500,
                vec![0x02],
                500,
                vec![0x01],
                true,
            ),
            ("type ascending", 400, vec![0x01], 500, vec![0x01], false),
            (
                "same type, length ascending",
                500,
                vec![0x01],
                500,
                vec![0x01, 0x02],
                false,
            ),
            (
                "same type+len, value ascending",
                500,
                vec![0x01],
                500,
                vec![0x02],
                false,
            ),
            ("identical (equal)", 500, vec![0xAA], 500, vec![0xAA], false),
        ];

        for (name, t1, v1, t2, v2, expect_err) in cases {
            let tlvs = vec![
                LsTlv {
                    tlv_type: t1,
                    value: v1,
                },
                LsTlv {
                    tlv_type: t2,
                    value: v2,
                },
            ];
            let result = validate_tlv_ordering(&tlvs);
            assert_eq!(result.is_err(), expect_err, "case: {name}");
        }
    }

    #[test]
    fn test_tlv_ordering_violation_other_nlris_survive() {
        // Bad NLRI: 257 before 256
        let mut bad_body = Vec::new();
        bad_body.push(LsProtocolId::OspfV2 as u8);
        bad_body.extend_from_slice(&1u64.to_be_bytes());
        let mut local = Vec::new();
        write_tlv(
            &mut local,
            LsTlvType::AutonomousSystem,
            &65001u32.to_be_bytes(),
        );
        let mut remote = Vec::new();
        write_tlv(
            &mut remote,
            LsTlvType::AutonomousSystem,
            &65002u32.to_be_bytes(),
        );
        write_tlv(&mut bad_body, LsTlvType::RemoteNodeDescriptors, &remote);
        write_tlv(&mut bad_body, LsTlvType::LocalNodeDescriptors, &local);

        let good_entry = build_ls_nlri(
            LsNlriType::Node,
            LsProtocolId::Direct,
            2,
            LsDescriptors::Node {
                local_node: sample_node(65002, &[10, 0, 0, 2]),
            },
            None,
        );

        let mut wire = Vec::new();
        wire.extend_from_slice(&(LsNlriType::Link as u16).to_be_bytes());
        wire.extend_from_slice(&(bad_body.len() as u16).to_be_bytes());
        wire.extend_from_slice(&bad_body);
        wire.extend_from_slice(&(LsNlriType::Node as u16).to_be_bytes());
        wire.extend_from_slice(&(good_entry.raw.len() as u16).to_be_bytes());
        wire.extend_from_slice(&good_entry.raw);

        let parsed = parse_ls_nlri_list(&wire, Safi::LinkState).expect("list-level should succeed");
        assert_eq!(parsed.len(), 2, "both NLRIs preserved");
        assert!(parsed[0].body.is_none(), "bad NLRI not parsed");
        assert_eq!(unwrap_body(&parsed[1]).identifier, 2);
    }

    #[test]
    fn test_malformed_nlri_discarded() {
        // (name, nlri_type, body)
        let cases: Vec<(&str, LsNlriType, Vec<u8>)> = vec![
            (
                "body too short",
                LsNlriType::Node,
                vec![LsProtocolId::Direct as u8, 0, 0, 0], // 4 bytes < 9
            ),
            ("missing local node descriptor", LsNlriType::Node, {
                let mut body = Vec::new();
                body.push(LsProtocolId::Direct as u8);
                body.extend_from_slice(&1u64.to_be_bytes());
                body
            }),
            ("duplicate node descriptor sub-TLV", LsNlriType::Node, {
                let mut body = Vec::new();
                body.push(LsProtocolId::Direct as u8);
                body.extend_from_slice(&1u64.to_be_bytes());
                let mut inner = Vec::new();
                write_tlv(
                    &mut inner,
                    LsTlvType::AutonomousSystem,
                    &65001u32.to_be_bytes(),
                );
                write_tlv(
                    &mut inner,
                    LsTlvType::AutonomousSystem,
                    &65002u32.to_be_bytes(),
                );
                write_tlv(&mut body, LsTlvType::LocalNodeDescriptors, &inner);
                body
            }),
            (
                "AS sub-TLV wrong length",
                LsNlriType::Node,
                node_body_with_subtlv(LsTlvType::AutonomousSystem, &[0x01, 0x02, 0x03]),
            ),
            (
                "BGP-LS ID sub-TLV wrong length",
                LsNlriType::Node,
                node_body_with_subtlv(LsTlvType::BgpLsId, &[0x01, 0x02]),
            ),
            (
                "OSPF Area-ID sub-TLV wrong length",
                LsNlriType::Node,
                node_body_with_subtlv(LsTlvType::OspfAreaId, &[0x01]),
            ),
            (
                "Link Local/Remote ID wrong length",
                LsNlriType::Link,
                link_body_with_descriptor(LsTlvType::LinkLocalRemoteId, &[0x01; 4]),
            ),
            (
                "IPv4 Interface Address wrong length",
                LsNlriType::Link,
                link_body_with_descriptor(LsTlvType::Ipv4InterfaceAddr, &[0x01; 3]),
            ),
            (
                "IPv4 Neighbor Address wrong length",
                LsNlriType::Link,
                link_body_with_descriptor(LsTlvType::Ipv4NeighborAddr, &[0x01; 5]),
            ),
            (
                "IPv6 Interface Address wrong length",
                LsNlriType::Link,
                link_body_with_descriptor(LsTlvType::Ipv6InterfaceAddr, &[0x01; 15]),
            ),
            (
                "IPv6 Neighbor Address wrong length",
                LsNlriType::Link,
                link_body_with_descriptor(LsTlvType::Ipv6NeighborAddr, &[0x01; 17]),
            ),
            (
                "Link Multi-Topology ID odd length",
                LsNlriType::Link,
                link_body_with_descriptor(LsTlvType::MultiTopologyId, &[0x01; 3]),
            ),
            (
                "Prefix Multi-Topology ID odd length",
                LsNlriType::PrefixV4,
                prefix_body_with_descriptor(LsTlvType::MultiTopologyId, &[0x01; 5]),
            ),
            (
                "OSPF Route Type wrong length",
                LsNlriType::PrefixV4,
                prefix_body_with_descriptor(LsTlvType::OspfRouteType, &[0x01, 0x02]),
            ),
        ];

        for (name, nlri_type, body) in cases {
            let wire = wrap_nlri_raw(nlri_type, body);
            let parsed = parse_ls_nlri_list(&wire, Safi::LinkState).unwrap_or_else(|_| {
                panic!("{name}: list-level parse should succeed");
            });
            assert_eq!(parsed.len(), 1, "{name}: NLRI preserved for propagation");
            assert!(parsed[0].body.is_none(), "{name}: body should be None");
        }
    }

    #[test]
    fn test_unrecoverable_parse_errors() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty input", vec![]),
            ("truncated header (2 bytes)", vec![0x00, 0x01]),
            ("NLRI length exceeds available bytes", {
                let mut wire = Vec::new();
                wire.extend_from_slice(&1u16.to_be_bytes());
                wire.extend_from_slice(&100u16.to_be_bytes());
                wire.extend_from_slice(&[0u8; 10]);
                wire
            }),
        ];

        for (name, wire) in cases {
            let result = parse_ls_nlri_list(&wire, Safi::LinkState);
            if name == "empty input" {
                assert!(result.expect("empty should be ok").is_empty(), "{name}");
            } else {
                assert!(result.is_err(), "{name}: should return error");
            }
        }
    }
}
