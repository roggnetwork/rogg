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

use super::bgpls_attr::parse_ls_attr;
use super::bgpls_nlri::{parse_ls_nlri_list, write_ls_nlri_list, RD_LEN};
use super::msg::MessageFormat;
use super::msg_notification::{BgpError, UpdateMessageError};
use super::msg_update::{TOTAL_ATTR_LENGTH_SIZE, WITHDRAWN_ROUTES_LENGTH_SIZE};
use super::msg_update_types::{
    attr_type_code, malformed_attr_action, Aggregator, AsPath, AsPathSegment, AsPathSegmentType,
    AttrType, LargeCommunity, MpReachNlri, MpUnreachNlri, NextHopAddr, Nlri, Origin, PathAttrError,
    PathAttrFlag, PathAttrValue, PathAttribute,
};
use super::multiprotocol::{Afi, AfiSafi, Safi};
use super::utils::{
    is_valid_unicast_ipv4, parse_nlri_list, parse_nlri_v6_list, read_u32, ParserError,
};
use crate::log::warn;
use crate::net::IpNetwork;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) fn validate_attribute_flags(
    flags: u8,
    attr_type: &AttrType,
    attr_type_code: u8,
    attr_len: u16,
) -> Result<(), ParserError> {
    let expected = attr_type.expected_flags();
    let mask = PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE;

    // Validate Optional and Transitive bits match the attribute type
    if (flags & mask) != expected {
        let mut data = vec![flags, attr_type_code];
        if flags & PathAttrFlag::EXTENDED_LENGTH != 0 {
            data.extend_from_slice(&attr_len.to_be_bytes());
        } else {
            data.push(attr_len as u8);
        }
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError),
            data,
        });
    }

    // Partial bit must be 0 for well-known attributes
    if attr_type.is_well_known() && (flags & PathAttrFlag::PARTIAL != 0) {
        let mut data = vec![flags, attr_type_code];
        if flags & PathAttrFlag::EXTENDED_LENGTH != 0 {
            data.extend_from_slice(&attr_len.to_be_bytes());
        } else {
            data.push(attr_len as u8);
        }
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::AttributeFlagsError),
            data,
        });
    }

    Ok(())
}

pub(super) fn validate_attribute_length(
    attr_type: &AttrType,
    attr_len: u16,
    attr_bytes: &[u8],
    use_4byte_asn: bool,
) -> Result<(), ParserError> {
    let valid = match attr_type {
        AttrType::Origin => attr_len == 1,
        AttrType::NextHop => attr_len == 4, // Only IPv4 per RFC 4271
        AttrType::MultiExtiDisc => attr_len == 4,
        AttrType::LocalPref => attr_len == 4,
        AttrType::AtomicAggregate => attr_len == 0,
        // RFC 7606 Section 7.7: 6 bytes without 4-byte ASN, 8 bytes with
        AttrType::Aggregator if use_4byte_asn => attr_len == 8,
        AttrType::Aggregator => attr_len == 6,
        AttrType::AsPath => true, // Variable length
        AttrType::Communities => attr_len > 0 && attr_len.is_multiple_of(4), // RFC 7606 Section 7.8
        // RFC 4456: ORIGINATOR_ID is 4 bytes (IPv4 address)
        AttrType::OriginatorId => attr_len == 4,
        // RFC 7606 Section 7.10: non-zero multiple of 4
        AttrType::ClusterList => attr_len > 0 && attr_len.is_multiple_of(4),
        AttrType::MpReachNlri => true,   // Variable length
        AttrType::MpUnreachNlri => true, // Variable length
        AttrType::ExtendedCommunities => attr_len > 0 && attr_len.is_multiple_of(8), // RFC 7606 Section 7.14
        AttrType::As4Path => true,       // Variable length (RFC 6793)
        AttrType::As4Aggregator => true, // Variable length - validation in parser (RFC 6793)
        AttrType::LinkState => true,     // Variable length (RFC 9552)
        AttrType::LargeCommunities => attr_len > 0 && attr_len.is_multiple_of(12), // Non-zero multiple of 12
    };

    if !valid {
        // RFC 4271 Section 6.3: for recognized optional attributes, use OptionalAttributeError
        let error = if attr_type.is_optional() {
            UpdateMessageError::OptionalAttributeError
        } else {
            UpdateMessageError::AttributeLengthError
        };
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(error),
            data: attr_bytes.to_vec(),
        });
    }

    Ok(())
}

pub(super) fn validate_update_message_lengths(
    withdrawn_routes_len: usize,
    total_path_attributes_len: usize,
    body_length: usize,
) -> Result<(), ParserError> {
    // RFC 4271 Section 6.3: If Withdrawn Routes Length + Total Attribute Length + 23
    // exceeds the message Length, then Error Subcode MUST be set to Malformed Attribute List.
    // Since we work with body (message_length - 19), check becomes:
    // withdrawn_routes_len + total_path_attributes_len + 4 > body_length
    let length_fields_size = WITHDRAWN_ROUTES_LENGTH_SIZE + TOTAL_ATTR_LENGTH_SIZE;
    let claimed_size = withdrawn_routes_len + total_path_attributes_len + length_fields_size;

    if claimed_size > body_length {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
            data: Vec::new(),
        });
    }

    Ok(())
}

/// RFC 7606: Missing well-known mandatory attributes -> treat-as-withdraw.
/// Returns true if all mandatory attributes are present (valid).
/// Only call this when the UPDATE contains NLRI (RFC 4271 Section 5).
pub(super) fn validate_well_known_mandatory_attributes(path_attributes: &[PathAttribute]) -> bool {
    let has_origin = path_attributes
        .iter()
        .any(|attr| matches!(attr.value, PathAttrValue::Origin(_)));
    let has_as_path = path_attributes
        .iter()
        .any(|attr| matches!(attr.value, PathAttrValue::AsPath(_)));
    let has_next_hop = path_attributes
        .iter()
        .any(|attr| matches!(attr.value, PathAttrValue::NextHop(_)));
    let has_mp_reach = path_attributes
        .iter()
        .any(|attr| matches!(attr.value, PathAttrValue::MpReachNlri(_)));

    if !has_origin {
        warn!("missing ORIGIN attribute, treat-as-withdraw per RFC 7606");
        return false;
    }

    if !has_as_path {
        warn!("missing AS_PATH attribute, treat-as-withdraw per RFC 7606");
        return false;
    }

    // NEXT_HOP is required UNLESS MP_REACH_NLRI is present
    if !has_next_hop && !has_mp_reach {
        warn!("missing NEXT_HOP attribute, treat-as-withdraw per RFC 7606");
        return false;
    }

    true
}

fn validate_nlri_afi(afi: &Afi, nlri_list: &[Nlri]) -> bool {
    for nlri in nlri_list {
        match (afi, &nlri.prefix) {
            (Afi::Ipv4, IpNetwork::V4(_)) | (Afi::Ipv6, IpNetwork::V6(_)) => {}
            _ => return false,
        }
    }
    true
}

/// Format bytes as space-separated hex for RFC 7606 Section 8 logging.
/// Truncates at 256 bytes with a "... (N total)" suffix.
pub(super) fn format_bytes_hex(bytes: &[u8]) -> String {
    const MAX_BYTES: usize = 256;
    if bytes.len() <= MAX_BYTES {
        bytes
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        let truncated: String = bytes[..MAX_BYTES]
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<_>>()
            .join(" ");
        format!("{}... ({} total)", truncated, bytes.len())
    }
}

fn optional_attribute_error(attr_bytes: &[u8]) -> ParserError {
    ParserError::BgpError {
        error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
        data: attr_bytes.to_vec(),
    }
}

fn validate_mp_reach_buffer(
    afi: &Afi,
    safi: &Safi,
    next_hop_len: usize,
    bytes: &[u8],
    header_size: usize,
    reserved_size: usize,
) -> Result<(), ParserError> {
    // Validate next hop length based on AFI/SAFI.
    // IPv4=4, IPv6=16 or 32 (global or global+link-local per RFC 2545).
    // BGP-LS uses IPv4 or IPv6 next hop based on session type (RFC 9552 Section 5.5).
    // BGP-LS-VPN (SAFI 72) prepends an 8-byte all-zero RD to the next hop.
    let valid = match (afi, safi) {
        (Afi::Ipv4, Safi::Unicast | Safi::Multicast | Safi::MplsLabel) => next_hop_len == 4,
        (Afi::Ipv6, Safi::Unicast | Safi::Multicast | Safi::MplsLabel) => {
            next_hop_len == 16 || next_hop_len == 32
        }
        (Afi::LinkState, Safi::LinkStateVpn) => {
            next_hop_len == RD_LEN + 4 || next_hop_len == RD_LEN + 16
        }
        (Afi::LinkState, Safi::LinkState) => {
            next_hop_len == 4 || next_hop_len == 16 || next_hop_len == 32
        }
        _ => false,
    };
    if !valid {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError),
            data: Vec::new(),
        });
    }

    let min_total_size = header_size + next_hop_len + reserved_size;
    if bytes.len() < min_total_size {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError),
            data: Vec::new(),
        });
    }

    Ok(())
}

fn parse_mp_next_hop(
    bytes: &[u8],
    offset: usize,
    afi: Afi,
    next_hop_len: usize,
) -> Result<NextHopAddr, ParserError> {
    match afi {
        Afi::Ipv4 => {
            let addr = parse_ipv4_addr(bytes, offset);
            if !is_valid_unicast_ipv4(u32::from(addr)) {
                return Err(ParserError::BgpError {
                    error: BgpError::UpdateMessageError(
                        UpdateMessageError::InvalidNextHopAttribute,
                    ),
                    data: Vec::new(),
                });
            }
            Ok(NextHopAddr::Ipv4(addr))
        }
        Afi::Ipv6 => Ok(parse_ipv6_next_hop(bytes, offset, next_hop_len)),
        // RFC 9552 Section 5.5: BGP-LS next-hop has no forwarding semantic,
        // so skip unicast validation (e.g. 0.0.0.0 is valid).
        // VPN (SAFI 72) prepends 8-byte all-zero RD: skip it to reach the address.
        Afi::LinkState => match next_hop_len {
            4 => Ok(parse_ipv4_next_hop(bytes, offset)),
            n if n == RD_LEN + 4 => Ok(parse_ipv4_next_hop(bytes, offset + RD_LEN)),
            16 | 32 => Ok(parse_ipv6_next_hop(bytes, offset, next_hop_len)),
            n if n == RD_LEN + 16 => Ok(parse_ipv6_next_hop(bytes, offset + RD_LEN, 16)),
            _ => Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::InvalidNextHopAttribute),
                data: Vec::new(),
            }),
        },
    }
}

fn parse_ipv4_addr(bytes: &[u8], offset: usize) -> Ipv4Addr {
    let mut octets = [0u8; 4];
    octets.copy_from_slice(&bytes[offset..offset + 4]);
    Ipv4Addr::from(octets)
}

fn parse_ipv4_next_hop(bytes: &[u8], offset: usize) -> NextHopAddr {
    NextHopAddr::Ipv4(parse_ipv4_addr(bytes, offset))
}

fn parse_ipv6_next_hop(bytes: &[u8], offset: usize, len: usize) -> NextHopAddr {
    let mut global = [0u8; 16];
    global.copy_from_slice(&bytes[offset..offset + 16]);
    if len == 32 {
        // RFC 2545: 32-byte form carries global + link-local
        let mut link_local = [0u8; 16];
        link_local.copy_from_slice(&bytes[offset + 16..offset + 32]);
        NextHopAddr::Ipv6WithLinkLocal(Ipv6Addr::from(global), Ipv6Addr::from(link_local))
    } else {
        NextHopAddr::Ipv6(Ipv6Addr::from(global))
    }
}

pub(super) fn parse_attr_type(
    bytes: &[u8],
    flags: &PathAttrFlag,
    attr_type_code: u8,
    attr_len: u16,
) -> Result<Option<AttrType>, ParserError> {
    match AttrType::try_from(attr_type_code) {
        Ok(attr_type) => Ok(Some(attr_type)),
        Err(_) => {
            // Unrecognized well-known attribute (OPTIONAL=0)
            // RFC 4271 Section 6.3: return error with full attribute data
            if flags.0 & PathAttrFlag::OPTIONAL == 0 {
                let header_len = flags.header_len();
                let total_attr_len = header_len + attr_len as usize;
                let attr_data = bytes[..total_attr_len.min(bytes.len())].to_vec();

                Err(ParserError::BgpError {
                    error: BgpError::UpdateMessageError(
                        UpdateMessageError::UnrecognizedWellKnownAttribute,
                    ),
                    data: attr_data,
                })
            } else {
                // RFC 4271 Section 6.3: optional attributes (transitive or non-transitive)
                // Return None to signal this should be stored as Unknown variant
                Ok(None)
            }
        }
    }
}

pub(super) fn read_attr_as_path(bytes: &[u8], use_4byte_asn: bool) -> Result<AsPath, ParserError> {
    // Empty AS_PATH is valid (iBGP or locally originated routes)
    if bytes.is_empty() {
        return Ok(AsPath { segments: vec![] });
    }

    // RFC 6793: Use encoding based on negotiated four-octet AS capability
    let asn_size = if use_4byte_asn { 4 } else { 2 };
    try_read_as_path(bytes, asn_size)
}

fn try_read_as_path(bytes: &[u8], asn_size: usize) -> Result<AsPath, ParserError> {
    let mut segments = vec![];
    let mut cursor = 0;

    while cursor < bytes.len() {
        if cursor + 2 > bytes.len() {
            return Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
                data: Vec::new(),
            });
        }

        let segment_type = AsPathSegmentType::try_from(bytes[cursor])?;
        let segment_len = bytes[cursor + 1] as usize;

        // Path segment length cannot be zero
        if segment_len == 0 {
            return Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
                data: Vec::new(),
            });
        }

        let segment_data_size = segment_len * asn_size;
        let segment_total_size = 2 + segment_data_size;

        if cursor + segment_total_size > bytes.len() {
            return Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
                data: Vec::new(),
            });
        }

        let asn_list = (0..segment_len)
            .map(|i| {
                let pos = cursor + 2 + (i * asn_size);
                if asn_size == 4 {
                    u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                } else {
                    u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as u32
                }
            })
            .collect();

        segments.push(AsPathSegment {
            segment_type,
            segment_len: segment_len as u8,
            asn_list,
        });

        cursor += segment_total_size;
    }

    // Verify we consumed all bytes
    if cursor != bytes.len() {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
            data: Vec::new(),
        });
    }

    Ok(AsPath { segments })
}

pub(super) fn read_attr_as4_path(bytes: &[u8]) -> Result<AsPath, ParserError> {
    // RFC 6793 §10: AS4_PATH validation
    // - Attribute length must be at least 6 bytes to carry one AS number
    // - Attribute length must be multiple of 2
    if bytes.len() < 6 || !bytes.len().is_multiple_of(2) {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
            data: Vec::new(),
        });
    }

    // Parse using the common AS_PATH parser with 4-byte ASNs
    let mut path = try_read_as_path(bytes, 4)?;

    // RFC 6793: AS_CONFED_SEQUENCE and AS_CONFED_SET MUST NOT be carried in AS4_PATH
    // If received, discard these segments
    let original_len = path.segments.len();
    path.segments.retain(|seg| {
        !matches!(
            seg.segment_type,
            AsPathSegmentType::AsConfedSequence | AsPathSegmentType::AsConfedSet
        )
    });

    // Log if we discarded confederation segments
    if path.segments.len() < original_len {
        warn!("discarded AS_CONFED segments from AS4_PATH per RFC 6793");
    }

    Ok(path)
}

pub(super) fn read_attr_next_hop(bytes: &[u8]) -> NextHopAddr {
    // Length already validated by validate_attribute_length
    let mut octets = [0u8; 4];
    octets.copy_from_slice(&bytes[0..4]);
    NextHopAddr::Ipv4(Ipv4Addr::from(octets))
}

pub(super) fn read_attr_aggregator(bytes: &[u8]) -> Aggregator {
    // RFC 6793: AGGREGATOR can be 6 bytes (2-byte ASN) or 8 bytes (4-byte ASN)
    // depending on whether both peers support 4-byte ASN capability
    if bytes.len() == 8 {
        // 4-byte ASN encoding (NEW speaker to NEW speaker)
        let asn = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let ip_addr = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
        Aggregator { asn, ip_addr }
    } else {
        // 2-byte ASN encoding (OLD speaker or to OLD speaker)
        let asn = u16::from_be_bytes([bytes[0], bytes[1]]) as u32;
        let ip_addr = Ipv4Addr::new(bytes[2], bytes[3], bytes[4], bytes[5]);
        Aggregator { asn, ip_addr }
    }
}

pub(super) fn read_attr_as4_aggregator(bytes: &[u8]) -> Result<Aggregator, ParserError> {
    if bytes.len() != 8 {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    Ok(read_attr_aggregator(bytes))
}

/// Check if a segment type is a confederation segment
fn is_confed_segment(segment_type: AsPathSegmentType) -> bool {
    matches!(
        segment_type,
        AsPathSegmentType::AsConfedSequence | AsPathSegmentType::AsConfedSet
    )
}

/// Count non-confederation ASNs in an AS path
fn count_non_confed_asns(path: &AsPath) -> usize {
    path.segments
        .iter()
        .filter(|seg| !is_confed_segment(seg.segment_type))
        .map(|seg| seg.asn_list.len())
        .sum()
}

/// Merge AS_PATH and AS4_PATH per RFC 6793 Section 4.2.3
/// This is used when receiving routes from a 2-byte-only speaker that added AS4_PATH
pub fn merge_as_paths(as_path: &AsPath, as4_path: &AsPath) -> AsPath {
    // Count non-confederation ASNs in each path
    let as_path_count = count_non_confed_asns(as_path);
    let as4_path_count = count_non_confed_asns(as4_path);

    // RFC 6793: If AS4_PATH is longer than AS_PATH, discard it (malformed)
    if as4_path_count > as_path_count {
        return as_path.clone();
    }

    // Calculate how many ASNs to prepend from AS_PATH
    let prepend_count = as_path_count - as4_path_count;

    let mut result_segments = Vec::new();
    let mut prepended = 0;

    // RFC 6793: Copy prepend_count ASNs from AS_PATH
    // Include confederation segments only if they are leading or adjacent to prepended segments
    for segment in &as_path.segments {
        if is_confed_segment(segment.segment_type) {
            // Only include confederation segments if we're still prepending
            if prepended < prepend_count {
                result_segments.push(segment.clone());
            } else {
                // Done prepending - stop processing AS_PATH
                break;
            }
        } else if prepended < prepend_count {
            let take_count = (prepend_count - prepended).min(segment.asn_list.len());
            if take_count > 0 {
                result_segments.push(AsPathSegment {
                    segment_type: segment.segment_type,
                    segment_len: take_count as u8,
                    asn_list: segment.asn_list[..take_count].to_vec(),
                });
                prepended += take_count;
            }
        } else {
            // Done prepending - stop processing AS_PATH
            break;
        }
    }

    // Then, append all non-confederation segments from AS4_PATH
    for segment in &as4_path.segments {
        if !is_confed_segment(segment.segment_type) {
            result_segments.push(segment.clone());
        }
    }

    AsPath {
        segments: result_segments,
    }
}

pub(super) fn read_attr_communities(bytes: &[u8]) -> Result<Vec<u32>, ParserError> {
    // Length must be multiple of 4 (each community is 4 octets)
    if !bytes.len().is_multiple_of(4) {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    let mut communities = Vec::new();
    for chunk in bytes.chunks_exact(4) {
        let community = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        communities.push(community);
    }

    Ok(communities)
}

pub(super) fn read_attr_extended_communities(bytes: &[u8]) -> Result<Vec<u64>, ParserError> {
    // Length must be multiple of 8 (each extended community is 8 octets)
    if !bytes.len().is_multiple_of(8) {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    let mut ext_communities = Vec::new();
    for chunk in bytes.chunks_exact(8) {
        let extcomm = u64::from_be_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
        ext_communities.push(extcomm);
    }

    Ok(ext_communities)
}

pub(super) fn read_attr_large_communities(
    bytes: &[u8],
) -> Result<Vec<LargeCommunity>, ParserError> {
    // Length must be multiple of 12 (each large community is 12 octets)
    if !bytes.len().is_multiple_of(12) {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    let mut large_communities = Vec::new();
    for chunk in bytes.chunks_exact(12) {
        let mut buf = [0u8; 12];
        buf.copy_from_slice(chunk);
        large_communities.push(LargeCommunity::from_bytes(buf));
    }

    Ok(large_communities)
}

/// RFC 4456: Read ORIGINATOR_ID attribute (4 bytes = IPv4 address)
pub(super) fn read_attr_originator_id(bytes: &[u8]) -> Ipv4Addr {
    let mut octets = [0u8; 4];
    octets.copy_from_slice(&bytes[0..4]);
    Ipv4Addr::from(octets)
}

/// RFC 4456: Read CLUSTER_LIST attribute (N*4 bytes = list of IPv4 addresses)
pub(super) fn read_attr_cluster_list(bytes: &[u8]) -> Vec<Ipv4Addr> {
    bytes
        .chunks_exact(4)
        .map(|chunk| {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(chunk);
            Ipv4Addr::from(octets)
        })
        .collect()
}

pub(super) fn read_attr_mp_reach_nlri(
    bytes: &[u8],
    format: MessageFormat,
) -> Result<MpReachNlri, ParserError> {
    // MP_REACH_NLRI: AFI(2) + SAFI(1) + NextHopLen(1) + NextHop + Reserved(1) + NLRI
    const HEADER_SIZE: usize = 4; // AFI(2) + SAFI(1) + NextHopLen(1)
    const RESERVED_SIZE: usize = 1;
    const MIN_SIZE: usize = HEADER_SIZE + RESERVED_SIZE; // Minimum without next hop address

    if bytes.len() < MIN_SIZE {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    let afi = Afi::try_from(u16::from_be_bytes([bytes[0], bytes[1]]))?;
    let safi = Safi::try_from(bytes[2])?;
    let next_hop_len = bytes[3] as usize;

    // Resolve ADD-PATH from the AFI/SAFI declared in this attribute
    let add_path = format.add_path.contains(&AfiSafi::new(afi, safi));

    validate_mp_reach_buffer(&afi, &safi, next_hop_len, bytes, HEADER_SIZE, RESERVED_SIZE)?;

    let next_hop = parse_mp_next_hop(bytes, HEADER_SIZE, afi, next_hop_len)?;
    let cursor = HEADER_SIZE + next_hop_len;
    let nlri_bytes = &bytes[cursor + RESERVED_SIZE..];

    let (nlri, ls_nlri) = match afi {
        Afi::Ipv4 => (parse_nlri_list(nlri_bytes, add_path)?, vec![]),
        Afi::Ipv6 => (parse_nlri_v6_list(nlri_bytes, add_path)?, vec![]),
        Afi::LinkState => (vec![], parse_ls_nlri_list(nlri_bytes, safi)?),
    };

    Ok(MpReachNlri {
        afi,
        safi,
        next_hop,
        nlri,
        ls_nlri,
    })
}

pub(super) fn read_attr_mp_unreach_nlri(
    bytes: &[u8],
    format: MessageFormat,
) -> Result<MpUnreachNlri, ParserError> {
    if bytes.len() < 3 {
        return Err(ParserError::BgpError {
            error: BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            data: Vec::new(),
        });
    }

    let afi = Afi::try_from(u16::from_be_bytes([bytes[0], bytes[1]]))?;
    let safi = Safi::try_from(bytes[2])?;

    // Resolve ADD-PATH from the AFI/SAFI declared in this attribute
    let add_path = format.add_path.contains(&AfiSafi::new(afi, safi));

    let nlri_bytes = &bytes[3..];
    let (withdrawn_routes, ls_withdrawn) = match afi {
        Afi::Ipv4 => (parse_nlri_list(nlri_bytes, add_path)?, vec![]),
        Afi::Ipv6 => (parse_nlri_v6_list(nlri_bytes, add_path)?, vec![]),
        Afi::LinkState => (vec![], parse_ls_nlri_list(nlri_bytes, safi)?),
    };

    Ok(MpUnreachNlri {
        afi,
        safi,
        withdrawn_routes,
        ls_withdrawn,
    })
}

pub(super) fn write_attr_mp_reach_nlri(mp_reach: &MpReachNlri) -> Vec<u8> {
    let mut bytes = Vec::new();

    // AFI (2 bytes)
    bytes.extend_from_slice(&(mp_reach.afi as u16).to_be_bytes());

    // SAFI (1 byte)
    bytes.push(mp_reach.safi as u8);

    let vpn = mp_reach.safi == Safi::LinkStateVpn;

    // Next hop length and address.
    // RFC 9552 Section 5.5: VPN SAFI prepends 8-byte all-zero RD to next hop.
    match &mp_reach.next_hop {
        NextHopAddr::Ipv4(addr) => {
            if vpn {
                bytes.push((RD_LEN + 4) as u8);
                bytes.extend_from_slice(&[0u8; RD_LEN]);
            } else {
                bytes.push(4);
            }
            bytes.extend_from_slice(&addr.octets());
        }
        NextHopAddr::Ipv6(addr) => {
            if vpn {
                bytes.push((RD_LEN + 16) as u8);
                bytes.extend_from_slice(&[0u8; RD_LEN]);
            } else {
                bytes.push(16);
            }
            bytes.extend_from_slice(&addr.octets());
        }
        NextHopAddr::Ipv6WithLinkLocal(global, link_local) => {
            if vpn {
                bytes.push((RD_LEN + 32) as u8);
                bytes.extend_from_slice(&[0u8; RD_LEN]);
            } else {
                bytes.push(32);
            }
            bytes.extend_from_slice(&global.octets());
            bytes.extend_from_slice(&link_local.octets());
        }
    }

    // Reserved (1 byte)
    bytes.push(0);

    // NLRI - IP prefixes or BGP-LS NLRIs
    if mp_reach.afi == Afi::LinkState {
        bytes.extend_from_slice(&write_ls_nlri_list(&mp_reach.ls_nlri));
    } else {
        bytes.extend_from_slice(&write_nlri_list(&mp_reach.nlri));
    }

    bytes
}

pub(super) fn write_attr_mp_unreach_nlri(mp_unreach: &MpUnreachNlri) -> Vec<u8> {
    let mut bytes = Vec::new();

    // AFI (2 bytes)
    bytes.extend_from_slice(&(mp_unreach.afi as u16).to_be_bytes());

    // SAFI (1 byte)
    bytes.push(mp_unreach.safi as u8);

    if mp_unreach.afi == Afi::LinkState {
        bytes.extend_from_slice(&write_ls_nlri_list(&mp_unreach.ls_withdrawn));
    } else {
        bytes.extend_from_slice(&write_nlri_list(&mp_unreach.withdrawn_routes));
    }

    bytes
}

/// Parse a single path attribute from the byte stream.
///
/// Parse the value of a known attribute type.
///
/// Returns Some(value) on success, None if the attribute is malformed.
fn parse_attr_value(
    attr_type: &AttrType,
    attr_data: &[u8],
    format: MessageFormat,
) -> Option<PathAttrValue> {
    let use_4byte_asn = format.use_4byte_asn;

    let value = match attr_type {
        AttrType::Origin => match attr_data[0] {
            0 => PathAttrValue::Origin(Origin::IGP),
            1 => PathAttrValue::Origin(Origin::EGP),
            2 => PathAttrValue::Origin(Origin::INCOMPLETE),
            value => {
                warn!(
                    "invalid ORIGIN value {}, treat-as-withdraw per RFC 7606",
                    value
                );
                return None;
            }
        },
        AttrType::AsPath => match read_attr_as_path(attr_data, use_4byte_asn) {
            Ok(as_path) => PathAttrValue::AsPath(as_path),
            Err(_) => {
                warn!("malformed AS_PATH per RFC 7606");
                return None;
            }
        },
        AttrType::NextHop => {
            let next_hop = read_attr_next_hop(attr_data);
            if let NextHopAddr::Ipv4(addr) = next_hop {
                if !is_valid_unicast_ipv4(u32::from(addr)) {
                    warn!("invalid NEXT_HOP per RFC 7606");
                    return None;
                }
            }
            PathAttrValue::NextHop(next_hop)
        }
        AttrType::MultiExtiDisc => match read_u32(attr_data) {
            Ok(med) => PathAttrValue::MultiExtiDisc(med),
            Err(_) => {
                warn!("malformed MED per RFC 7606");
                return None;
            }
        },
        AttrType::LocalPref => {
            if format.is_ebgp {
                warn!("discarding LOCAL_PREF from eBGP peer");
                return None;
            }
            match read_u32(attr_data) {
                Ok(local_pref) => PathAttrValue::LocalPref(local_pref),
                Err(_) => {
                    warn!("malformed LOCAL_PREF per RFC 7606");
                    return None;
                }
            }
        }
        AttrType::AtomicAggregate => PathAttrValue::AtomicAggregate,
        AttrType::Aggregator => PathAttrValue::Aggregator(read_attr_aggregator(attr_data)),
        AttrType::Communities => match read_attr_communities(attr_data) {
            Ok(communities) => PathAttrValue::Communities(communities),
            Err(_) => {
                warn!("malformed COMMUNITIES per RFC 7606");
                return None;
            }
        },
        AttrType::OriginatorId => {
            if format.is_ebgp {
                warn!("discarding ORIGINATOR_ID from eBGP peer");
                return None;
            }
            PathAttrValue::OriginatorId(read_attr_originator_id(attr_data))
        }
        AttrType::ClusterList => {
            if format.is_ebgp {
                warn!("discarding CLUSTER_LIST from eBGP peer");
                return None;
            }
            PathAttrValue::ClusterList(read_attr_cluster_list(attr_data))
        }
        AttrType::MpReachNlri => match read_attr_mp_reach_nlri(attr_data, format) {
            Ok(mp_reach) if validate_nlri_afi(&mp_reach.afi, &mp_reach.nlri) => {
                PathAttrValue::MpReachNlri(mp_reach)
            }
            _ => {
                warn!("malformed MP_REACH_NLRI per RFC 7606");
                return None;
            }
        },
        AttrType::MpUnreachNlri => match read_attr_mp_unreach_nlri(attr_data, format) {
            Ok(mp_unreach) if validate_nlri_afi(&mp_unreach.afi, &mp_unreach.withdrawn_routes) => {
                PathAttrValue::MpUnreachNlri(mp_unreach)
            }
            _ => {
                warn!("malformed MP_UNREACH_NLRI per RFC 7606");
                return None;
            }
        },
        AttrType::ExtendedCommunities => match read_attr_extended_communities(attr_data) {
            Ok(ext_communities) => PathAttrValue::ExtendedCommunities(ext_communities),
            Err(_) => {
                warn!("malformed EXTENDED_COMMUNITIES per RFC 7606");
                return None;
            }
        },
        AttrType::LargeCommunities => match read_attr_large_communities(attr_data) {
            Ok(large_communities) => PathAttrValue::LargeCommunities(large_communities),
            Err(_) => {
                warn!("malformed LARGE_COMMUNITIES per RFC 7606");
                return None;
            }
        },
        AttrType::As4Path => match read_attr_as4_path(attr_data) {
            Ok(as4_path) => PathAttrValue::As4Path(as4_path),
            Err(_) => {
                warn!("malformed AS4_PATH per RFC 6793");
                return None;
            }
        },
        AttrType::As4Aggregator => match read_attr_as4_aggregator(attr_data) {
            Ok(as4_aggregator) => PathAttrValue::As4Aggregator(as4_aggregator),
            Err(_) => {
                warn!("malformed AS4_AGGREGATOR per RFC 6793");
                return None;
            }
        },
        AttrType::LinkState => match parse_ls_attr(attr_data) {
            Some(ls_attr) => PathAttrValue::LsAttr(ls_attr),
            None => {
                warn!("malformed BGP-LS attribute per RFC 9552 Section 8.2");
                return None;
            }
        },
    };

    Some(value)
}

/// Result of parsing a single path attribute per RFC 7606.
#[derive(Debug, PartialEq)]
pub(super) enum PathAttrResult {
    /// Successfully parsed attribute.
    Parsed(PathAttribute),
    /// Malformed attribute with RFC 7606 error action.
    Malformed(PathAttrError),
}

impl PathAttrResult {
    #[cfg(test)]
    pub(in crate::bgp) fn unwrap(self) -> PathAttribute {
        match self {
            PathAttrResult::Parsed(attr) => attr,
            other => panic!("expected Parsed, got {:?}", other),
        }
    }
}

/// Returns `(result, bytes_consumed)`.
///
/// Only returns Err for session-reset-level errors (unrecognized well-known
/// attributes, or malformed MP_REACH_NLRI per RFC 7606 Section 7.11).
pub(super) fn read_path_attribute(
    bytes: &[u8],
    format: MessageFormat,
) -> Result<(PathAttrResult, u16), ParserError> {
    let attribute_flag = PathAttrFlag(bytes[0]);
    let header_len = attribute_flag.header_len();

    // RFC 7606 Section 4: remaining bytes must fit the attribute header
    if bytes.len() < header_len {
        warn!(
            remaining = bytes.len(),
            header_len,
            attr_hex = %format_bytes_hex(bytes),
            "truncated attribute header, treat-as-withdraw per RFC 7606 Section 4"
        );
        return Ok((
            PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw),
            bytes.len() as u16,
        ));
    }

    let attr_type_code = bytes[1];
    let attr_len = match attribute_flag.extended_len() {
        true => u16::from_be_bytes([bytes[2], bytes[3]]),
        false => bytes[2] as u16,
    };

    let total_offset = header_len + attr_len as usize;

    // RFC 7606 Section 4: attribute length exceeds remaining buffer
    if total_offset > bytes.len() {
        warn!(
            attr_type_code,
            claimed = total_offset,
            available = bytes.len(),
            attr_hex = %format_bytes_hex(bytes),
            "attribute length overrun, treat-as-withdraw per RFC 7606 Section 4"
        );
        return Ok((
            PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw),
            bytes.len() as u16,
        ));
    }

    // Unrecognized well-known attribute -> always session reset
    let known_type = parse_attr_type(bytes, &attribute_flag, attr_type_code, attr_len)?;

    let attr_val = match known_type {
        Some(attr_type) => {
            let attr_bytes = &bytes[..total_offset];

            // RFC 7606 Section 3(c): flag errors SHOULD use treat-as-withdraw,
            // except ATOMIC_AGGREGATE/AGGREGATOR which use attribute-discard per Section 3(f).
            if let Err(err) =
                validate_attribute_flags(bytes[0], &attr_type, attr_type_code, attr_len)
            {
                warn!(
                    type_code = attr_type_code,
                    attr_hex = %format_bytes_hex(attr_bytes),
                    "attribute flag error per RFC 7606 Section 3(c)"
                );
                if attr_type_code == attr_type_code::MP_REACH_NLRI {
                    return Err(err);
                }
                let action = match attr_type_code {
                    attr_type_code::ATOMIC_AGGREGATE | attr_type_code::AGGREGATOR => {
                        PathAttrError::Discard
                    }
                    _ => PathAttrError::TreatAsWithdraw,
                };
                return Ok((PathAttrResult::Malformed(action), total_offset as u16));
            }

            // Length errors use per-attribute actions from malformed_attr_action()
            if let Err(err) =
                validate_attribute_length(&attr_type, attr_len, attr_bytes, format.use_4byte_asn)
            {
                warn!(
                    type_code = attr_type_code,
                    attr_hex = %format_bytes_hex(attr_bytes),
                    "malformed attribute length per RFC 7606"
                );
                if attr_type_code == attr_type_code::MP_REACH_NLRI {
                    return Err(err);
                }
                let malformed_result = PathAttrResult::Malformed(malformed_attr_action(
                    attr_type_code,
                    format.is_ebgp,
                ));
                return Ok((malformed_result, total_offset as u16));
            }

            let attr_data = &bytes[header_len..header_len + attr_len as usize];

            match parse_attr_value(&attr_type, attr_data, format) {
                Some(value) => value,
                None => {
                    // Section 7.11: MP_REACH_NLRI -> session reset
                    if attr_type_code == attr_type_code::MP_REACH_NLRI {
                        return Err(optional_attribute_error(attr_bytes));
                    }
                    let malformed_result = PathAttrResult::Malformed(malformed_attr_action(
                        attr_type_code,
                        format.is_ebgp,
                    ));
                    return Ok((malformed_result, total_offset as u16));
                }
            }
        }
        None => {
            // Unknown optional attribute
            // RFC 4271 Section 6.3: set PARTIAL bit for transitive, store raw data
            let data = bytes[header_len..header_len + attr_len as usize].to_vec();

            let mut flags = attribute_flag.0;
            if flags & PathAttrFlag::TRANSITIVE != 0 {
                flags |= PathAttrFlag::PARTIAL;
            }

            PathAttrValue::Unknown {
                type_code: attr_type_code,
                flags,
                data,
            }
        }
    };

    // Update PathAttribute flags if PARTIAL bit was set for unknown transitive
    let final_flags = match &attr_val {
        PathAttrValue::Unknown { flags, .. } => PathAttrFlag(*flags),
        _ => attribute_flag,
    };

    let attribute = PathAttribute {
        flags: final_flags,
        value: attr_val,
    };

    Ok((PathAttrResult::Parsed(attribute), total_offset as u16))
}

/// Parse all path attributes from the byte stream.
///
/// Returns `(attributes, treat_as_withdraw)`. The flag is set if any
/// per-attribute error escalated to treat-as-withdraw.
///
/// Only returns Err for session-reset-level errors.
pub(super) fn read_path_attributes(
    bytes: &[u8],
    format: MessageFormat,
) -> Result<(Vec<PathAttribute>, bool), ParserError> {
    let mut cursor = 0;
    let mut path_attributes: Vec<PathAttribute> = Vec::new();
    let mut seen_type_codes: HashSet<u8> = HashSet::new();
    let mut treat_as_withdraw = false;

    while cursor < bytes.len() {
        let (result, offset) = read_path_attribute(&bytes[cursor..], format)?;
        let offset_usize = offset as usize;

        match result {
            PathAttrResult::Parsed(attribute) => {
                let type_code = attribute.type_code();
                let is_mp = matches!(
                    type_code,
                    attr_type_code::MP_REACH_NLRI | attr_type_code::MP_UNREACH_NLRI
                );
                if !seen_type_codes.insert(type_code) {
                    if is_mp {
                        // Duplicate MP attribute -> SessionReset
                        return Err(ParserError::BgpError {
                            error: BgpError::UpdateMessageError(
                                UpdateMessageError::MalformedAttributeList,
                            ),
                            data: Vec::new(),
                        });
                    }
                    // RFC 7606: duplicate non-MP attribute -> discard (keep first)
                    warn!(
                        type_code = type_code,
                        "discarded duplicate attribute per RFC 7606"
                    );
                    cursor += offset_usize;
                    continue;
                }
                path_attributes.push(attribute);
            }
            PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw) => {
                treat_as_withdraw = true;
            }
            PathAttrResult::Malformed(PathAttrError::Discard) => {}
        }

        cursor += offset_usize;
    }

    Ok((path_attributes, treat_as_withdraw))
}

/// Encode NLRI entries to wire format. Each entry's optional path_id (RFC 7911)
/// is prepended when present.
pub(super) fn write_nlri_list(nlri_list: &[Nlri]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for nlri in nlri_list {
        if let Some(pid) = nlri.path_id {
            bytes.extend_from_slice(&pid.to_be_bytes());
        }
        match &nlri.prefix {
            IpNetwork::V4(net) => {
                bytes.push(net.prefix_length);
                let octets = net.address.octets();
                let num_octets = net.prefix_length.div_ceil(8) as usize;
                bytes.extend_from_slice(&octets[..num_octets]);
            }
            IpNetwork::V6(net) => {
                bytes.push(net.prefix_length);
                let octets = net.address.octets();
                let num_octets = net.prefix_length.div_ceil(8) as usize;
                bytes.extend_from_slice(&octets[..num_octets]);
            }
        }
    }
    bytes
}

fn encode_asn(asn: u32, use_4byte_asn: bool) -> Vec<u8> {
    if use_4byte_asn {
        asn.to_be_bytes().to_vec()
    } else {
        (asn as u16).to_be_bytes().to_vec()
    }
}

pub(super) fn write_path_attribute(attr: &PathAttribute, use_4byte_asn: bool) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Serialize attribute value first to determine length
    let attr_value_bytes = match &attr.value {
        PathAttrValue::Origin(origin) => {
            vec![*origin as u8]
        }
        PathAttrValue::AsPath(as_path) => {
            let mut path_bytes = Vec::new();
            for segment in &as_path.segments {
                path_bytes.push(segment.segment_type as u8);
                path_bytes.push(segment.segment_len);
                for asn in &segment.asn_list {
                    path_bytes.extend_from_slice(&encode_asn(*asn, use_4byte_asn));
                }
            }
            path_bytes
        }
        PathAttrValue::NextHop(next_hop) => match next_hop {
            NextHopAddr::Ipv4(addr) => addr.octets().to_vec(),
            NextHopAddr::Ipv6(addr) => addr.octets().to_vec(),
            NextHopAddr::Ipv6WithLinkLocal(_, _) => {
                // NEXT_HOP attr is IPv4-only (RFC 4271). IPv6 uses MP_REACH_NLRI.
                // This is a logic bug if reached — skip rather than send a malformed attribute.
                warn!("attempted to write Ipv6WithLinkLocal as NEXT_HOP attribute, skipping");
                return vec![];
            }
        },
        PathAttrValue::MultiExtiDisc(value) => value.to_be_bytes().to_vec(),
        PathAttrValue::LocalPref(value) => value.to_be_bytes().to_vec(),
        PathAttrValue::AtomicAggregate => vec![],
        PathAttrValue::Aggregator(agg) => {
            let mut agg_bytes = encode_asn(agg.asn, use_4byte_asn);
            agg_bytes.extend_from_slice(&agg.ip_addr.octets());
            agg_bytes
        }
        PathAttrValue::Communities(communities) => {
            let mut comm_bytes = Vec::new();
            for &community in communities {
                comm_bytes.extend_from_slice(&community.to_be_bytes());
            }
            comm_bytes
        }
        PathAttrValue::OriginatorId(originator_id) => originator_id.octets().to_vec(),
        PathAttrValue::ClusterList(cluster_list) => {
            let mut cluster_bytes = Vec::new();
            for &cluster_id in cluster_list {
                cluster_bytes.extend_from_slice(&cluster_id.octets());
            }
            cluster_bytes
        }
        PathAttrValue::MpReachNlri(mp_reach) => write_attr_mp_reach_nlri(mp_reach),
        PathAttrValue::MpUnreachNlri(mp_unreach) => write_attr_mp_unreach_nlri(mp_unreach),
        PathAttrValue::ExtendedCommunities(ext_communities) => {
            let mut ext_comm_bytes = Vec::new();
            for &ext_comm in ext_communities {
                ext_comm_bytes.extend_from_slice(&ext_comm.to_be_bytes());
            }
            ext_comm_bytes
        }
        PathAttrValue::LargeCommunities(large_communities) => {
            let mut large_comm_bytes = Vec::new();
            for lc in large_communities {
                large_comm_bytes.extend_from_slice(&lc.to_bytes());
            }
            large_comm_bytes
        }
        PathAttrValue::As4Path(as_path) => {
            // RFC 6793: AS4_PATH always uses 4-byte ASN encoding
            let mut path_bytes = Vec::new();
            for segment in &as_path.segments {
                path_bytes.push(segment.segment_type as u8);
                path_bytes.push(segment.segment_len);
                for asn in &segment.asn_list {
                    let asn_4byte = asn.to_be_bytes();
                    path_bytes.extend_from_slice(&asn_4byte);
                }
            }
            path_bytes
        }
        PathAttrValue::As4Aggregator(agg) => {
            // RFC 6793: AS4_AGGREGATOR always uses 4-byte ASN encoding
            let mut agg_bytes = Vec::new();
            let asn_4byte = agg.asn.to_be_bytes();
            agg_bytes.extend_from_slice(&asn_4byte);
            agg_bytes.extend_from_slice(&agg.ip_addr.octets());
            agg_bytes
        }
        PathAttrValue::LsAttr(ls_attr) => ls_attr.raw.clone(),
        PathAttrValue::Unknown { data, .. } => data.clone(),
    };

    // Write flags (Unknown stores its own flags)
    let flags = match &attr.value {
        PathAttrValue::Unknown { flags, .. } => *flags,
        _ => attr.flags.0,
    };
    bytes.push(flags);

    // Write attribute type (Unknown stores its own type)
    let attr_type = match &attr.value {
        PathAttrValue::Origin(_) => AttrType::Origin as u8,
        PathAttrValue::AsPath(_) => AttrType::AsPath as u8,
        PathAttrValue::NextHop(_) => AttrType::NextHop as u8,
        PathAttrValue::MultiExtiDisc(_) => AttrType::MultiExtiDisc as u8,
        PathAttrValue::LocalPref(_) => AttrType::LocalPref as u8,
        PathAttrValue::AtomicAggregate => AttrType::AtomicAggregate as u8,
        PathAttrValue::Aggregator(_) => AttrType::Aggregator as u8,
        PathAttrValue::Communities(_) => AttrType::Communities as u8,
        PathAttrValue::OriginatorId(_) => AttrType::OriginatorId as u8,
        PathAttrValue::ClusterList(_) => AttrType::ClusterList as u8,
        PathAttrValue::MpReachNlri(_) => AttrType::MpReachNlri as u8,
        PathAttrValue::MpUnreachNlri(_) => AttrType::MpUnreachNlri as u8,
        PathAttrValue::ExtendedCommunities(_) => AttrType::ExtendedCommunities as u8,
        PathAttrValue::As4Path(_) => AttrType::As4Path as u8,
        PathAttrValue::As4Aggregator(_) => AttrType::As4Aggregator as u8,
        PathAttrValue::LargeCommunities(_) => AttrType::LargeCommunities as u8,
        PathAttrValue::LsAttr(_) => AttrType::LinkState as u8,
        PathAttrValue::Unknown { type_code, .. } => *type_code,
    };
    bytes.push(attr_type);

    // Write length (use extended_len from Unknown's flags if applicable)
    let attr_len = attr_value_bytes.len();
    let extended_len = flags & PathAttrFlag::EXTENDED_LENGTH != 0;
    if extended_len {
        bytes.extend_from_slice(&(attr_len as u16).to_be_bytes());
    } else {
        bytes.push(attr_len as u8);
    }

    // Write attribute value
    bytes.extend_from_slice(&attr_value_bytes);

    bytes
}

pub(super) fn write_path_attributes(
    path_attributes: &[PathAttribute],
    use_4byte_asn: bool,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    for attr in path_attributes {
        bytes.extend_from_slice(&write_path_attribute(attr, use_4byte_asn));
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::bgpls::LsTlv;
    use crate::bgp::bgpls_attr::{build_ls_attr, LinkAttrTlv, LsAttr, LsAttrTlv, NodeAttrTlv};
    use crate::bgp::bgpls_nlri::{
        build_ls_nlri, LsDescriptors, LsNlriType, LsProtocolId, NodeDescriptor,
    };
    use crate::bgp::msg_notification::{BgpError, UpdateMessageError};
    use crate::bgp::msg_update_types::AttrType;
    use crate::bgp::{
        nlri_v4, ADDPATH_FORMAT, DEFAULT_FORMAT, PATH_ATTR_COMMUNITIES_TWO,
        PATH_ATTR_EXTENDED_COMMUNITIES_TWO,
    };
    use crate::net::Ipv6Net;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Sample MP_REACH_NLRI for IPv4 (192.168.1.1, NLRI=10.0.0.0/8)
    const MP_REACH_IPV4_SAMPLE: &[u8] = &[
        0x00, 0x01, // AFI = IPv4 (1)
        0x01, // SAFI = 1 (unicast)
        0x04, // Next hop length = 4
        0xc0, 0xa8, 0x01, 0x01, // Next hop 192.168.1.1
        0x00, // Reserved
        0x08, 0x0a, // NLRI: 10.0.0.0/8
    ];

    const PATH_ATTR_ORIGIN_EGP: &[u8] =
        &[PathAttrFlag::TRANSITIVE, AttrType::Origin as u8, 0x01, 1];

    #[test]
    fn test_read_path_attribute_origin() {
        let (result, offset) = read_path_attribute(PATH_ATTR_ORIGIN_EGP, DEFAULT_FORMAT).unwrap();
        let attribute = result.unwrap();

        assert_eq!(
            attribute,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::Origin(Origin::try_from(1).unwrap()),
            }
        );
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_read_path_attribute_origin_invalid_value() {
        let input: &[u8] = &[PathAttrFlag::TRANSITIVE, AttrType::Origin as u8, 0x01, 0x03];

        // RFC 7606: invalid ORIGIN value -> treat-as-withdraw
        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        assert!(matches!(
            result,
            PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw)
        ));
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_read_path_attribute_communities() {
        let (result, offset) =
            read_path_attribute(PATH_ATTR_COMMUNITIES_TWO, DEFAULT_FORMAT).unwrap();
        let attr = result.unwrap();

        assert_eq!(
            attr,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::Communities(vec![0x00010064, 0xFFFFFF01]),
            }
        );
        assert_eq!(offset, 11);
    }

    #[test]
    fn test_write_path_attribute_communities() {
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::Communities(vec![0x00010064, 0xFFFFFF01]),
        };

        let bytes = write_path_attribute(&attr, false);
        assert_eq!(bytes, PATH_ATTR_COMMUNITIES_TWO);
    }

    #[test]
    fn test_communities_roundtrip() {
        let original_communities = vec![0x00010064, 0xFFFFFF01, 0xFFFFFF02];
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::Communities(original_communities.clone()),
        };

        let bytes = write_path_attribute(&attr, false);
        let (result, _) = read_path_attribute(&bytes, DEFAULT_FORMAT).unwrap();
        let parsed_attr = result.unwrap();

        if let PathAttrValue::Communities(communities) = parsed_attr.value {
            assert_eq!(communities, original_communities);
        } else {
            panic!("Expected Communities attribute after roundtrip");
        }
    }

    const PATH_ATTR_COMMUNITIES_EMPTY: &[u8] = &[
        PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
        AttrType::Communities as u8,
        0x00, // Length: 0
    ];

    const PATH_ATTR_COMMUNITIES_WELL_KNOWN: &[u8] = &[
        PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
        AttrType::Communities as u8,
        0x0c, // Length: 12 bytes (3 communities)
        0xFF,
        0xFF,
        0xFF,
        0x01, // NO_EXPORT
        0xFF,
        0xFF,
        0xFF,
        0x02, // NO_ADVERTISE
        0xFF,
        0xFF,
        0xFF,
        0x03, // NO_EXPORT_SUBCONFED
    ];

    #[test]
    fn test_read_path_attribute_communities_empty() {
        // RFC 7606 Section 7.8: length must be non-zero multiple of 4
        let (result, offset) =
            read_path_attribute(PATH_ATTR_COMMUNITIES_EMPTY, DEFAULT_FORMAT).unwrap();
        assert!(matches!(
            result,
            PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw)
        ));
        assert_eq!(offset, 3);
    }

    #[test]
    fn test_read_path_attribute_communities_well_known() {
        let (result, _) =
            read_path_attribute(PATH_ATTR_COMMUNITIES_WELL_KNOWN, DEFAULT_FORMAT).unwrap();
        let attr = result.unwrap();

        if let PathAttrValue::Communities(communities) = attr.value {
            assert_eq!(communities.len(), 3);
            assert_eq!(communities[0], 0xFFFFFF01); // NO_EXPORT
            assert_eq!(communities[1], 0xFFFFFF02); // NO_ADVERTISE
            assert_eq!(communities[2], 0xFFFFFF03); // NO_EXPORT_SUBCONFED
        } else {
            panic!("Expected Communities attribute");
        }
    }

    #[test]
    fn test_read_path_attribute_communities_invalid_length() {
        // Length not multiple of 4
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::Communities as u8,
            0x03, // Invalid length: 3 bytes (not multiple of 4)
            0x00,
            0x01,
            0x00,
        ];

        // RFC 7606: COMMUNITIES length error -> treat-as-withdraw
        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        assert!(matches!(
            result,
            PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw)
        ));
        assert_eq!(offset, 6);
    }

    #[test]
    fn test_write_path_attribute_communities_empty() {
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::Communities(vec![]),
        };

        let bytes = write_path_attribute(&attr, false);
        assert_eq!(bytes, PATH_ATTR_COMMUNITIES_EMPTY);
    }

    #[test]
    fn test_write_path_attribute_extended_communities() {
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::ExtendedCommunities(vec![
                0x0002FDE800000064, // rt:65000:100
                0x0102C0A801010064, // rt:192.168.1.1:100
            ]),
        };

        let bytes = write_path_attribute(&attr, false);
        assert_eq!(bytes, PATH_ATTR_EXTENDED_COMMUNITIES_TWO);
    }

    #[test]
    fn test_extended_communities_roundtrip() {
        use crate::bgp::msg_update_types::{from_ipv4, from_two_octet_as, SUBTYPE_ROUTE_TARGET};

        let original_ext_communities = vec![
            from_two_octet_as(SUBTYPE_ROUTE_TARGET, 65000, 100),
            from_ipv4(
                SUBTYPE_ROUTE_TARGET,
                u32::from(Ipv4Addr::new(192, 168, 1, 1)),
                100,
            ),
        ];
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::ExtendedCommunities(original_ext_communities.clone()),
        };

        let bytes = write_path_attribute(&attr, false);
        let (result, _) = read_path_attribute(&bytes, DEFAULT_FORMAT).unwrap();
        let parsed_attr = result.unwrap();

        if let PathAttrValue::ExtendedCommunities(ext_communities) = parsed_attr.value {
            assert_eq!(ext_communities, original_ext_communities);
        } else {
            panic!("Expected ExtendedCommunities attribute after roundtrip");
        }
    }

    // AS_PATH attribute tests
    const PATH_ATTR_AS_PATH: &[u8] = &[
        PathAttrFlag::TRANSITIVE,
        AttrType::AsPath as u8,
        0x0a, // 1 + 1 + 2*4 = 10 bytes (4-byte ASN)
        AsPathSegmentType::AsSet as u8,
        0x02,
        0x00,
        0x00,
        0x00,
        0x10, // ASN 16
        0x00,
        0x00,
        0x01,
        0x12, // ASN 274
    ];

    #[test]
    fn test_read_path_attribute_as_path() {
        let (result, offset) = read_path_attribute(PATH_ATTR_AS_PATH, DEFAULT_FORMAT).unwrap();
        let as_path = result.unwrap();
        let segments = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSet,
            segment_len: 2,
            asn_list: vec![16, 274],
        }];

        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AsPath(AsPath { segments }),
            }
        );
        assert_eq!(offset, 13);
    }

    #[test]
    fn test_read_path_attribute_as_path_truncated_header() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::AsPath as u8,
            0x01,
            AsPathSegmentType::AsSet as u8,
        ];

        // RFC 7606: malformed AS_PATH -> treat-as-withdraw
        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        assert!(matches!(
            result,
            PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw)
        ));
        assert_eq!(offset, 4);
    }

    #[test]
    fn test_read_path_attribute_as_path_truncated_asn_data() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::AsPath as u8,
            0x04,
            AsPathSegmentType::AsSequence as u8,
            0x02,
            0x00,
            0x10,
        ];

        // RFC 7606: malformed AS_PATH -> treat-as-withdraw
        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        assert!(matches!(
            result,
            PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw)
        ));
        assert_eq!(offset, 7);
    }

    #[test]
    fn test_read_path_attribute_as_path_empty() {
        let input: &[u8] = &[PathAttrFlag::TRANSITIVE, AttrType::AsPath as u8, 0x00];

        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        let as_path = result.unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AsPath(AsPath { segments: vec![] }),
            }
        );
        assert_eq!(offset, 3);
    }

    #[test]
    fn test_read_path_attribute_as_path_multiple_segments() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::AsPath as u8,
            0x10, // 10 + 6 = 16 bytes (4-byte ASN)
            AsPathSegmentType::AsSequence as u8,
            0x02,
            0x00,
            0x00,
            0x00,
            0x0a, // ASN 10
            0x00,
            0x00,
            0x00,
            0x14, // ASN 20
            AsPathSegmentType::AsSet as u8,
            0x01,
            0x00,
            0x00,
            0x00,
            0x1e, // ASN 30
        ];

        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        let as_path = result.unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AsPath(AsPath {
                    segments: vec![
                        AsPathSegment {
                            segment_type: AsPathSegmentType::AsSequence,
                            segment_len: 2,
                            asn_list: vec![10, 20],
                        },
                        AsPathSegment {
                            segment_type: AsPathSegmentType::AsSet,
                            segment_len: 1,
                            asn_list: vec![30],
                        }
                    ]
                }),
            }
        );
        assert_eq!(offset, 19);
    }

    // NEXT_HOP attribute tests
    const PATH_ATTR_NEXT_HOP_IPV4: &[u8] = &[
        PathAttrFlag::TRANSITIVE,
        AttrType::NextHop as u8,
        0x04,
        0xc8,
        0xc9,
        0xca,
        0xcb,
    ];

    #[test]
    fn test_read_path_attribute_next_hop_ipv4() {
        let (result, offset) =
            read_path_attribute(PATH_ATTR_NEXT_HOP_IPV4, DEFAULT_FORMAT).unwrap();
        let as_path = result.unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::NextHop(NextHopAddr::Ipv4(Ipv4Addr::new(200, 201, 202, 203))),
            }
        );
        assert_eq!(offset, 7);
    }

    #[test]
    fn test_read_path_attribute_next_hop_invalid_length() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::NextHop as u8,
            0x05,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x0e,
        ];

        // RFC 7606: NEXT_HOP length error -> treat-as-withdraw
        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        assert!(matches!(
            result,
            PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw)
        ));
        assert_eq!(offset, 8);
    }

    #[test]
    fn test_read_path_attribute_next_hop_invalid_address() {
        let test_cases = vec![
            ("0.0.0.0", [0x00, 0x00, 0x00, 0x00]),
            ("255.255.255.255", [0xff, 0xff, 0xff, 0xff]),
            ("224.0.0.1", [0xe0, 0x00, 0x00, 0x01]),
            ("239.255.255.255", [0xef, 0xff, 0xff, 0xff]),
        ];

        for (name, ip_bytes) in test_cases {
            let input: Vec<u8> = vec![
                PathAttrFlag::TRANSITIVE,
                AttrType::NextHop as u8,
                0x04,
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3],
            ];

            // RFC 7606: invalid NEXT_HOP address -> treat-as-withdraw
            let (result, offset) = read_path_attribute(&input, DEFAULT_FORMAT).unwrap();
            assert!(
                matches!(
                    result,
                    PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw)
                ),
                "Failed for {}",
                name
            );
            assert_eq!(offset, 7, "Failed for {}", name);
        }
    }

    // MED attribute tests
    #[test]
    fn test_read_path_attribute_multi_exit_disc() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL,
            AttrType::MultiExtiDisc as u8,
            0x04,
            0x00,
            0x01,
            0x00,
            0x01,
        ];

        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        let as_path = result.unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                value: PathAttrValue::MultiExtiDisc(65537),
            }
        );
        assert_eq!(offset, 7);
    }

    #[test]
    fn test_read_path_attribute_optional_invalid_length() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL,
            AttrType::MultiExtiDisc as u8,
            0x03,
            0x00,
            0x00,
            0x01,
        ];

        // RFC 7606 Section 7.4: MED error -> treat-as-withdraw
        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        assert!(matches!(
            result,
            PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw)
        ));
        assert_eq!(offset, 6);
    }

    // LOCAL_PREF attribute tests
    #[test]
    fn test_read_path_attribute_local_pref() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::LocalPref as u8,
            0x04,
            0x00,
            0x00,
            0x0f,
            0x01,
        ];

        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        let as_path = result.unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::LocalPref(3841),
            }
        );
        assert_eq!(offset, 7);
    }

    #[test]
    fn test_read_path_attribute_local_pref_invalid_length() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::LocalPref as u8,
            0x03,
            0x00,
            0x00,
            0x0f,
        ];

        // RFC 7606: LOCAL_PREF length error -> treat-as-withdraw
        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        assert!(matches!(
            result,
            PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw)
        ));
        assert_eq!(offset, 6);
    }

    // ATOMIC_AGGREGATE attribute tests
    #[test]
    fn test_read_path_attribute_atomic_aggregate() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::AtomicAggregate as u8,
            0x00,
        ];

        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        let as_path = result.unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AtomicAggregate,
            }
        );
        assert_eq!(offset, 3);
    }

    #[test]
    fn test_read_path_attribute_atomic_aggregate_invalid_length() {
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::AtomicAggregate as u8,
            0x01,
            0x00,
        ];

        // RFC 7606: ATOMIC_AGGREGATE length error -> attribute-discard (not treat-as-withdraw)
        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        assert!(matches!(
            result,
            PathAttrResult::Malformed(PathAttrError::Discard)
        ));
        assert_eq!(offset, 4);
    }

    // AGGREGATOR attribute tests
    #[test]
    fn test_read_path_attribute_aggregator_ipv4() {
        use std::str::FromStr;

        // 2-byte ASN format (6 bytes) with a non-4byte-ASN session
        let format_2byte = MessageFormat {
            use_4byte_asn: false,
            ..DEFAULT_FORMAT
        };

        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::Aggregator as u8,
            0x06,
            0x00,
            0x10,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
        ];

        let (result, offset) = read_path_attribute(input, format_2byte).unwrap();
        let as_path = result.unwrap();
        assert_eq!(
            as_path,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::Aggregator(Aggregator {
                    asn: 16,
                    ip_addr: Ipv4Addr::from_str("10.11.12.13").unwrap(),
                }),
            }
        );
        assert_eq!(offset, 9);
    }

    #[test]
    fn test_read_path_attribute_aggregator_invalid_length() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::Aggregator as u8,
            0x03,
            0x00,
            0x10,
            0x0a,
        ];

        // RFC 7606: AGGREGATOR length error -> attribute-discard (not treat-as-withdraw)
        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        assert!(matches!(
            result,
            PathAttrResult::Malformed(PathAttrError::Discard)
        ));
        assert_eq!(offset, 6);
    }

    #[test]
    fn test_read_path_attribute_extended_communities() {
        let (result, offset) =
            read_path_attribute(PATH_ATTR_EXTENDED_COMMUNITIES_TWO, DEFAULT_FORMAT).unwrap();
        let attr = result.unwrap();

        assert_eq!(
            attr,
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::ExtendedCommunities(vec![
                    0x0002FDE800000064, // rt:65000:100
                    0x0102C0A801010064, // rt:192.168.1.1:100
                ]),
            }
        );
        assert_eq!(offset, 19);
    }

    #[test]
    fn test_large_communities_roundtrip() {
        let original_large_communities = vec![
            LargeCommunity::new(65536, 100, 200),
            LargeCommunity::new(4200000000, 1, 2),
            LargeCommunity::new(0, 0, 0),
        ];
        let attr = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::LargeCommunities(original_large_communities.clone()),
        };

        let bytes = write_path_attribute(&attr, false);
        let (result, _) = read_path_attribute(&bytes, DEFAULT_FORMAT).unwrap();
        let parsed_attr = result.unwrap();

        if let PathAttrValue::LargeCommunities(large_communities) = parsed_attr.value {
            assert_eq!(large_communities, original_large_communities);
        } else {
            panic!("Expected LargeCommunities attribute after roundtrip");
        }
    }

    #[test]
    fn test_read_attr_large_communities() {
        // Wire format: [GA:4][LD1:4][LD2:4] for each community
        let bytes = vec![
            0x00, 0x01, 0x00, 0x00, // GA = 65536
            0x00, 0x00, 0x00, 0x64, // LD1 = 100
            0x00, 0x00, 0x00, 0xC8, // LD2 = 200
            0xFA, 0x56, 0xEA, 0x00, // GA = 4200000000
            0x00, 0x00, 0x00, 0x01, // LD1 = 1
            0x00, 0x00, 0x00, 0x02, // LD2 = 2
        ];

        let large_communities = read_attr_large_communities(&bytes).unwrap();
        assert_eq!(large_communities.len(), 2);

        assert_eq!(large_communities[0], LargeCommunity::new(65536, 100, 200));
        assert_eq!(large_communities[1], LargeCommunity::new(4200000000, 1, 2));

        // Verify field extraction
        assert_eq!(large_communities[0].global_admin, 65536);
        assert_eq!(large_communities[0].local_data_1, 100);
        assert_eq!(large_communities[0].local_data_2, 200);
    }

    #[test]
    fn test_read_attr_large_communities_invalid_length() {
        // Length not multiple of 12
        let bytes = vec![0x00, 0x01, 0x00, 0x00, 0x00];

        let result = read_attr_large_communities(&bytes);
        assert!(result.is_err());
        match result {
            Err(ParserError::BgpError { error, .. }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError)
                );
            }
            _ => panic!("Expected OptionalAttributeError for invalid length"),
        }
    }

    #[test]
    fn test_validate_nlri_afi_mismatch() {
        let ipv6_route = Nlri {
            prefix: IpNetwork::V6(Ipv6Net {
                address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                prefix_length: 64,
            }),
            path_id: None,
        };
        let ipv4_route = nlri_v4(192, 168, 1, 0, 24, None);

        // AFI mismatch should fail
        assert!(!validate_nlri_afi(&Afi::Ipv4, &[ipv6_route]));
        assert!(!validate_nlri_afi(&Afi::Ipv6, &[ipv4_route]));

        // AFI match should succeed
        assert!(validate_nlri_afi(&Afi::Ipv4, &[ipv4_route]));
        assert!(validate_nlri_afi(&Afi::Ipv6, &[ipv6_route]));
    }

    #[test]
    fn test_read_attr_mp_reach_nlri_ipv4() {
        // (name, input, format, expected_nlri)
        let tests: Vec<(&str, &[u8], MessageFormat, Vec<Nlri>)> = vec![
            (
                "without add_path",
                MP_REACH_IPV4_SAMPLE,
                DEFAULT_FORMAT,
                vec![nlri_v4(10, 0, 0, 0, 8, None)],
            ),
            (
                "with add_path",
                &[
                    0x00, 0x01, // AFI = IPv4
                    0x01, // SAFI = unicast
                    0x04, // Next hop length = 4
                    0xc0, 0xa8, 0x01, 0x01, // Next hop 192.168.1.1
                    0x00, // Reserved
                    // NLRI: path_id=42, 10.0.0.0/8
                    0x00, 0x00, 0x00, 0x2a, 0x08, 0x0a,
                ],
                ADDPATH_FORMAT,
                vec![nlri_v4(10, 0, 0, 0, 8, Some(42))],
            ),
            (
                "with add_path multiple NLRIs",
                &[
                    0x00, 0x01, // AFI = IPv4
                    0x01, // SAFI = unicast
                    0x04, // Next hop length = 4
                    0xc0, 0xa8, 0x01, 0x01, // Next hop 192.168.1.1
                    0x00, // Reserved
                    // NLRI 1: path_id=1, 10.0.0.0/8
                    0x00, 0x00, 0x00, 0x01, 0x08, 0x0a,
                    // NLRI 2: path_id=2, 172.16.0.0/16
                    0x00, 0x00, 0x00, 0x02, 0x10, 0xac, 0x10,
                ],
                ADDPATH_FORMAT,
                vec![
                    nlri_v4(10, 0, 0, 0, 8, Some(1)),
                    nlri_v4(172, 16, 0, 0, 16, Some(2)),
                ],
            ),
        ];

        for (name, input, format, expected_nlri) in tests {
            let result = read_attr_mp_reach_nlri(input, format).unwrap();
            assert_eq!(result.afi, Afi::Ipv4, "{name}");
            assert_eq!(result.safi, Safi::Unicast, "{name}");
            assert_eq!(
                result.next_hop,
                NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                "{name}"
            );
            assert_eq!(result.nlri, expected_nlri, "{name}");
        }
    }

    #[test]
    fn test_mp_reach_ipv4_addpath_roundtrip() {
        let mp_reach = MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
            nlri: vec![
                nlri_v4(10, 0, 0, 0, 8, Some(1)),
                nlri_v4(172, 16, 0, 0, 16, Some(2)),
            ],
            ls_nlri: vec![],
        };

        let bytes = write_attr_mp_reach_nlri(&mp_reach);
        let parsed = read_attr_mp_reach_nlri(&bytes, ADDPATH_FORMAT).unwrap();

        assert_eq!(parsed.afi, mp_reach.afi);
        assert_eq!(parsed.safi, mp_reach.safi);
        assert_eq!(parsed.next_hop, mp_reach.next_hop);
        assert_eq!(parsed.nlri, mp_reach.nlri);
    }

    #[test]
    fn test_mp_reach_ipv6_link_local_roundtrip() {
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xade0);
        let mp_reach = MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: NextHopAddr::Ipv6WithLinkLocal(global, link_local),
            nlri: vec![Nlri {
                prefix: IpNetwork::V6(Ipv6Net {
                    address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                    prefix_length: 32,
                }),
                path_id: None,
            }],
            ls_nlri: vec![],
        };

        let bytes = write_attr_mp_reach_nlri(&mp_reach);
        let parsed = read_attr_mp_reach_nlri(&bytes, DEFAULT_FORMAT).unwrap();

        assert_eq!(
            parsed.next_hop,
            NextHopAddr::Ipv6WithLinkLocal(global, link_local)
        );
        assert_eq!(parsed.nlri, mp_reach.nlri);
    }

    #[test]
    fn test_mp_reach_ipv6_32byte_parse() {
        // 32-byte next-hop: global 2001:db8::1 + link-local fe80::1
        let input: Vec<u8> = vec![
            0x00, 0x02, // AFI = IPv6
            0x01, // SAFI = unicast
            0x20, // Next hop length = 32
            // Global: 2001:db8::1
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // Link-local: fe80::1
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, // Reserved
            // NLRI: 2001:db8::/32
            0x20, 0x20, 0x01, 0x0d, 0xb8,
        ];

        let result = read_attr_mp_reach_nlri(&input, DEFAULT_FORMAT).unwrap();
        assert_eq!(
            result.next_hop,
            NextHopAddr::Ipv6WithLinkLocal(
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            )
        );
    }

    #[test]
    fn test_mp_reach_ls_roundtrip() {
        let ls_entries = vec![build_ls_nlri(
            LsNlriType::Node,
            LsProtocolId::Direct,
            1,
            LsDescriptors::Node {
                local_node: NodeDescriptor {
                    as_number: Some(65001),
                    igp_router_id: Some(vec![10, 0, 0, 1]),
                    ..Default::default()
                },
            },
            None,
        )];

        let mp_reach = MpReachNlri {
            afi: Afi::LinkState,
            safi: Safi::LinkState,
            next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            nlri: vec![],
            ls_nlri: ls_entries,
        };

        let reach_bytes = write_attr_mp_reach_nlri(&mp_reach);
        let parsed = read_attr_mp_reach_nlri(&reach_bytes, DEFAULT_FORMAT).unwrap();

        assert_eq!(parsed.afi, Afi::LinkState);
        assert_eq!(parsed.safi, Safi::LinkState);
        assert!(parsed.nlri.is_empty());
        assert_eq!(parsed.ls_nlri.len(), 1);
        assert_eq!(parsed.ls_nlri[0].nlri_type, LsNlriType::Node as u16);
        let body = parsed.ls_nlri[0]
            .body
            .as_ref()
            .expect("expected parsed body");
        assert_eq!(body.protocol_id(), Some(LsProtocolId::Direct));
    }

    #[test]
    fn test_mp_unreach_ls_roundtrip() {
        let ls_entries = vec![build_ls_nlri(
            LsNlriType::Node,
            LsProtocolId::Direct,
            1,
            LsDescriptors::Node {
                local_node: NodeDescriptor {
                    as_number: Some(65001),
                    igp_router_id: Some(vec![10, 0, 0, 1]),
                    ..Default::default()
                },
            },
            None,
        )];

        let mp_unreach = MpUnreachNlri {
            afi: Afi::LinkState,
            safi: Safi::LinkState,
            withdrawn_routes: vec![],
            ls_withdrawn: ls_entries,
        };

        let unreach_bytes = write_attr_mp_unreach_nlri(&mp_unreach);
        let parsed = read_attr_mp_unreach_nlri(&unreach_bytes, DEFAULT_FORMAT).unwrap();

        assert_eq!(parsed.afi, Afi::LinkState);
        assert_eq!(parsed.safi, Safi::LinkState);
        assert!(parsed.withdrawn_routes.is_empty());
        assert_eq!(parsed.ls_withdrawn.len(), 1);
    }

    #[test]
    fn test_ls_attribute_roundtrip() {
        let cases: Vec<(&str, LsAttr)> = vec![
            (
                "with TLVs",
                build_ls_attr(vec![
                    LsAttrTlv::Node(NodeAttrTlv::Name("router1".to_string())),
                    LsAttrTlv::Link(LinkAttrTlv::IgpMetric(10)),
                ]),
            ),
            ("empty", build_ls_attr(vec![])),
            (
                "unknown TLV preserved",
                build_ls_attr(vec![LsAttrTlv::Unknown(LsTlv {
                    tlv_type: 60000,
                    value: vec![0xCA, 0xFE],
                })]),
            ),
        ];

        for (name, ls_attr) in cases {
            let attr = PathAttribute::new(
                PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                PathAttrValue::LsAttr(ls_attr.clone()),
            );
            let wire = write_path_attribute(&attr, true);
            let (result, consumed) = read_path_attribute(&wire, DEFAULT_FORMAT).unwrap();
            assert_eq!(consumed as usize, wire.len(), "{name}: all bytes consumed");
            let parsed = result.unwrap();
            assert_eq!(parsed.value, PathAttrValue::LsAttr(ls_attr), "{name}");
        }
    }

    #[test]
    fn test_ls_attribute_malformed_discard() {
        // Type 29 with truncated TLV inside -- should trigger Attribute Discard
        let mut value = Vec::new();
        value.extend_from_slice(&1026u16.to_be_bytes()); // TLV type
        value.extend_from_slice(&100u16.to_be_bytes()); // length claims 100 bytes
        value.extend_from_slice(&[0x01, 0x02]); // only 2 bytes available

        let mut wire = Vec::new();
        wire.push(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE); // flags
        wire.push(AttrType::LinkState as u8); // type 29
        wire.push(value.len() as u8); // length
        wire.extend_from_slice(&value);

        let (result, _) = read_path_attribute(&wire, DEFAULT_FORMAT).unwrap();
        assert_eq!(result, PathAttrResult::Malformed(PathAttrError::Discard));
    }

    #[test]
    fn test_read_attr_mp_reach_nlri_ipv6() {
        // Common IPv6 header: AFI=IPv6, SAFI=1, next_hop=2001:db8::1
        let ipv6_header: &[u8] = &[
            0x00, 0x02, // AFI = IPv6 (2)
            0x01, // SAFI = 1 (unicast)
            0x10, // Next hop length = 16
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, // Next hop 2001:db8::1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, // Reserved
        ];

        // (name, nlri_bytes, format, expected_nlri)
        let tests: Vec<(&str, &[u8], MessageFormat, Vec<Nlri>)> = vec![
            (
                "without add_path",
                // 2001:db8::/32
                &[0x20, 0x20, 0x01, 0x0d, 0xb8],
                DEFAULT_FORMAT,
                vec![Nlri {
                    prefix: IpNetwork::V6(Ipv6Net {
                        address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
                        prefix_length: 32,
                    }),
                    path_id: None,
                }],
            ),
            (
                "with add_path",
                // path_id=100, 2001:db8::/32
                &[0x00, 0x00, 0x00, 0x64, 0x20, 0x20, 0x01, 0x0d, 0xb8],
                ADDPATH_FORMAT,
                vec![Nlri {
                    prefix: IpNetwork::V6(Ipv6Net {
                        address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
                        prefix_length: 32,
                    }),
                    path_id: Some(100),
                }],
            ),
        ];

        for (name, nlri_bytes, format, expected_nlri) in tests {
            let mut input = ipv6_header.to_vec();
            input.extend_from_slice(nlri_bytes);

            let result = read_attr_mp_reach_nlri(&input, format).unwrap();
            assert_eq!(result.afi, Afi::Ipv6, "{name}");
            assert_eq!(result.safi, Safi::Unicast, "{name}");
            assert_eq!(
                result.next_hop,
                NextHopAddr::Ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
                "{name}"
            );
            assert_eq!(result.nlri, expected_nlri, "{name}");
        }
    }

    #[test]
    fn test_read_attr_mp_unreach_nlri_ipv4() {
        // (name, input, format, expected_withdrawn)
        let tests: Vec<(&str, Vec<u8>, MessageFormat, Vec<Nlri>)> = vec![
            (
                "without add_path",
                vec![
                    0x00, 0x01, // AFI = IPv4
                    0x01, // SAFI = unicast
                    0x08, 0x0a, // Withdrawn: 10.0.0.0/8
                ],
                DEFAULT_FORMAT,
                vec![nlri_v4(10, 0, 0, 0, 8, None)],
            ),
            (
                "with add_path",
                vec![
                    0x00, 0x01, // AFI = IPv4
                    0x01, // SAFI = unicast
                    // path_id=5, 10.0.0.0/8
                    0x00, 0x00, 0x00, 0x05, 0x08, 0x0a,
                ],
                ADDPATH_FORMAT,
                vec![nlri_v4(10, 0, 0, 0, 8, Some(5))],
            ),
            (
                "with add_path same prefix different path_ids",
                vec![
                    0x00, 0x01, // AFI = IPv4
                    0x01, // SAFI = unicast
                    // path_id=1, 10.0.0.0/8
                    0x00, 0x00, 0x00, 0x01, 0x08, 0x0a, // path_id=2, 10.0.0.0/8
                    0x00, 0x00, 0x00, 0x02, 0x08, 0x0a,
                ],
                ADDPATH_FORMAT,
                vec![
                    nlri_v4(10, 0, 0, 0, 8, Some(1)),
                    nlri_v4(10, 0, 0, 0, 8, Some(2)),
                ],
            ),
        ];

        for (name, input, format, expected_withdrawn) in tests {
            let result = read_attr_mp_unreach_nlri(&input, format).unwrap();
            assert_eq!(result.afi, Afi::Ipv4, "{name}");
            assert_eq!(result.safi, Safi::Unicast, "{name}");
            assert_eq!(result.withdrawn_routes, expected_withdrawn, "{name}");
        }
    }

    #[test]
    fn test_read_attr_mp_unreach_nlri_ipv6() {
        // (name, input, format, expected_withdrawn)
        let tests: Vec<(&str, &[u8], MessageFormat, Vec<Nlri>)> = vec![
            (
                "without add_path",
                &[
                    0x00, 0x02, // AFI = IPv6
                    0x01, // SAFI = unicast
                    0x20, 0x20, 0x01, 0x0d, 0xb8, // Withdrawn: 2001:db8::/32
                ],
                DEFAULT_FORMAT,
                vec![Nlri {
                    prefix: IpNetwork::V6(Ipv6Net {
                        address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
                        prefix_length: 32,
                    }),
                    path_id: None,
                }],
            ),
            (
                "with add_path",
                &[
                    0x00, 0x02, // AFI = IPv6
                    0x01, // SAFI = unicast
                    // path_id=7, 2001:db8::/32
                    0x00, 0x00, 0x00, 0x07, 0x20, 0x20, 0x01, 0x0d, 0xb8,
                ],
                ADDPATH_FORMAT,
                vec![Nlri {
                    prefix: IpNetwork::V6(Ipv6Net {
                        address: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
                        prefix_length: 32,
                    }),
                    path_id: Some(7),
                }],
            ),
        ];

        for (name, input, format, expected_withdrawn) in tests {
            let result = read_attr_mp_unreach_nlri(input, format).unwrap();
            assert_eq!(result.afi, Afi::Ipv6, "{name}");
            assert_eq!(result.safi, Safi::Unicast, "{name}");
            assert_eq!(result.withdrawn_routes, expected_withdrawn, "{name}");
        }
    }

    #[test]
    fn test_next_hop_with_mp_reach_ignored() {
        // RFC 4760 Section 3: when MP_REACH_NLRI is present, NEXT_HOP is ignored.
        // NEXT_HOP says 10.10.10.10, MP_REACH says 192.168.1.1 -- MP_REACH wins.
        let mut attrs_bytes = Vec::new();

        // NEXT_HOP attribute with a different address than MP_REACH
        attrs_bytes.extend_from_slice(&[
            0x40, // flags: TRANSITIVE
            0x03, // type: NEXT_HOP
            0x04, // length: 4
            10, 10, 10, 10, // next_hop: 10.10.10.10
        ]);

        // MP_REACH_NLRI with next_hop 192.168.1.1
        attrs_bytes.extend_from_slice(&[
            0x80,                             // flags: OPTIONAL
            0x0e,                             // type: MP_REACH_NLRI
            MP_REACH_IPV4_SAMPLE.len() as u8, // length
        ]);
        attrs_bytes.extend_from_slice(MP_REACH_IPV4_SAMPLE);

        let (attrs, _) = read_path_attributes(&attrs_bytes, DEFAULT_FORMAT).unwrap();

        // MP_REACH next-hop is used, not the NEXT_HOP attribute
        let mp_reach = attrs.iter().find_map(|attr| match &attr.value {
            PathAttrValue::MpReachNlri(mp) => Some(mp),
            _ => None,
        });
        assert_eq!(
            mp_reach.unwrap().next_hop,
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    // RFC 6793 Attribute Discard Tests

    #[test]
    fn test_malformed_as4_path_aggreator_attributes_discarded() {
        struct TestCase {
            name: &'static str,
            input: &'static [u8],
            expected_offset: Option<u16>,
        }

        let tests = vec![
            TestCase {
                name: "AS4_PATH truncated - segment length claims 2 ASNs but only 1 present",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x06, // Length: 6 bytes
                    AsPathSegmentType::AsSequence as u8,
                    0x02, // Segment length claims 2 ASNs (but we only have data for 1)
                    0x00,
                    0x00,
                    0x00,
                    0x0a, // First ASN: 10 (second ASN missing)
                ],
                expected_offset: Some(9),
            },
            TestCase {
                name: "AS4_PATH invalid segment type",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x06, // Length: 6 bytes
                    0xFF, // Invalid segment type (255)
                    0x01, // Segment length: 1 ASN
                    0x00,
                    0x00,
                    0x00,
                    0x0a, // ASN: 10
                ],
                expected_offset: None,
            },
            TestCase {
                name: "AS4_AGGREGATOR wrong length",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Aggregator as u8,
                    0x06, // Length: 6 bytes (should be 8)
                    0x00,
                    0x00,
                    0x00,
                    0x0a, // ASN: 10
                    0xc0,
                    0xa8, // IP incomplete
                ],
                expected_offset: Some(9),
            },
            TestCase {
                name: "AS4_PATH too short",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x04, // Length: 4 bytes (too short - need at least 6)
                    AsPathSegmentType::AsSequence as u8,
                    0x00, // Segment length: 0
                    0x00,
                    0x00,
                ],
                expected_offset: None,
            },
            TestCase {
                name: "AS4_PATH odd length",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x07, // Length: 7 bytes (not multiple of 2)
                    AsPathSegmentType::AsSequence as u8,
                    0x01, // Segment length: 1 ASN
                    0x00,
                    0x00,
                    0x00,
                    0x0a, // ASN: 10
                    0x00, // Extra odd byte
                ],
                expected_offset: None,
            },
            TestCase {
                name: "AS4_PATH zero segment length",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x06, // Length: 6 bytes
                    AsPathSegmentType::AsSequence as u8,
                    0x00, // Segment length: 0 (invalid)
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                ],
                expected_offset: None,
            },
        ];

        for test in tests {
            let result = read_path_attribute(test.input, DEFAULT_FORMAT);
            assert!(result.is_ok(), "{}: should return Ok", test.name);
            let (result, offset) = result.unwrap();
            assert!(
                !matches!(result, PathAttrResult::Parsed(_)),
                "{}: malformed attribute should be discarded",
                test.name
            );
            if let Some(expected) = test.expected_offset {
                assert_eq!(offset, expected, "{}: offset mismatch", test.name);
            }
        }
    }

    #[test]
    fn test_as4_path_well_formed_accepted() {
        // Well-formed AS4_PATH should still be accepted
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::As4Path as u8,
            0x0a, // Length: 10 bytes
            AsPathSegmentType::AsSequence as u8,
            0x02, // Segment length: 2 ASNs
            0x00,
            0x00,
            0x00,
            0x0a, // First ASN: 10
            0x00,
            0x00,
            0x00,
            0x14, // Second ASN: 20
        ];

        let (result, _) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        let attr = result.unwrap();
        if let PathAttrValue::As4Path(as_path) = attr.value {
            assert_eq!(as_path.segments.len(), 1);
            assert_eq!(as_path.segments[0].asn_list, vec![10, 20]);
        } else {
            panic!("Expected As4Path attribute");
        }
    }

    #[test]
    fn test_malformed_as_path() {
        // Segment claims 2 ASNs but data is truncated
        let input: &[u8] = &[
            PathAttrFlag::TRANSITIVE,
            AttrType::AsPath as u8,
            0x06, // Length: 6 bytes (segment header=2, 1 ASN=4)
            AsPathSegmentType::AsSequence as u8,
            0x02, // Segment length claims: 2 ASNs (but only 1 ASN worth of data follows)
            0x00,
            0x00,
            0x00,
            0x0a, // First ASN: 10 (second ASN missing - truncated)
        ];

        // RFC 7606: malformed AS_PATH -> treat-as-withdraw
        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        assert!(matches!(
            result,
            PathAttrResult::Malformed(PathAttrError::TreatAsWithdraw)
        ));
        assert_eq!(offset, 9);
    }

    #[test]
    fn test_as4_path_confed_segment_filtering() {
        struct TestCase {
            name: &'static str,
            input: &'static [u8],
            expected_segments: usize,
            expected_asns: Vec<u32>,
        }

        let tests = vec![
            TestCase {
                name: "only confederation segments - result is empty",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x0a, // Length: 10 bytes
                    AsPathSegmentType::AsConfedSequence as u8,
                    0x02, // Segment length: 2 ASNs
                    0x00,
                    0x00,
                    0x00,
                    0x0a, // ASN: 10
                    0x00,
                    0x00,
                    0x00,
                    0x14, // ASN: 20
                ],
                expected_segments: 0,
                expected_asns: vec![],
            },
            TestCase {
                name: "mixed regular and confederation segments",
                input: &[
                    PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                    AttrType::As4Path as u8,
                    0x12, // Length: 18 bytes (3 segments: 6+6+6)
                    // First segment: regular AS_SEQUENCE
                    AsPathSegmentType::AsSequence as u8,
                    0x01, // Segment length: 1 ASN
                    0x00,
                    0x00,
                    0x00,
                    0x0a, // ASN: 10
                    // Second segment: AS_CONFED_SEQUENCE (filtered)
                    AsPathSegmentType::AsConfedSequence as u8,
                    0x01, // Segment length: 1 ASN
                    0x00,
                    0x00,
                    0x00,
                    0x14, // ASN: 20
                    // Third segment: AS_CONFED_SET (filtered)
                    AsPathSegmentType::AsConfedSet as u8,
                    0x01, // Segment length: 1 ASN
                    0x00,
                    0x00,
                    0x00,
                    0x1e, // ASN: 30
                ],
                expected_segments: 1,
                expected_asns: vec![10],
            },
        ];

        for test in tests {
            let result = read_path_attribute(test.input, DEFAULT_FORMAT);
            assert!(result.is_ok(), "{}: should return Ok", test.name);
            let (result, _) = result.unwrap();
            let attr = result.unwrap();
            if let PathAttrValue::As4Path(as_path) = attr.value {
                assert_eq!(
                    as_path.segments.len(),
                    test.expected_segments,
                    "{}: segment count mismatch",
                    test.name
                );
                if test.expected_segments > 0 {
                    assert_eq!(
                        as_path.segments[0].segment_type,
                        AsPathSegmentType::AsSequence,
                        "{}: segment type mismatch",
                        test.name
                    );
                    assert_eq!(
                        as_path.segments[0].asn_list, test.expected_asns,
                        "{}: ASN list mismatch",
                        test.name
                    );
                }
            } else {
                panic!("{}: Expected As4Path attribute", test.name);
            }
        }
    }

    // Helper function to create AS path segments
    fn make_as_path(segments: Vec<(AsPathSegmentType, Vec<u32>)>) -> AsPath {
        AsPath {
            segments: segments
                .into_iter()
                .map(|(segment_type, asn_list)| AsPathSegment {
                    segment_type,
                    segment_len: asn_list.len() as u8,
                    asn_list,
                })
                .collect(),
        }
    }

    #[test]
    fn test_merge_as_paths() {
        use AsPathSegmentType::{AsConfedSequence, AsSequence};

        struct TestCase {
            name: &'static str,
            as_path: Vec<(AsPathSegmentType, Vec<u32>)>,
            as4_path: Vec<(AsPathSegmentType, Vec<u32>)>,
            expected: Vec<(AsPathSegmentType, Vec<u32>)>,
        }

        let tests = vec![
            TestCase {
                name: "normal merge",
                as_path: vec![(AsSequence, vec![100, 200, 300])],
                as4_path: vec![(AsSequence, vec![300])],
                expected: vec![(AsSequence, vec![100, 200]), (AsSequence, vec![300])],
            },
            TestCase {
                name: "malformed as4_path longer than as_path",
                as_path: vec![(AsSequence, vec![100, 200])],
                as4_path: vec![(AsSequence, vec![100, 200, 300])],
                expected: vec![(AsSequence, vec![100, 200])],
            },
            TestCase {
                name: "same length paths",
                as_path: vec![(AsSequence, vec![100, 200])],
                as4_path: vec![(AsSequence, vec![100, 200])],
                expected: vec![(AsSequence, vec![100, 200])],
            },
            TestCase {
                name: "leading confederation segments",
                as_path: vec![
                    (AsConfedSequence, vec![50, 60]),
                    (AsSequence, vec![100, 200, 300]),
                ],
                as4_path: vec![(AsSequence, vec![300])],
                expected: vec![
                    (AsConfedSequence, vec![50, 60]),
                    (AsSequence, vec![100, 200]),
                    (AsSequence, vec![300]),
                ],
            },
            TestCase {
                name: "trailing confederation segments discarded",
                as_path: vec![
                    (AsSequence, vec![100, 200, 300]),
                    (AsConfedSequence, vec![50, 60]),
                ],
                as4_path: vec![(AsSequence, vec![300])],
                expected: vec![(AsSequence, vec![100, 200]), (AsSequence, vec![300])],
            },
            TestCase {
                name: "multiple segments",
                as_path: vec![(AsSequence, vec![100, 200]), (AsSequence, vec![300, 400])],
                as4_path: vec![(AsSequence, vec![400])],
                expected: vec![
                    (AsSequence, vec![100, 200]),
                    (AsSequence, vec![300]),
                    (AsSequence, vec![400]),
                ],
            },
            TestCase {
                name: "partial segment prepend",
                as_path: vec![(AsSequence, vec![100, 200, 300])],
                as4_path: vec![(AsSequence, vec![200, 300])],
                expected: vec![(AsSequence, vec![100]), (AsSequence, vec![200, 300])],
            },
            TestCase {
                name: "as4_path with confed segments filtered",
                as_path: vec![(AsSequence, vec![100, 200])],
                as4_path: vec![(AsConfedSequence, vec![50]), (AsSequence, vec![200])],
                expected: vec![(AsSequence, vec![100]), (AsSequence, vec![200])],
            },
        ];

        for test in tests {
            let as_path = make_as_path(test.as_path);
            let as4_path = make_as_path(test.as4_path);
            let expected = make_as_path(test.expected);

            let result = merge_as_paths(&as_path, &as4_path);

            assert_eq!(
                result.segments.len(),
                expected.segments.len(),
                "{}: segment count mismatch",
                test.name
            );

            for (i, (result_seg, expected_seg)) in result
                .segments
                .iter()
                .zip(expected.segments.iter())
                .enumerate()
            {
                assert_eq!(
                    result_seg.segment_type, expected_seg.segment_type,
                    "{}: segment {} type mismatch",
                    test.name, i
                );
                assert_eq!(
                    result_seg.asn_list, expected_seg.asn_list,
                    "{}: segment {} ASN list mismatch",
                    test.name, i
                );
            }
        }
    }

    #[test]
    fn test_count_non_confed_asns() {
        let path = make_as_path(vec![
            (AsPathSegmentType::AsConfedSequence, vec![50, 60]),
            (AsPathSegmentType::AsSequence, vec![100, 200]),
            (AsPathSegmentType::AsConfedSet, vec![70]),
            (AsPathSegmentType::AsSequence, vec![300]),
        ]);

        assert_eq!(count_non_confed_asns(&path), 3); // 100, 200, 300
    }

    #[test]
    fn test_is_confed_segment() {
        assert!(is_confed_segment(AsPathSegmentType::AsConfedSequence));
        assert!(is_confed_segment(AsPathSegmentType::AsConfedSet));
        assert!(!is_confed_segment(AsPathSegmentType::AsSequence));
        assert!(!is_confed_segment(AsPathSegmentType::AsSet));
    }

    #[test]
    fn test_validate_attribute_length() {
        // (name, attr_type, attr_len, use_4byte_asn, expect_ok)
        let tests: Vec<(&str, AttrType, u16, bool, bool)> = vec![
            // Origin: must be exactly 1
            ("origin valid", AttrType::Origin, 1, true, true),
            ("origin too short", AttrType::Origin, 0, true, false),
            ("origin too long", AttrType::Origin, 2, true, false),
            // NextHop: must be exactly 4
            ("nexthop valid", AttrType::NextHop, 4, true, true),
            ("nexthop too short", AttrType::NextHop, 3, true, false),
            ("nexthop too long", AttrType::NextHop, 5, true, false),
            // MED: must be exactly 4
            ("med valid", AttrType::MultiExtiDisc, 4, true, true),
            ("med too short", AttrType::MultiExtiDisc, 3, true, false),
            // LocalPref: must be exactly 4
            ("localpref valid", AttrType::LocalPref, 4, true, true),
            ("localpref too long", AttrType::LocalPref, 5, true, false),
            // AtomicAggregate: must be exactly 0
            ("atomic_agg valid", AttrType::AtomicAggregate, 0, true, true),
            (
                "atomic_agg nonzero",
                AttrType::AtomicAggregate,
                1,
                true,
                false,
            ),
            // RFC 7606 Section 7.7: AGGREGATOR length depends on 4-byte ASN
            (
                "aggregator 8 with 4byte",
                AttrType::Aggregator,
                8,
                true,
                true,
            ),
            (
                "aggregator 6 with 4byte",
                AttrType::Aggregator,
                6,
                true,
                false,
            ),
            (
                "aggregator 6 without 4byte",
                AttrType::Aggregator,
                6,
                false,
                true,
            ),
            (
                "aggregator 8 without 4byte",
                AttrType::Aggregator,
                8,
                false,
                false,
            ),
            ("aggregator 7", AttrType::Aggregator, 7, true, false),
            ("aggregator 0", AttrType::Aggregator, 0, true, false),
            // AsPath: variable length, always valid
            ("aspath empty", AttrType::AsPath, 0, true, true),
            ("aspath any", AttrType::AsPath, 100, true, true),
            // Communities: non-zero multiple of 4
            ("communities 4", AttrType::Communities, 4, true, true),
            ("communities 8", AttrType::Communities, 8, true, true),
            ("communities 0", AttrType::Communities, 0, true, false),
            ("communities 3", AttrType::Communities, 3, true, false),
            ("communities 5", AttrType::Communities, 5, true, false),
            // OriginatorId: must be exactly 4
            ("originator_id valid", AttrType::OriginatorId, 4, true, true),
            (
                "originator_id short",
                AttrType::OriginatorId,
                3,
                true,
                false,
            ),
            // ClusterList: non-zero multiple of 4
            ("cluster_list 4", AttrType::ClusterList, 4, true, true),
            ("cluster_list 8", AttrType::ClusterList, 8, true, true),
            ("cluster_list 0", AttrType::ClusterList, 0, true, false),
            ("cluster_list 5", AttrType::ClusterList, 5, true, false),
            // ExtendedCommunities: non-zero multiple of 8
            ("ext_comm 8", AttrType::ExtendedCommunities, 8, true, true),
            ("ext_comm 16", AttrType::ExtendedCommunities, 16, true, true),
            ("ext_comm 0", AttrType::ExtendedCommunities, 0, true, false),
            ("ext_comm 7", AttrType::ExtendedCommunities, 7, true, false),
            // LargeCommunities: non-zero multiple of 12
            ("large_comm 12", AttrType::LargeCommunities, 12, true, true),
            ("large_comm 24", AttrType::LargeCommunities, 24, true, true),
            ("large_comm 0", AttrType::LargeCommunities, 0, true, false),
            ("large_comm 11", AttrType::LargeCommunities, 11, true, false),
            // Variable length types: always valid
            ("mp_reach", AttrType::MpReachNlri, 50, true, true),
            ("mp_unreach", AttrType::MpUnreachNlri, 50, true, true),
            ("as4_path", AttrType::As4Path, 10, true, true),
            ("as4_aggregator", AttrType::As4Aggregator, 8, true, true),
        ];

        for (name, attr_type, attr_len, use_4byte_asn, expect_ok) in &tests {
            let result = validate_attribute_length(attr_type, *attr_len, &[], *use_4byte_asn);
            assert_eq!(result.is_ok(), *expect_ok, "{name}");
        }
    }

    #[test]
    fn test_validate_attribute_length_error_subcodes() {
        // Well-known attribute (Origin) -> AttributeLengthError
        let result = validate_attribute_length(&AttrType::Origin, 0, &[], true);
        if let Err(ParserError::BgpError { error, .. }) = result {
            assert_eq!(
                error,
                BgpError::UpdateMessageError(UpdateMessageError::AttributeLengthError),
            );
        } else {
            panic!("Expected AttributeLengthError for well-known Origin");
        }

        // Optional attribute (MED) -> OptionalAttributeError
        let result = validate_attribute_length(&AttrType::MultiExtiDisc, 3, &[], true);
        if let Err(ParserError::BgpError { error, .. }) = result {
            assert_eq!(
                error,
                BgpError::UpdateMessageError(UpdateMessageError::OptionalAttributeError),
            );
        } else {
            panic!("Expected OptionalAttributeError for optional MED");
        }
    }

    #[test]
    fn test_read_attr_originator_id() {
        assert_eq!(
            read_attr_originator_id(&[192, 168, 1, 1]),
            Ipv4Addr::new(192, 168, 1, 1)
        );
        assert_eq!(
            read_attr_originator_id(&[10, 0, 0, 1]),
            Ipv4Addr::new(10, 0, 0, 1)
        );
    }

    #[test]
    fn test_read_attr_cluster_list() {
        assert_eq!(
            read_attr_cluster_list(&[192, 168, 1, 1]),
            vec![Ipv4Addr::new(192, 168, 1, 1)]
        );
        assert_eq!(
            read_attr_cluster_list(&[192, 168, 1, 1, 10, 0, 0, 1, 172, 16, 0, 1]),
            vec![
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(172, 16, 0, 1),
            ]
        );
        assert!(read_attr_cluster_list(&[]).is_empty());
    }
}
