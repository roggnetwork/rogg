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

use super::bgpls_attr::LsAttr;
use super::bgpls_nlri::LsNlri;
use super::msg_notification::{BgpError, UpdateMessageError};
use super::multiprotocol::{Afi, Safi};
use super::utils::ParserError;
use crate::net::IpNetwork;
use std::net::{Ipv4Addr, Ipv6Addr};

/// RFC 7606 Section 7: Should a malformed attribute trigger treat-as-withdraw?
///
/// Returns true for attributes whose errors invalidate the entire UPDATE
/// (e.g. ORIGIN, AS_PATH, NEXT_HOP). Returns false for attributes where
/// the error can be handled by silently discarding just the attribute
/// (e.g. AGGREGATOR, ATOMIC_AGGREGATE).
///
/// MP_REACH_NLRI is not covered here — it requires session reset (Section 7.11)
/// and is handled directly in the parser.
///
/// Some attributes differ by session type: LOCAL_PREF, ORIGINATOR_ID,
/// CLUSTER_LIST are attribute-discard on eBGP but treat-as-withdraw on iBGP
/// (Sections 7.5, 7.9, 7.10).
/// RFC 7606 per-attribute error handling result.
#[derive(Debug, PartialEq)]
pub enum PathAttrError {
    /// Attribute discarded (drop attribute, keep route).
    Discard,
    /// Treat-as-withdraw (convert entire UPDATE to withdrawals).
    TreatAsWithdraw,
}

/// RFC 7606: determine the error action for a malformed attribute.
pub fn malformed_attr_action(attr_type_code: u8, is_ebgp: bool) -> PathAttrError {
    match attr_type_code {
        // Section 7.1
        attr_type_code::ORIGIN => PathAttrError::TreatAsWithdraw,
        // Section 7.2
        attr_type_code::AS_PATH => PathAttrError::TreatAsWithdraw,
        // Section 7.3
        attr_type_code::NEXT_HOP => PathAttrError::TreatAsWithdraw,
        // Section 7.4
        attr_type_code::MULTI_EXIT_DISC => PathAttrError::TreatAsWithdraw,
        // Section 7.5: eBGP -> discard, iBGP -> treat-as-withdraw
        attr_type_code::LOCAL_PREF if is_ebgp => PathAttrError::Discard,
        attr_type_code::LOCAL_PREF => PathAttrError::TreatAsWithdraw,
        // Section 7.6: attribute-discard
        attr_type_code::ATOMIC_AGGREGATE => PathAttrError::Discard,
        // Section 7.7: attribute-discard
        attr_type_code::AGGREGATOR => PathAttrError::Discard,
        // Section 7.8
        attr_type_code::COMMUNITIES => PathAttrError::TreatAsWithdraw,
        // Section 7.14
        attr_type_code::EXTENDED_COMMUNITIES => PathAttrError::TreatAsWithdraw,
        // Consistent with Section 8
        attr_type_code::LARGE_COMMUNITIES => PathAttrError::TreatAsWithdraw,
        // Section 7.9: eBGP -> discard, iBGP -> treat-as-withdraw
        attr_type_code::ORIGINATOR_ID if is_ebgp => PathAttrError::Discard,
        attr_type_code::ORIGINATOR_ID => PathAttrError::TreatAsWithdraw,
        // Section 7.10: eBGP -> discard, iBGP -> treat-as-withdraw
        attr_type_code::CLUSTER_LIST if is_ebgp => PathAttrError::Discard,
        attr_type_code::CLUSTER_LIST => PathAttrError::TreatAsWithdraw,
        // Section 7.12 / 3(j): simple layout, NLRI position is deterministic
        attr_type_code::MP_UNREACH_NLRI => PathAttrError::TreatAsWithdraw,
        // RFC 6793: attribute-discard
        attr_type_code::AS4_PATH => PathAttrError::Discard,
        attr_type_code::AS4_AGGREGATOR => PathAttrError::Discard,
        // Unknown optional: attribute-discard
        _ => PathAttrError::Discard,
    }
}

// Re-export community functions and constants
pub use super::community::{asn, from_asn_value, value};
pub use super::community::{NO_ADVERTISE, NO_EXPORT, NO_EXPORT_SUBCONFED};

// Re-export extended community functions and constants
pub use super::ext_community::{
    ext_subtype, ext_type, ext_value, format_extended_community, from_four_octet_as, from_ipv4,
    from_two_octet_as, parse_extended_community,
};
pub use super::ext_community::{
    SUBTYPE_ROUTE_ORIGIN, SUBTYPE_ROUTE_TARGET, TYPE_EVPN, TYPE_FOUR_OCTET_AS, TYPE_IPV4_ADDRESS,
    TYPE_TRANSITIVE_OPAQUE, TYPE_TWO_OCTET_AS,
};

// Re-export large community
pub use super::large_community::{parse_large_community, LargeCommunity};

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct PathAttrFlag(pub u8);

impl PathAttrFlag {
    pub const OPTIONAL: u8 = 1 << 7;
    pub const TRANSITIVE: u8 = 1 << 6;
    pub const PARTIAL: u8 = 1 << 5;
    pub const EXTENDED_LENGTH: u8 = 1 << 4;

    pub(super) fn extended_len(&self) -> bool {
        self.0 & Self::EXTENDED_LENGTH != 0
    }

    pub(super) fn header_len(&self) -> usize {
        if self.extended_len() {
            4
        } else {
            3
        }
    }
}

// Public constants for use in tests
pub mod attr_flags {
    pub const OPTIONAL: u8 = 1 << 7;
    pub const TRANSITIVE: u8 = 1 << 6;
    pub const PARTIAL: u8 = 1 << 5;
    pub const EXTENDED_LENGTH: u8 = 1 << 4;
}

pub mod attr_type_code {
    pub const ORIGIN: u8 = 1;
    pub const AS_PATH: u8 = 2;
    pub const NEXT_HOP: u8 = 3;
    pub const MULTI_EXIT_DISC: u8 = 4;
    pub const LOCAL_PREF: u8 = 5;
    pub const ATOMIC_AGGREGATE: u8 = 6;
    pub const AGGREGATOR: u8 = 7;
    pub const COMMUNITIES: u8 = 8;
    pub const ORIGINATOR_ID: u8 = 9;
    pub const CLUSTER_LIST: u8 = 10;
    pub const MP_REACH_NLRI: u8 = 14;
    pub const MP_UNREACH_NLRI: u8 = 15;
    pub const EXTENDED_COMMUNITIES: u8 = 16;
    pub const AS4_PATH: u8 = 17;
    pub const AS4_AGGREGATOR: u8 = 18;
    pub const LINK_STATE: u8 = 29;
    pub const LARGE_COMMUNITIES: u8 = 32;
}

// RFC 6793: AS_TRANS and 4-byte ASN constants
pub const AS_TRANS: u16 = 23456;
pub const MAX_2BYTE_ASN: u32 = 65535;

/// A prefix with its optional ADD-PATH path identifier (RFC 7911).
#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub struct Nlri {
    pub prefix: IpNetwork,
    pub path_id: Option<u32>,
}

/// Pair each prefix with the same path identifier.
pub fn make_nlri_list(prefixes: &[IpNetwork], path_id: Option<u32>) -> Vec<Nlri> {
    prefixes
        .iter()
        .map(|net| Nlri {
            prefix: *net,
            path_id,
        })
        .collect()
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct MpReachNlri {
    pub afi: Afi,
    pub safi: Safi,
    pub next_hop: NextHopAddr,
    pub nlri: Vec<Nlri>,
    pub ls_nlri: Vec<LsNlri>,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct MpUnreachNlri {
    pub afi: Afi,
    pub safi: Safi,
    pub withdrawn_routes: Vec<Nlri>,
    pub ls_withdrawn: Vec<LsNlri>,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub enum PathAttrValue {
    Origin(Origin),
    AsPath(AsPath),
    NextHop(NextHopAddr),
    MultiExtiDisc(u32),
    LocalPref(u32),
    AtomicAggregate,
    Aggregator(Aggregator),
    Communities(Vec<u32>),
    OriginatorId(Ipv4Addr),
    ClusterList(Vec<Ipv4Addr>),
    MpReachNlri(MpReachNlri),
    MpUnreachNlri(MpUnreachNlri),
    ExtendedCommunities(Vec<u64>),
    As4Path(AsPath),
    As4Aggregator(Aggregator),
    LargeCommunities(Vec<LargeCommunity>),
    LsAttr(LsAttr),
    Unknown {
        type_code: u8,
        flags: u8,
        data: Vec<u8>,
    },
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct PathAttribute {
    pub(super) flags: PathAttrFlag,
    pub value: PathAttrValue,
}

impl PathAttribute {
    pub fn new(flags: PathAttrFlag, value: PathAttrValue) -> Self {
        PathAttribute { flags, value }
    }

    pub fn is_unknown_transitive(&self) -> bool {
        if let PathAttrValue::Unknown { flags, .. } = &self.value {
            flags & attr_flags::TRANSITIVE != 0
        } else {
            false
        }
    }

    pub(super) fn type_code(&self) -> u8 {
        match &self.value {
            PathAttrValue::Origin(_) => attr_type_code::ORIGIN,
            PathAttrValue::AsPath(_) => attr_type_code::AS_PATH,
            PathAttrValue::NextHop(_) => attr_type_code::NEXT_HOP,
            PathAttrValue::MultiExtiDisc(_) => attr_type_code::MULTI_EXIT_DISC,
            PathAttrValue::LocalPref(_) => attr_type_code::LOCAL_PREF,
            PathAttrValue::AtomicAggregate => attr_type_code::ATOMIC_AGGREGATE,
            PathAttrValue::Aggregator(_) => attr_type_code::AGGREGATOR,
            PathAttrValue::Communities(_) => attr_type_code::COMMUNITIES,
            PathAttrValue::OriginatorId(_) => attr_type_code::ORIGINATOR_ID,
            PathAttrValue::ClusterList(_) => attr_type_code::CLUSTER_LIST,
            PathAttrValue::MpReachNlri(_) => attr_type_code::MP_REACH_NLRI,
            PathAttrValue::MpUnreachNlri(_) => attr_type_code::MP_UNREACH_NLRI,
            PathAttrValue::ExtendedCommunities(_) => attr_type_code::EXTENDED_COMMUNITIES,
            PathAttrValue::As4Path(_) => attr_type_code::AS4_PATH,
            PathAttrValue::As4Aggregator(_) => attr_type_code::AS4_AGGREGATOR,
            PathAttrValue::LargeCommunities(_) => attr_type_code::LARGE_COMMUNITIES,
            PathAttrValue::LsAttr(_) => attr_type_code::LINK_STATE,
            PathAttrValue::Unknown { type_code, .. } => *type_code,
        }
    }
}

#[repr(u8)]
pub(crate) enum AttrType {
    Origin = 1,
    AsPath = 2,
    NextHop = 3,
    MultiExtiDisc = 4,
    LocalPref = 5,
    AtomicAggregate = 6,
    Aggregator = 7,
    Communities = 8,
    OriginatorId = 9,
    ClusterList = 10,
    MpReachNlri = 14,
    MpUnreachNlri = 15,
    ExtendedCommunities = 16,
    As4Path = 17,
    As4Aggregator = 18,
    LinkState = 29,
    LargeCommunities = 32,
}

impl TryFrom<u8> for AttrType {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AttrType::Origin),
            2 => Ok(AttrType::AsPath),
            3 => Ok(AttrType::NextHop),
            4 => Ok(AttrType::MultiExtiDisc),
            5 => Ok(AttrType::LocalPref),
            6 => Ok(AttrType::AtomicAggregate),
            7 => Ok(AttrType::Aggregator),
            8 => Ok(AttrType::Communities),
            9 => Ok(AttrType::OriginatorId),
            10 => Ok(AttrType::ClusterList),
            14 => Ok(AttrType::MpReachNlri),
            15 => Ok(AttrType::MpUnreachNlri),
            16 => Ok(AttrType::ExtendedCommunities),
            17 => Ok(AttrType::As4Path),
            18 => Ok(AttrType::As4Aggregator),
            29 => Ok(AttrType::LinkState),
            32 => Ok(AttrType::LargeCommunities),
            _ => Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::Unknown(0)),
                data: Vec::new(),
            }),
        }
    }
}

impl AttrType {
    pub(super) fn expected_flags(&self) -> u8 {
        match self {
            AttrType::Origin => PathAttrFlag::TRANSITIVE,
            AttrType::AsPath => PathAttrFlag::TRANSITIVE,
            AttrType::NextHop => PathAttrFlag::TRANSITIVE,
            AttrType::MultiExtiDisc => PathAttrFlag::OPTIONAL,
            AttrType::LocalPref => PathAttrFlag::TRANSITIVE,
            AttrType::AtomicAggregate => PathAttrFlag::TRANSITIVE,
            AttrType::Aggregator => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::Communities => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            // RFC 4456: ORIGINATOR_ID and CLUSTER_LIST are optional, non-transitive
            AttrType::OriginatorId => PathAttrFlag::OPTIONAL,
            AttrType::ClusterList => PathAttrFlag::OPTIONAL,
            AttrType::MpReachNlri => PathAttrFlag::OPTIONAL,
            AttrType::MpUnreachNlri => PathAttrFlag::OPTIONAL,
            AttrType::ExtendedCommunities => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::As4Path => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::As4Aggregator => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::LinkState => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::LargeCommunities => PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
        }
    }

    pub(super) fn is_well_known(&self) -> bool {
        matches!(
            self,
            AttrType::Origin
                | AttrType::AsPath
                | AttrType::NextHop
                | AttrType::LocalPref
                | AttrType::AtomicAggregate
        )
    }

    pub(super) fn is_optional(&self) -> bool {
        matches!(
            self,
            AttrType::MultiExtiDisc
                | AttrType::Aggregator
                | AttrType::Communities
                | AttrType::OriginatorId
                | AttrType::ClusterList
                | AttrType::MpReachNlri
                | AttrType::MpUnreachNlri
                | AttrType::ExtendedCommunities
                | AttrType::As4Path
                | AttrType::As4Aggregator
                | AttrType::LinkState
                | AttrType::LargeCommunities
        )
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Origin {
    IGP = 0,
    EGP = 1,
    INCOMPLETE = 2,
}

impl TryFrom<u8> for Origin {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Origin::IGP),
            1 => Ok(Origin::EGP),
            2 => Ok(Origin::INCOMPLETE),
            _ => Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::InvalidOriginAttribute),
                data: Vec::new(),
            }),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct AsPathSegment {
    pub segment_type: AsPathSegmentType,
    pub segment_len: u8,
    pub asn_list: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
    AsConfedSequence = 3,
    AsConfedSet = 4,
}

impl TryFrom<u8> for AsPathSegmentType {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AsPathSegmentType::AsSet),
            2 => Ok(AsPathSegmentType::AsSequence),
            3 => Ok(AsPathSegmentType::AsConfedSequence),
            4 => Ok(AsPathSegmentType::AsConfedSet),
            _ => Err(ParserError::BgpError {
                error: BgpError::UpdateMessageError(UpdateMessageError::MalformedASPath),
                data: Vec::new(),
            }),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Hash)]
pub enum NextHopAddr {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    /// RFC 2545: global + link-local IPv6 next-hop (32-byte form in MP_REACH_NLRI)
    Ipv6WithLinkLocal(Ipv6Addr, Ipv6Addr),
}

impl std::fmt::Display for NextHopAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NextHopAddr::Ipv4(addr) => write!(f, "{}", addr),
            NextHopAddr::Ipv6(addr) => write!(f, "{}", addr),
            NextHopAddr::Ipv6WithLinkLocal(global, link_local) => {
                write!(f, "{} ({})", link_local, global)
            }
        }
    }
}

impl NextHopAddr {
    pub fn is_unspecified(&self) -> bool {
        match self {
            NextHopAddr::Ipv4(addr) => addr.is_unspecified(),
            NextHopAddr::Ipv6(addr) => addr.is_unspecified(),
            NextHopAddr::Ipv6WithLinkLocal(global, link_local) => {
                global.is_unspecified() && link_local.is_unspecified()
            }
        }
    }

    /// Returns the global IPv6 address, stripping any link-local component.
    pub fn global_addr(&self) -> NextHopAddr {
        match self {
            NextHopAddr::Ipv6WithLinkLocal(global, _) => NextHopAddr::Ipv6(*global),
            other => *other,
        }
    }

    /// Returns the link-local address if present.
    pub fn link_local(&self) -> Option<Ipv6Addr> {
        match self {
            NextHopAddr::Ipv6WithLinkLocal(_, link_local) => Some(*link_local),
            _ => None,
        }
    }
}

impl From<std::net::IpAddr> for NextHopAddr {
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(v4) => NextHopAddr::Ipv4(v4),
            std::net::IpAddr::V6(v6) => NextHopAddr::Ipv6(v6),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct AsPath {
    pub segments: Vec<AsPathSegment>,
}

impl AsPath {
    /// Returns the leftmost AS in the AS_PATH (first AS of the first segment).
    /// Per RFC 4271, this is the AS that most recently added itself to the path.
    pub fn leftmost_as(&self) -> Option<u32> {
        self.segments
            .first()
            .and_then(|seg| seg.asn_list.first().copied())
    }
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct Aggregator {
    pub asn: u32,
    pub ip_addr: Ipv4Addr, // IPv4 only (RFC 4271)
}
