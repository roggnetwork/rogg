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

/// A single TLV (Type-Length-Value) used throughout BGP-LS:
/// NLRI descriptors, node/link/prefix attributes, and opaque forwarding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LsTlv {
    pub tlv_type: u16,
    pub value: Vec<u8>,
}

/// NLRI descriptor TLV type codes (RFC 9552 Section 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LsTlvType {
    LocalNodeDescriptors = 256,
    RemoteNodeDescriptors = 257,
    LinkLocalRemoteId = 258,
    Ipv4InterfaceAddr = 259,
    Ipv4NeighborAddr = 260,
    Ipv6InterfaceAddr = 261,
    Ipv6NeighborAddr = 262,
    MultiTopologyId = 263,
    OspfRouteType = 264,
    IpReachabilityInfo = 265,
    AutonomousSystem = 512,
    BgpLsId = 513,
    OspfAreaId = 514,
    IgpRouterId = 515,
}

impl LsTlvType {
    pub fn from_u16(val: u16) -> Option<LsTlvType> {
        match val {
            256 => Some(LsTlvType::LocalNodeDescriptors),
            257 => Some(LsTlvType::RemoteNodeDescriptors),
            258 => Some(LsTlvType::LinkLocalRemoteId),
            259 => Some(LsTlvType::Ipv4InterfaceAddr),
            260 => Some(LsTlvType::Ipv4NeighborAddr),
            261 => Some(LsTlvType::Ipv6InterfaceAddr),
            262 => Some(LsTlvType::Ipv6NeighborAddr),
            263 => Some(LsTlvType::MultiTopologyId),
            264 => Some(LsTlvType::OspfRouteType),
            265 => Some(LsTlvType::IpReachabilityInfo),
            512 => Some(LsTlvType::AutonomousSystem),
            513 => Some(LsTlvType::BgpLsId),
            514 => Some(LsTlvType::OspfAreaId),
            515 => Some(LsTlvType::IgpRouterId),
            _ => None,
        }
    }
}

/// BGP-LS Attribute TLV type codes (RFC 9552 Section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LsAttrTlvType {
    // Node Attribute TLVs (Section 5.3.1)
    NodeFlagBits = 1024,
    OpaqueNodeAttr = 1025,
    NodeName = 1026,
    IsisAreaId = 1027,
    Ipv4RouterIdLocal = 1028,
    Ipv6RouterIdLocal = 1029,
    // Link Attribute TLVs (Section 5.3.2)
    Ipv4RouterIdRemote = 1030,
    Ipv6RouterIdRemote = 1031,
    AdminGroup = 1088,
    MaxLinkBw = 1089,
    MaxRsvblLinkBw = 1090,
    UnreservedBw = 1091,
    TeDefaultMetric = 1092,
    LinkProtection = 1093,
    MplsProtocolMask = 1094,
    IgpMetric = 1095,
    Srlg = 1096,
    OpaqueLinkAttr = 1097,
    LinkName = 1098,
    // Prefix Attribute TLVs (Section 5.3.3)
    IgpFlags = 1152,
    IgpRouteTag = 1153,
    IgpExtendedRouteTag = 1154,
    PrefixMetric = 1155,
    OspfFwdAddr = 1156,
    OpaquePrefixAttr = 1157,
}

impl LsAttrTlvType {
    pub fn from_u16(val: u16) -> Option<LsAttrTlvType> {
        match val {
            1024 => Some(LsAttrTlvType::NodeFlagBits),
            1025 => Some(LsAttrTlvType::OpaqueNodeAttr),
            1026 => Some(LsAttrTlvType::NodeName),
            1027 => Some(LsAttrTlvType::IsisAreaId),
            1028 => Some(LsAttrTlvType::Ipv4RouterIdLocal),
            1029 => Some(LsAttrTlvType::Ipv6RouterIdLocal),
            1030 => Some(LsAttrTlvType::Ipv4RouterIdRemote),
            1031 => Some(LsAttrTlvType::Ipv6RouterIdRemote),
            1088 => Some(LsAttrTlvType::AdminGroup),
            1089 => Some(LsAttrTlvType::MaxLinkBw),
            1090 => Some(LsAttrTlvType::MaxRsvblLinkBw),
            1091 => Some(LsAttrTlvType::UnreservedBw),
            1092 => Some(LsAttrTlvType::TeDefaultMetric),
            1093 => Some(LsAttrTlvType::LinkProtection),
            1094 => Some(LsAttrTlvType::MplsProtocolMask),
            1095 => Some(LsAttrTlvType::IgpMetric),
            1096 => Some(LsAttrTlvType::Srlg),
            1097 => Some(LsAttrTlvType::OpaqueLinkAttr),
            1098 => Some(LsAttrTlvType::LinkName),
            1152 => Some(LsAttrTlvType::IgpFlags),
            1153 => Some(LsAttrTlvType::IgpRouteTag),
            1154 => Some(LsAttrTlvType::IgpExtendedRouteTag),
            1155 => Some(LsAttrTlvType::PrefixMetric),
            1156 => Some(LsAttrTlvType::OspfFwdAddr),
            1157 => Some(LsAttrTlvType::OpaquePrefixAttr),
            _ => None,
        }
    }
}
