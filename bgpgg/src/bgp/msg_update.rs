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

// Re-export public types
pub use super::msg_update_types::{
    attr_flags, attr_type_code, Aggregator, AsPath, AsPathSegment, AsPathSegmentType,
    LargeCommunity, NextHopAddr, Origin, PathAttrFlag, PathAttrValue, PathAttribute,
};

use super::bgpls_attr::LsAttr;
use super::bgpls_nlri::LsNlri;
use super::msg::{Message, MessageFormat, MessageType};
use super::msg_update_codec::{
    format_bytes_hex, read_path_attributes, validate_update_message_lengths,
    validate_well_known_mandatory_attributes, write_nlri_list, write_path_attributes,
};
use super::msg_update_types::{
    make_nlri_list, MpReachNlri, MpUnreachNlri, Nlri, AS_TRANS, MAX_2BYTE_ASN,
};
use super::multiprotocol::{Afi, AfiSafi, Safi};
use super::utils::{parse_nlri_list, ParserError};
use crate::log::warn;
use crate::net::IpNetwork;
use crate::rib::Path;
use std::collections::HashSet;

pub(super) const WITHDRAWN_ROUTES_LENGTH_SIZE: usize = 2;
pub(super) const TOTAL_ATTR_LENGTH_SIZE: usize = 2;

impl UpdateMessage {
    /// Create an UPDATE for IP routes. IPv4 -> traditional NLRI + NEXT_HOP attr,
    /// IPv6 -> MP_REACH_NLRI.
    pub fn new(path: &Path, nlri_list: Vec<IpNetwork>, format: MessageFormat) -> Self {
        let (ipv4_routes, ipv6_routes): (Vec<_>, Vec<_>) = nlri_list
            .into_iter()
            .partition(|p| matches!(p, IpNetwork::V4(_)));

        let mut path_attributes = Self::build_common_path_attrs(path);

        // Traditional NEXT_HOP attribute (attr 3) -- only for IPv4 unicast.
        // Other families carry next-hop inside MP_REACH_NLRI (RFC 4760 Section 3).
        if !ipv4_routes.is_empty() && matches!(path.next_hop(), NextHopAddr::Ipv4(_)) {
            path_attributes.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::NextHop(*path.next_hop()),
            });
        }

        let ipv4_path_id =
            path.path_id_for(&format.add_path, &AfiSafi::new(Afi::Ipv4, Safi::Unicast));
        let ipv6_path_id =
            path.path_id_for(&format.add_path, &AfiSafi::new(Afi::Ipv6, Safi::Unicast));

        if !ipv6_routes.is_empty() {
            path_attributes.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                value: PathAttrValue::MpReachNlri(MpReachNlri {
                    afi: Afi::Ipv6,
                    safi: Safi::Unicast,
                    next_hop: *path.next_hop(),
                    nlri: make_nlri_list(&ipv6_routes, ipv6_path_id),
                    ls_nlri: vec![],
                }),
            });
        }

        UpdateMessage {
            withdrawn_routes_len: 0,
            withdrawn_routes: vec![],
            total_path_attributes_len: write_path_attributes(&path_attributes, format.use_4byte_asn)
                .len() as u16,
            path_attributes,
            nlri_list: make_nlri_list(&ipv4_routes, ipv4_path_id),
            format,
        }
    }

    /// Create an UPDATE for BGP-LS routes. NLRIs go in MP_REACH_NLRI with AFI 16388.
    pub fn new_ls(
        path: &Path,
        ls_nlri: Vec<LsNlri>,
        afi_safi: AfiSafi,
        format: MessageFormat,
    ) -> Self {
        let mut path_attributes = Self::build_common_path_attrs(path);

        path_attributes.push(PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
            value: PathAttrValue::MpReachNlri(MpReachNlri {
                afi: afi_safi.afi,
                safi: afi_safi.safi,
                next_hop: *path.next_hop(),
                nlri: vec![],
                ls_nlri,
            }),
        });

        // BGP-LS Attribute (type 29) -- RFC 9552 Section 8.2.2: omit if absent
        if let Some(ref ls_attr) = path.attrs.ls_attr {
            path_attributes.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::LsAttr(ls_attr.clone()),
            });
        }

        UpdateMessage {
            withdrawn_routes_len: 0,
            withdrawn_routes: vec![],
            total_path_attributes_len: write_path_attributes(&path_attributes, format.use_4byte_asn)
                .len() as u16,
            path_attributes,
            nlri_list: vec![],
            format,
        }
    }

    /// Create a withdrawal UPDATE for IP routes. IPv4 -> traditional withdrawn field,
    /// IPv6 -> MP_UNREACH_NLRI.
    pub fn new_withdraw(withdrawn: Vec<Nlri>, format: MessageFormat) -> Self {
        let (ipv4_withdrawn, ipv6_withdrawn): (Vec<_>, Vec<_>) = withdrawn
            .into_iter()
            .partition(|nlri| matches!(nlri.prefix, IpNetwork::V4(_)));

        let mut path_attributes = vec![];

        if !ipv6_withdrawn.is_empty() {
            path_attributes.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                value: PathAttrValue::MpUnreachNlri(MpUnreachNlri {
                    afi: Afi::Ipv6,
                    safi: Safi::Unicast,
                    withdrawn_routes: ipv6_withdrawn,
                    ls_withdrawn: vec![],
                }),
            });
        }

        let withdrawn_routes = ipv4_withdrawn;

        UpdateMessage {
            withdrawn_routes_len: write_nlri_list(&withdrawn_routes).len() as u16,
            total_path_attributes_len: write_path_attributes(&path_attributes, format.use_4byte_asn)
                .len() as u16,
            withdrawn_routes,
            path_attributes,
            nlri_list: vec![],
            format,
        }
    }

    /// Create a withdrawal UPDATE for BGP-LS routes via MP_UNREACH_NLRI.
    pub fn new_ls_withdraw(
        ls_withdrawn: Vec<LsNlri>,
        afi_safi: AfiSafi,
        format: MessageFormat,
    ) -> Self {
        let path_attributes = vec![PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
            value: PathAttrValue::MpUnreachNlri(MpUnreachNlri {
                afi: afi_safi.afi,
                safi: afi_safi.safi,
                withdrawn_routes: vec![],
                ls_withdrawn,
            }),
        }];

        UpdateMessage {
            withdrawn_routes_len: 0,
            total_path_attributes_len: write_path_attributes(&path_attributes, format.use_4byte_asn)
                .len() as u16,
            withdrawn_routes: vec![],
            path_attributes,
            nlri_list: vec![],
            format,
        }
    }

    /// Build common path attributes shared by all UPDATE types.
    fn build_common_path_attrs(path: &Path) -> Vec<PathAttribute> {
        let mut attrs = vec![
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::Origin(path.origin()),
            },
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AsPath(AsPath {
                    segments: path.as_path().clone(),
                }),
            },
        ];

        if let Some(pref) = path.local_pref() {
            attrs.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::LocalPref(pref),
            });
        }

        if let Some(metric) = path.med() {
            attrs.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                value: PathAttrValue::MultiExtiDisc(metric),
            });
        }

        if path.atomic_aggregate() {
            attrs.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AtomicAggregate,
            });
        }

        if let Some(ref agg) = path.aggregator() {
            attrs.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::Aggregator(agg.clone()),
            });
        }

        if !path.communities().is_empty() {
            attrs.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::Communities(path.communities().clone()),
            });
        }

        if let Some(originator) = path.originator_id() {
            attrs.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                value: PathAttrValue::OriginatorId(originator),
            });
        }

        if !path.cluster_list().is_empty() {
            attrs.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                value: PathAttrValue::ClusterList(path.cluster_list().clone()),
            });
        }

        if !path.extended_communities().is_empty() {
            attrs.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::ExtendedCommunities(path.extended_communities().clone()),
            });
        }

        if !path.large_communities().is_empty() {
            attrs.push(PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::LargeCommunities(path.large_communities().clone()),
            });
        }

        attrs.extend(path.unknown_attrs().clone());

        attrs
    }

    pub fn nlri_prefixes(&self) -> Vec<IpNetwork> {
        let mut prefixes: Vec<IpNetwork> = self.nlri_list.iter().map(|nlri| nlri.prefix).collect();

        // Add NLRI from MP_REACH_NLRI if present
        for attr in &self.path_attributes {
            if let PathAttrValue::MpReachNlri(ref mp_reach) = attr.value {
                prefixes.extend(mp_reach.nlri.iter().map(|nlri| nlri.prefix));
            }
        }

        prefixes
    }

    /// Returns all NLRI entries with their path identifiers (RFC 7911).
    pub fn nlri_list(&self) -> Vec<Nlri> {
        let mut nlri = self.nlri_list.clone();

        for attr in &self.path_attributes {
            if let PathAttrValue::MpReachNlri(ref mp_reach) = attr.value {
                nlri.extend_from_slice(&mp_reach.nlri);
            }
        }

        nlri
    }

    pub fn withdrawn_routes(&self) -> Vec<Nlri> {
        let mut withdrawn = self.withdrawn_routes.clone();

        // Add withdrawn routes from MP_UNREACH_NLRI if present
        for attr in &self.path_attributes {
            if let PathAttrValue::MpUnreachNlri(ref mp_unreach) = attr.value {
                withdrawn.extend(mp_unreach.withdrawn_routes.clone());
            }
        }

        withdrawn
    }

    /// Returns all BGP-LS NLRIs from MP_REACH_NLRI attributes.
    pub fn ls_nlri_list(&self) -> Vec<LsNlri> {
        let mut ls_nlri = Vec::new();
        for attr in &self.path_attributes {
            if let PathAttrValue::MpReachNlri(ref mp_reach) = attr.value {
                if mp_reach.afi == Afi::LinkState {
                    ls_nlri.extend(mp_reach.ls_nlri.clone());
                }
            }
        }
        ls_nlri
    }

    /// Returns all BGP-LS withdrawn NLRIs from MP_UNREACH_NLRI attributes.
    pub fn ls_withdrawn_list(&self) -> Vec<LsNlri> {
        let mut ls_withdrawn = Vec::new();
        for attr in &self.path_attributes {
            if let PathAttrValue::MpUnreachNlri(ref mp_unreach) = attr.value {
                if mp_unreach.afi == Afi::LinkState {
                    ls_withdrawn.extend(mp_unreach.ls_withdrawn.clone());
                }
            }
        }
        ls_withdrawn
    }

    pub fn origin(&self) -> Option<Origin> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::Origin(origin) = attr.value {
                Some(origin)
            } else {
                None
            }
        })
    }

    pub fn as_path(&self) -> Option<Vec<AsPathSegment>> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::AsPath(ref as_path) = attr.value {
                Some(as_path.segments.clone())
            } else {
                None
            }
        })
    }

    /// RFC 6793: Extract AS4_PATH attribute if present
    pub fn as4_path(&self) -> Option<Vec<AsPathSegment>> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::As4Path(ref as4_path) = attr.value {
                Some(as4_path.segments.clone())
            } else {
                None
            }
        })
    }

    /// RFC 6793: Extract AGGREGATOR attribute if present
    pub fn aggregator(&self) -> Option<Aggregator> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::Aggregator(ref aggregator) = attr.value {
                Some(aggregator.clone())
            } else {
                None
            }
        })
    }

    /// RFC 6793: Extract AS4_AGGREGATOR attribute if present
    pub fn as4_aggregator(&self) -> Option<Aggregator> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::As4Aggregator(ref as4_aggregator) = attr.value {
                Some(as4_aggregator.clone())
            } else {
                None
            }
        })
    }

    /// RFC 6793: Transform AS_PATH for old speakers (2-byte ASN only)
    /// Returns replacement attributes: AS_PATH with AS_TRANS + AS4_PATH
    fn transform_as_path_for_old_speaker(
        attr: &PathAttribute,
        as_path: &AsPath,
    ) -> Vec<PathAttribute> {
        // Check if any ASN > 65535
        let has_large_asn = as_path
            .segments
            .iter()
            .any(|seg| seg.asn_list.iter().any(|&asn| asn > MAX_2BYTE_ASN));

        if !has_large_asn {
            // No large ASNs, keep as-is
            return vec![attr.clone()];
        }

        let mut result = Vec::new();

        // Create AS_PATH with AS_TRANS substitution
        let mut segments_2byte = Vec::new();
        for seg in &as_path.segments {
            let asn_list_2byte: Vec<u32> = seg
                .asn_list
                .iter()
                .map(|&asn| {
                    if asn > MAX_2BYTE_ASN {
                        AS_TRANS as u32
                    } else {
                        asn
                    }
                })
                .collect();
            segments_2byte.push(AsPathSegment {
                segment_type: seg.segment_type,
                segment_len: seg.segment_len,
                asn_list: asn_list_2byte,
            });
        }

        result.push(PathAttribute {
            flags: attr.flags.clone(),
            value: PathAttrValue::AsPath(AsPath {
                segments: segments_2byte,
            }),
        });

        // Generate AS4_PATH (exclude confederation segments per RFC 6793)
        let segments_4byte: Vec<AsPathSegment> = as_path
            .segments
            .iter()
            .filter(|seg| {
                !matches!(
                    seg.segment_type,
                    AsPathSegmentType::AsConfedSequence | AsPathSegmentType::AsConfedSet
                )
            })
            .cloned()
            .collect();

        if !segments_4byte.is_empty() {
            result.push(PathAttribute {
                flags: PathAttrFlag(attr_flags::OPTIONAL | attr_flags::TRANSITIVE),
                value: PathAttrValue::As4Path(AsPath {
                    segments: segments_4byte,
                }),
            });
        }

        result
    }

    /// RFC 6793: Transform AGGREGATOR for old speakers (2-byte ASN only)
    /// Returns replacement attributes: AGGREGATOR with AS_TRANS + AS4_AGGREGATOR
    fn transform_aggregator_for_old_speaker(
        attr: &PathAttribute,
        agg: &Aggregator,
    ) -> Vec<PathAttribute> {
        if agg.asn <= MAX_2BYTE_ASN {
            // ASN fits in 2 bytes, keep as-is
            return vec![attr.clone()];
        }

        vec![
            // AGGREGATOR with AS_TRANS
            PathAttribute {
                flags: attr.flags.clone(),
                value: PathAttrValue::Aggregator(Aggregator {
                    asn: AS_TRANS as u32,
                    ip_addr: agg.ip_addr,
                }),
            },
            // AS4_AGGREGATOR with real ASN
            PathAttribute {
                flags: PathAttrFlag(attr_flags::OPTIONAL | attr_flags::TRANSITIVE),
                value: PathAttrValue::As4Aggregator(agg.clone()),
            },
        ]
    }

    /// RFC 6793 Section 4.1: Strip AS4_PATH/AS4_AGGREGATOR from NEW speakers
    /// NEW speakers MUST NOT send these attributes to other NEW speakers
    /// This method discards them when received (protocol violation)
    pub fn strip_as4_attributes(&mut self) {
        self.path_attributes.retain(|attr| {
            !matches!(
                attr.value,
                PathAttrValue::As4Path(_) | PathAttrValue::As4Aggregator(_)
            )
        });
    }

    pub fn path_attributes(&self) -> &[PathAttribute] {
        &self.path_attributes
    }

    /// Returns the leftmost AS in the AS_PATH attribute.
    pub fn leftmost_as(&self) -> Option<u32> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::AsPath(ref as_path) = attr.value {
                as_path.leftmost_as()
            } else {
                None
            }
        })
    }

    pub fn next_hop(&self) -> Option<NextHopAddr> {
        // First check for MP_REACH_NLRI
        for attr in &self.path_attributes {
            if let PathAttrValue::MpReachNlri(ref mp_reach) = attr.value {
                return Some(mp_reach.next_hop);
            }
        }

        // Fall back to traditional NEXT_HOP attribute
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::NextHop(ref next_hop) = attr.value {
                Some(*next_hop)
            } else {
                None
            }
        })
    }

    pub fn local_pref(&self) -> Option<u32> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::LocalPref(pref) = attr.value {
                Some(pref)
            } else {
                None
            }
        })
    }

    pub fn med(&self) -> Option<u32> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::MultiExtiDisc(med) = attr.value {
                Some(med)
            } else {
                None
            }
        })
    }

    pub fn atomic_aggregate(&self) -> bool {
        self.path_attributes
            .iter()
            .any(|attr| attr.value == PathAttrValue::AtomicAggregate)
    }

    pub fn unknown_attrs(&self) -> Vec<PathAttribute> {
        self.path_attributes
            .iter()
            .filter_map(|attr| {
                if matches!(attr.value, PathAttrValue::Unknown { .. }) {
                    Some(attr.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn communities(&self) -> Option<Vec<u32>> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::Communities(ref communities) = attr.value {
                Some(communities.clone())
            } else {
                None
            }
        })
    }

    pub fn extended_communities(&self) -> Option<Vec<u64>> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::ExtendedCommunities(ref ext_communities) = attr.value {
                Some(ext_communities.clone())
            } else {
                None
            }
        })
    }

    pub fn large_communities(&self) -> Option<Vec<LargeCommunity>> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::LargeCommunities(ref large_communities) = attr.value {
                Some(large_communities.clone())
            } else {
                None
            }
        })
    }

    /// RFC 4456: Get ORIGINATOR_ID attribute if present
    pub fn originator_id(&self) -> Option<std::net::Ipv4Addr> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::OriginatorId(originator_id) = attr.value {
                Some(originator_id)
            } else {
                None
            }
        })
    }

    /// RFC 4456: Get CLUSTER_LIST attribute if present
    pub fn cluster_list(&self) -> Option<Vec<std::net::Ipv4Addr>> {
        self.path_attributes.iter().find_map(|attr| {
            if let PathAttrValue::ClusterList(ref cluster_list) = attr.value {
                Some(cluster_list.clone())
            } else {
                None
            }
        })
    }

    /// RFC 9552: Get BGP-LS Attribute (type 29) if present
    pub fn ls_attr(&self) -> Option<LsAttr> {
        self.path_attributes
            .iter()
            .find_map(|attr| match &attr.value {
                PathAttrValue::LsAttr(ls_attr) => Some(ls_attr.clone()),
                _ => None,
            })
    }

    pub fn use_4byte_asn(&self) -> bool {
        self.format.use_4byte_asn
    }

    pub fn from_bytes(bytes: Vec<u8>, format: MessageFormat) -> Result<UpdateMessage, ParserError> {
        let body_length = bytes.len();
        let data = &bytes[..];

        // Standard withdrawn/NLRI fields are always IPv4 Unicast (RFC 4271)
        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        let ipv4_add_path = format.add_path.contains(&ipv4_unicast);

        let mut offset = 0;

        let withdrawn_routes_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        offset += WITHDRAWN_ROUTES_LENGTH_SIZE;

        // RFC 7606 Section 3: syntactically incorrect Withdrawn Routes field
        // SHOULD be handled as treat-as-withdraw. Skip ahead using
        // withdrawn_routes_len and treat the entire UPDATE as a withdrawal.
        let (withdrawn_routes, mut treat_as_withdraw) =
            match parse_nlri_list(&data[offset..offset + withdrawn_routes_len], ipv4_add_path) {
                Ok(routes) => (routes, false),
                Err(_) => {
                    warn!(
                        withdrawn_routes_len,
                        "malformed withdrawn routes NLRI, treat-as-withdraw per RFC 7606 Section 3"
                    );
                    (vec![], true)
                }
            };
        offset += withdrawn_routes_len;

        let total_path_attributes_len =
            u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;

        validate_update_message_lengths(
            withdrawn_routes_len,
            total_path_attributes_len,
            body_length,
        )?;
        offset += TOTAL_ATTR_LENGTH_SIZE;

        let (path_attributes, attr_treat_as_withdraw) =
            read_path_attributes(&data[offset..offset + total_path_attributes_len], format)?;
        treat_as_withdraw |= attr_treat_as_withdraw;
        offset += total_path_attributes_len;

        let nlri_list: Vec<Nlri> = match total_path_attributes_len {
            0 => vec![],
            _ => parse_nlri_list(&data[offset..], ipv4_add_path)?,
        };

        // RFC 4271 Section 5 + RFC 4760 Section 3: ORIGIN and AS_PATH must
        // be present when advertising routes via either NLRI field or MP_REACH_NLRI.
        let has_mp_reach_nlri = path_attributes.iter().any(
            |attr| matches!(&attr.value, PathAttrValue::MpReachNlri(mp) if !mp.nlri.is_empty()),
        );
        if !nlri_list.is_empty() || has_mp_reach_nlri {
            treat_as_withdraw |= !validate_well_known_mandatory_attributes(&path_attributes);
        }

        if treat_as_withdraw {
            if should_escalate_to_session_reset(
                &nlri_list,
                has_mp_reach_nlri,
                &path_attributes,
                total_path_attributes_len,
            ) {
                warn!("treat-as-withdraw with no reachable NLRI, escalating to session reset per RFC 7606 Section 5.2");
                return Err(ParserError::BgpError {
                    error: super::msg_notification::BgpError::UpdateMessageError(
                        super::msg_notification::UpdateMessageError::MalformedAttributeList,
                    ),
                    data: Vec::new(),
                });
            }

            // Collect all routes from every source into withdrawals
            let mut all_withdrawn: HashSet<Nlri> = HashSet::from_iter(withdrawn_routes);
            all_withdrawn.extend(nlri_list);
            all_withdrawn.extend(collect_mp_nlri(&path_attributes));

            // RFC 7606 Section 6: log the full UPDATE body for debugging
            warn!(
                route_count = all_withdrawn.len(),
                update_hex = %format_bytes_hex(data),
                "treat-as-withdraw per RFC 7606"
            );

            Ok(Self::new_withdraw(
                all_withdrawn.into_iter().collect(),
                format,
            ))
        } else {
            Ok(UpdateMessage {
                withdrawn_routes_len: withdrawn_routes_len as u16,
                withdrawn_routes,
                total_path_attributes_len: total_path_attributes_len as u16,
                path_attributes,
                nlri_list,
                format,
            })
        }
    }

    /// Check if this UPDATE is an End-of-RIB marker (RFC 4724)
    pub fn is_eor(&self) -> bool {
        self.eor_afi_safi().is_some()
    }

    /// Extract the AFI/SAFI from an End-of-RIB marker (RFC 4724).
    /// - IPv4 Unicast: empty UPDATE (no withdrawn, no path attributes, no NLRI)
    /// - Other AFI/SAFI: only MP_UNREACH_NLRI with empty withdrawn routes
    pub fn eor_afi_safi(&self) -> Option<AfiSafi> {
        if !self.withdrawn_routes.is_empty() || !self.nlri_list.is_empty() {
            return None;
        }

        // IPv4 Unicast EoR: completely empty UPDATE
        if self.path_attributes.is_empty() {
            return Some(AfiSafi::new(Afi::Ipv4, Safi::Unicast));
        }

        // Other AFI/SAFI EoR: single MP_UNREACH_NLRI with empty withdrawn routes
        if self.path_attributes.len() == 1 {
            if let PathAttrValue::MpUnreachNlri(ref mp_unreach) = self.path_attributes[0].value {
                if mp_unreach.withdrawn_routes.is_empty() && mp_unreach.ls_withdrawn.is_empty() {
                    return Some(AfiSafi::new(mp_unreach.afi, mp_unreach.safi));
                }
            }
        }

        None
    }

    /// Create an End-of-RIB marker (RFC 4724)
    /// For IPv4 Unicast: empty UPDATE message
    /// For all other AFI/SAFI: UPDATE with MP_UNREACH_NLRI with empty withdrawn routes
    pub fn new_eor(afi: Afi, safi: Safi, format: MessageFormat) -> Self {
        if matches!((afi, safi), (Afi::Ipv4, Safi::Unicast)) {
            // IPv4 Unicast: empty UPDATE
            UpdateMessage {
                withdrawn_routes_len: 0,
                withdrawn_routes: Vec::new(),
                total_path_attributes_len: 0,
                path_attributes: Vec::new(),
                nlri_list: Vec::new(),
                format,
            }
        } else {
            // All other AFI/SAFI: MP_UNREACH_NLRI with empty withdrawn routes
            UpdateMessage {
                withdrawn_routes_len: 0,
                withdrawn_routes: Vec::new(),
                total_path_attributes_len: 0,
                path_attributes: vec![PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                    value: PathAttrValue::MpUnreachNlri(MpUnreachNlri {
                        afi,
                        safi,
                        withdrawn_routes: Vec::new(),
                        ls_withdrawn: Vec::new(),
                    }),
                }],
                nlri_list: Vec::new(),
                format,
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct UpdateMessage {
    withdrawn_routes_len: u16,
    /// Each withdrawn route carries its own optional path_id for ADD-PATH
    withdrawn_routes: Vec<Nlri>,
    total_path_attributes_len: u16,
    path_attributes: Vec<PathAttribute>,
    nlri_list: Vec<Nlri>,
    /// Message encoding format based on negotiated capabilities
    format: MessageFormat,
}

impl Message for UpdateMessage {
    fn kind(&self) -> MessageType {
        MessageType::Update
    }

    fn to_bytes(&self) -> Vec<u8> {
        // RFC 6793: Transform attributes based on peer capability
        let path_attributes = if self.format.use_4byte_asn {
            // NEW speaker: Strip AS4_PATH/AS4_AGGREGATOR
            self.path_attributes
                .iter()
                .filter(|attr| {
                    !matches!(
                        attr.value,
                        PathAttrValue::As4Path(_) | PathAttrValue::As4Aggregator(_)
                    )
                })
                .cloned()
                .collect()
        } else {
            // OLD speaker: Transform AS_PATH/AGGREGATOR for 2-byte ASN encoding
            let mut new_attrs = Vec::new();
            for attr in &self.path_attributes {
                match &attr.value {
                    PathAttrValue::AsPath(as_path) => {
                        new_attrs.extend(Self::transform_as_path_for_old_speaker(attr, as_path));
                    }
                    PathAttrValue::Aggregator(agg) => {
                        new_attrs.extend(Self::transform_aggregator_for_old_speaker(attr, agg));
                    }
                    _ => {
                        new_attrs.push(attr.clone());
                    }
                }
            }
            new_attrs
        };

        let mut bytes = Vec::new();

        // Withdrawn routes
        let withdrawn_routes_bytes = write_nlri_list(&self.withdrawn_routes);
        bytes.extend_from_slice(&(withdrawn_routes_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&withdrawn_routes_bytes);

        // Path attributes
        let path_attributes_bytes =
            write_path_attributes(&path_attributes, self.format.use_4byte_asn);
        bytes.extend_from_slice(&(path_attributes_bytes.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&path_attributes_bytes);

        // NLRI
        let nlri_bytes = write_nlri_list(&self.nlri_list);
        bytes.extend_from_slice(&nlri_bytes);

        bytes
    }
}

/// RFC 7606 Section 5.2: when treat-as-withdraw is triggered on an UPDATE
/// with path attributes beyond MP_UNREACH_NLRI but no reachable NLRI, we
/// can't be confident the NLRI were successfully parsed. Escalate to session
/// reset. Uses total_path_attributes_len (wire) because malformed attrs are
/// stripped during parsing.
fn should_escalate_to_session_reset(
    nlri_list: &[Nlri],
    has_mp_reach_nlri: bool,
    path_attributes: &[PathAttribute],
    total_path_attributes_len: usize,
) -> bool {
    if !nlri_list.is_empty() || has_mp_reach_nlri {
        return false; // has reachable NLRI, treat-as-withdraw is fine
    }
    if total_path_attributes_len == 0 {
        return false; // no path attributes on wire
    }
    // Wire had path attributes but no reachable NLRI. The only safe case
    // is a pure withdraw: exactly one MP_UNREACH_NLRI and nothing else.
    !(path_attributes.len() == 1
        && matches!(path_attributes[0].value, PathAttrValue::MpUnreachNlri(_)))
}

/// Collect all NLRI from MP_REACH_NLRI and MP_UNREACH_NLRI attributes.
fn collect_mp_nlri(path_attributes: &[PathAttribute]) -> Vec<Nlri> {
    let mut nlri = Vec::new();
    for attr in path_attributes {
        match &attr.value {
            PathAttrValue::MpReachNlri(mp_reach) => nlri.extend_from_slice(&mp_reach.nlri),
            PathAttrValue::MpUnreachNlri(mp_unreach) => {
                nlri.extend_from_slice(&mp_unreach.withdrawn_routes)
            }
            _ => {}
        }
    }
    nlri
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_notification::{BgpError, UpdateMessageError};
    use crate::bgp::msg_update_codec::{
        read_path_attribute, write_path_attribute, write_path_attributes, PathAttrResult,
    };
    use crate::bgp::msg_update_types::{AttrType, MpReachNlri, MpUnreachNlri};
    use crate::bgp::multiprotocol::{Afi, Safi};
    use crate::bgp::{
        nlri_v4, ADDPATH_FORMAT, DEFAULT_FORMAT, PATH_ATTR_COMMUNITIES_TWO,
        PATH_ATTR_EXTENDED_COMMUNITIES_TWO,
    };
    use crate::net::{IpNetwork, Ipv4Net, Ipv6Net};
    use crate::rib::{PathAttrs, RouteSource};
    use crate::rpki::vrp::RpkiValidation;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    /// Test helper to create a base Path with sensible defaults
    fn test_path() -> Path {
        Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            rpki_state: RpkiValidation::NotFound,
            attrs: Arc::new(PathAttrs {
                origin: Origin::IGP,
                as_path: vec![],
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                source: RouteSource::Local,
                local_pref: None,
                med: None,
                atomic_aggregate: false,
                aggregator: None,
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
                ls_attr: None,
            }),
        }
    }

    // Sample MP_REACH_NLRI for tests (192.168.1.1, NLRI=10.0.0.0/8)
    fn sample_mp_reach() -> MpReachNlri {
        MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
            nlri: vec![nlri_v4(10, 0, 0, 0, 8, None)],
            ls_nlri: vec![],
        }
    }

    const PATH_ATTR_ORIGIN_EGP: &[u8] =
        &[PathAttrFlag::TRANSITIVE, AttrType::Origin as u8, 0x01, 1];

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

    const PATH_ATTR_NEXT_HOP_IPV4: &[u8] = &[
        PathAttrFlag::TRANSITIVE,
        AttrType::NextHop as u8,
        0x04,
        0xc8,
        0xc9,
        0xca,
        0xcb,
    ];

    const WITHDRAWN_ROUTES_BYTES: &[u8] = &[
        0x00, 0x0c, // Withdrawn routes length (12 bytes: 3 routes * 4 bytes each)
        0x18, 0x0a, 0x0b, 0x0c, // Withdrawn route #1: /24 prefix
        0x18, 0x0a, 0x0b, 0x0d, // Withdrawn route #2: /24 prefix
        0x18, 0x0a, 0x0b, 0x0e, // Withdrawn route #3: /24 prefix
    ];

    const PATH_ATTR_ORIGIN_IGP: &[u8] =
        &[PathAttrFlag::TRANSITIVE, AttrType::Origin as u8, 0x01, 0x00];

    const PATH_ATTR_AS_PATH_EMPTY: &[u8] =
        &[PathAttrFlag::TRANSITIVE, AttrType::AsPath as u8, 0x00];

    const PATH_ATTR_NEXT_HOP: &[u8] = &[
        PathAttrFlag::TRANSITIVE,
        AttrType::NextHop as u8,
        0x04,
        0x0a,
        0x00,
        0x00,
        0x01,
    ];

    const PATH_ATTR_LOCAL_PREF: &[u8] = &[
        PathAttrFlag::TRANSITIVE,
        AttrType::LocalPref as u8,
        0x04,
        0x00,
        0x00,
        0x00,
        0x64,
    ];

    const NLRI_SINGLE: &[u8] = &[0x18, 0x0a, 0x0b, 0x0c];

    fn build_update_body(attrs: &[&[u8]], nlri: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();

        // Withdrawn routes length
        body.extend_from_slice(&[0x00, 0x00]);

        // Total path attributes length
        let total_attr_len: usize = attrs.iter().map(|a| a.len()).sum();
        body.extend_from_slice(&(total_attr_len as u16).to_be_bytes());

        // Path attributes
        for attr in attrs {
            body.extend_from_slice(attr);
        }

        // NLRI
        body.extend_from_slice(nlri);

        body
    }

    macro_rules! test_message_from_bytes {
        ($name: ident, $input: expr, expected $expected:expr) => {
            #[test]
            fn $name() {
                let message = UpdateMessage::from_bytes($input, DEFAULT_FORMAT).unwrap();
                assert_eq!(message, $expected)
            }
        };
    }

    test_message_from_bytes!(
        message_from_bytes,
        [
            WITHDRAWN_ROUTES_BYTES,
            &[
                0x00, 0x18, // Total path attribute length (24 bytes)
            ],
            PATH_ATTR_ORIGIN_EGP,
            PATH_ATTR_AS_PATH,
            PATH_ATTR_NEXT_HOP_IPV4,
            &[
                0x18, 0x0a, 0x0b, 0x0f, // NLRI #1: /24 prefix
                0x18, 0x0a, 0x0b, 0x10, // NLRI #2: /24 prefix
            ]

        ].concat(),
        expected UpdateMessage{
            withdrawn_routes_len: 12,
            withdrawn_routes: vec![
                nlri_v4(10, 11, 12, 0, 24, None),
                nlri_v4(10, 11, 13, 0, 24, None),
                nlri_v4(10, 11, 14, 0, 24, None),
            ],
            total_path_attributes_len: 24,
            format: DEFAULT_FORMAT,
            path_attributes: vec![
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::Origin(Origin::try_from(1).unwrap()),
                },
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::AsPath(
                        AsPath {
                            segments: vec![
                                AsPathSegment {
                                    segment_type: AsPathSegmentType::AsSet,
                                    segment_len: 2,
                                    asn_list: vec![16, 274],
                                }
                            ]
                        }
                    ),
                },
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::NextHop(NextHopAddr::Ipv4(Ipv4Addr::new(200, 201, 202, 203))),
                }
            ],
            nlri_list: vec![
                nlri_v4(10, 11, 15, 0, 24, None),
                nlri_v4(10, 11, 16, 0, 24, None),
            ],
        }
    );

    test_message_from_bytes!(
        message_from_bytes_no_withdrawn_routes,
        [
            &[
                0x00, 0x00, // Withdrawn routes length
                0x00, 0x18, // Total path attribute length (24 bytes)
            ],
            PATH_ATTR_ORIGIN_EGP,
            PATH_ATTR_AS_PATH,
            PATH_ATTR_NEXT_HOP_IPV4,
            &[
                0x18, 0x0a, 0x0b, 0x0f, // NLRI #1: /24 prefix
            ]

        ].concat(),
        expected UpdateMessage{
            withdrawn_routes_len: 0,
            withdrawn_routes: vec![],
            total_path_attributes_len: 24,
            format: DEFAULT_FORMAT,
            path_attributes: vec![
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::Origin(Origin::try_from(1).unwrap()),
                },
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::AsPath(
                        AsPath {
                            segments: vec![
                                AsPathSegment {
                                    segment_type: AsPathSegmentType::AsSet,
                                    segment_len: 2,
                                    asn_list: vec![16, 274],
                                }
                            ]
                        }
                    ),
                },
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::NextHop(NextHopAddr::Ipv4(Ipv4Addr::new(200, 201, 202, 203))),
                }
            ],
            nlri_list: vec![
                nlri_v4(10, 11, 15, 0, 24, None),
            ],
        }
    );

    test_message_from_bytes!(
        message_from_bytes_no_path_attributes,
        [
            WITHDRAWN_ROUTES_BYTES,
            &[
                0x00, 0x00, // Total path attribute length
            ],
        ].concat(),
        expected UpdateMessage{
            withdrawn_routes_len: 12,
            withdrawn_routes: vec![
                nlri_v4(10, 11, 12, 0, 24, None),
                nlri_v4(10, 11, 13, 0, 24, None),
                nlri_v4(10, 11, 14, 0, 24, None),
            ],
            total_path_attributes_len: 0,
            format: DEFAULT_FORMAT,
            path_attributes: vec![],
            nlri_list: vec![],
        }
    );

    const INPUT_BODY: &[u8] = &[
        0x00,
        0x0c, // Withdrawn routes length (12 bytes)
        0x18,
        0x0a,
        0x0b,
        0x0c, // Withdrawn route #1: /24 prefix
        0x18,
        0x0a,
        0x0b,
        0x0d, // Withdrawn route #2: /24 prefix
        0x18,
        0x0a,
        0x0b,
        0x0e, // Withdrawn route #3: /24 prefix
        0x00,
        0x18,                     // Total path attribute length (24 bytes)
        PathAttrFlag::TRANSITIVE, // Attribute flags
        AttrType::Origin as u8,   // Attribute type
        0x01,                     // Attribute length
        1,                        // Origin value: EGP
        PathAttrFlag::TRANSITIVE, // Attribute flags
        AttrType::AsPath as u8,   // Attribute type
        0x0a,                     // Attribute length (10 bytes, 4-byte ASN)
        AsPathSegmentType::AsSet as u8,
        0x02, // Number of ASes
        0x00,
        0x00,
        0x00,
        0x10, // ASN: 16
        0x00,
        0x00,
        0x01,
        0x12,                     // ASN: 274
        PathAttrFlag::TRANSITIVE, // Attribute flags
        AttrType::NextHop as u8,  // Attribute type
        0x04,                     // Attribute length
        0xc8,
        0xc9,
        0xca,
        0xcb,
        0x18,
        0x0a,
        0x0b,
        0x0f, // NLRI #1: /24 prefix
        0x18,
        0x0a,
        0x0b,
        0x10, // NLRI #2: /24 prefix
    ];

    #[test]
    fn test_update_message_encode_decode() {
        // Decode the message
        let message = UpdateMessage::from_bytes(INPUT_BODY.to_vec(), DEFAULT_FORMAT).unwrap();

        // Encode it back
        let encoded = message.to_bytes();

        // Should match the original input
        assert_eq!(encoded, INPUT_BODY);
    }

    #[test]
    fn test_update_message_serialize() {
        // Decode the message
        let message = UpdateMessage::from_bytes(INPUT_BODY.to_vec(), DEFAULT_FORMAT).unwrap();

        // Serialize it (includes BGP header)
        let serialized = message.serialize();

        // Check BGP header
        assert_eq!(&serialized[0..16], &[0xff; 16]); // Marker
        let length = u16::from_be_bytes([serialized[16], serialized[17]]);
        assert_eq!(length, 19 + INPUT_BODY.len() as u16); // Header + body
        assert_eq!(serialized[18], 2); // Message type: UPDATE

        // Check body
        assert_eq!(&serialized[19..], INPUT_BODY);
    }

    #[test]
    fn test_new_withdraw() {
        // Create a withdraw message with multiple prefixes
        let withdrawn_nlri: Vec<Nlri> = vec![
            nlri_v4(10, 0, 0, 0, 24, None),
            nlri_v4(192, 168, 1, 0, 24, None),
        ];

        let withdrawn: Vec<Nlri> = vec![
            nlri_v4(10, 0, 0, 0, 24, None),
            nlri_v4(192, 168, 1, 0, 24, None),
        ];

        let message = UpdateMessage::new_withdraw(withdrawn, DEFAULT_FORMAT);

        // Verify message structure
        assert_eq!(message.withdrawn_routes, withdrawn_nlri);
        assert_eq!(message.path_attributes, vec![]);
        assert_eq!(message.nlri_list, vec![]);
        assert_eq!(message.total_path_attributes_len, 0);

        // Verify the withdrawn routes length is calculated correctly
        // 10.0.0.0/24 = 1 byte (prefix length) + 3 bytes (address) = 4 bytes
        // 192.168.1.0/24 = 1 byte (prefix length) + 3 bytes (address) = 4 bytes
        // Total = 8 bytes
        assert_eq!(message.withdrawn_routes_len, 8);
    }

    #[test]
    fn test_new_withdraw_serialization() {
        // Create a withdraw message
        let withdrawn: Vec<Nlri> = vec![nlri_v4(10, 0, 0, 0, 24, None)];

        let message = UpdateMessage::new_withdraw(withdrawn, DEFAULT_FORMAT);

        // Serialize the message - created with use_4byte_asn=true
        let serialized = message.serialize();

        // Verify BGP header
        assert_eq!(&serialized[0..16], &[0xff; 16]); // Marker
        let length = u16::from_be_bytes([serialized[16], serialized[17]]);
        assert_eq!(length, serialized.len() as u16); // Length field matches actual length
        assert_eq!(serialized[18], 2); // Message type: UPDATE

        // Decode the body
        let body = &serialized[19..];

        // Withdrawn routes length
        let withdrawn_len = u16::from_be_bytes([body[0], body[1]]);
        assert_eq!(withdrawn_len, 4); // 1 byte prefix length + 3 bytes address

        // Withdrawn route data
        assert_eq!(body[2], 24); // Prefix length
        assert_eq!(&body[3..6], &[10, 0, 0]); // Address (only significant octets)

        // Total path attributes length
        let path_attr_len = u16::from_be_bytes([body[6], body[7]]);
        assert_eq!(path_attr_len, 0);

        // No NLRI
        assert_eq!(body.len(), 8);
    }

    #[test]
    fn test_get_local_pref() {
        let mut path = test_path();
        path.attrs_mut().local_pref = Some(200);
        let msg = UpdateMessage::new(&path, vec![], DEFAULT_FORMAT);
        assert_eq!(msg.local_pref(), Some(200));

        let path_no_pref = test_path();
        let msg_no_pref = UpdateMessage::new(&path_no_pref, vec![], DEFAULT_FORMAT);
        assert_eq!(msg_no_pref.local_pref(), None);
    }

    #[test]
    fn test_get_med() {
        let mut path = test_path();
        path.attrs_mut().med = Some(50);
        let msg = UpdateMessage::new(&path, vec![], DEFAULT_FORMAT);
        assert_eq!(msg.med(), Some(50));

        let path_no_med = test_path();
        let msg_no_med = UpdateMessage::new(&path_no_med, vec![], DEFAULT_FORMAT);
        assert_eq!(msg_no_med.med(), None);
    }

    #[test]
    fn test_update_message_new_encode_decode() {
        let test_cases = vec![
            (Origin::IGP, None, None, false),
            (Origin::IGP, Some(200), None, false),
            (Origin::INCOMPLETE, None, Some(50), false),
            (Origin::IGP, None, None, true),
            (Origin::EGP, Some(150), Some(100), true),
        ];

        for (origin, local_pref, med, atomic_aggregate) in test_cases {
            let mut path = test_path();
            let attrs = path.attrs_mut();
            attrs.origin = origin;
            attrs.local_pref = local_pref;
            attrs.med = med;
            attrs.atomic_aggregate = atomic_aggregate;
            let msg = UpdateMessage::new(&path, vec![], DEFAULT_FORMAT);

            let bytes = msg.to_bytes();
            let parsed = UpdateMessage::from_bytes(bytes, DEFAULT_FORMAT).unwrap();

            assert_eq!(parsed.origin(), Some(origin));
            assert_eq!(parsed.as_path(), Some(vec![]));
            // No IPv4 NLRI -> no NEXT_HOP emitted (RFC 4760 Section 3)
            assert_eq!(parsed.next_hop(), None);
            assert_eq!(parsed.local_pref(), local_pref);
            assert_eq!(parsed.med(), med);
            assert_eq!(parsed.atomic_aggregate(), atomic_aggregate);
        }
    }

    #[test]
    fn test_update_message_rr_attrs_encode_decode() {
        let originator_id = Ipv4Addr::new(192, 168, 1, 1);
        let cluster_list = vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)];

        let mut path = test_path();
        let attrs = path.attrs_mut();
        attrs.local_pref = Some(100);
        attrs.originator_id = Some(originator_id);
        attrs.cluster_list = cluster_list.clone();
        let msg = UpdateMessage::new(&path, vec![], DEFAULT_FORMAT);

        let bytes = msg.to_bytes();
        let parsed = UpdateMessage::from_bytes(bytes, DEFAULT_FORMAT).unwrap();

        assert_eq!(parsed.originator_id(), Some(originator_id));
        assert_eq!(parsed.cluster_list(), Some(cluster_list));
    }

    #[test]
    fn test_update_message_mp_encode_decode() {
        // Test coexistence of traditional NLRI/withdrawn with MP extensions,
        // both with and without ADD-PATH path identifiers.
        let cases = vec![
            ("without add-path", DEFAULT_FORMAT, None),
            ("with add-path", ADDPATH_FORMAT, Some(5)),
        ];

        for (desc, format, path_id) in cases {
            let mp_reach = MpReachNlri {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                nlri: vec![nlri_v4(10, 0, 0, 0, 8, path_id)],
                ls_nlri: vec![],
            };

            let mp_unreach = MpUnreachNlri {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                withdrawn_routes: vec![nlri_v4(20, 0, 0, 0, 8, path_id)],
                ls_withdrawn: vec![],
            };

            let path_attributes = vec![
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::Origin(Origin::IGP),
                },
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                    value: PathAttrValue::AsPath(AsPath { segments: vec![] }),
                },
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                    value: PathAttrValue::MpReachNlri(mp_reach),
                },
                PathAttribute {
                    flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                    value: PathAttrValue::MpUnreachNlri(mp_unreach),
                },
            ];

            let path_attributes_bytes =
                write_path_attributes(&path_attributes, format.use_4byte_asn);

            let nlri_list = vec![nlri_v4(40, 0, 0, 0, 8, path_id)];

            let withdrawn_routes = vec![nlri_v4(30, 0, 0, 0, 8, path_id)];
            let withdrawn_routes_bytes = write_nlri_list(&withdrawn_routes);

            let msg = UpdateMessage {
                withdrawn_routes_len: withdrawn_routes_bytes.len() as u16,
                withdrawn_routes,
                total_path_attributes_len: path_attributes_bytes.len() as u16,
                path_attributes,
                nlri_list,
                format,
            };

            let bytes = msg.to_bytes();
            let parsed = UpdateMessage::from_bytes(bytes, format).unwrap();

            assert_eq!(
                parsed.next_hop(),
                Some(NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1))),
                "{}",
                desc
            );

            // Verify combined NLRI (traditional 40.0.0.0/8 + MP_REACH 10.0.0.0/8)
            let mut nlri = parsed.nlri_list();
            nlri.sort_by_key(|entry| match &entry.prefix {
                IpNetwork::V4(v4) => v4.address,
                IpNetwork::V6(_) => Ipv4Addr::new(0, 0, 0, 0),
            });
            assert_eq!(
                nlri,
                vec![
                    nlri_v4(10, 0, 0, 0, 8, path_id),
                    nlri_v4(40, 0, 0, 0, 8, path_id),
                ],
                "{}",
                desc
            );

            // Verify combined withdrawn (traditional 30.0.0.0/8 + MP_UNREACH 20.0.0.0/8)
            let mut withdrawn = parsed.withdrawn_routes();
            withdrawn.sort_by_key(|entry| match &entry.prefix {
                IpNetwork::V4(v4) => v4.address,
                IpNetwork::V6(_) => Ipv4Addr::new(0, 0, 0, 0),
            });
            assert_eq!(
                withdrawn,
                vec![
                    nlri_v4(20, 0, 0, 0, 8, path_id),
                    nlri_v4(30, 0, 0, 0, 8, path_id),
                ],
                "{}",
                desc
            );
        }
    }

    #[test]
    fn test_update_message_next_hop_with_mp_reach_ignored() {
        // RFC 4760 Section 3: when MP_REACH_NLRI is present, NEXT_HOP is ignored.
        // NEXT_HOP says 10.0.0.1, MP_REACH says 192.168.1.1 -- MP_REACH wins.
        let mp_reach = sample_mp_reach();

        let path_attributes = vec![
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::Origin(Origin::IGP),
            },
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::AsPath(AsPath { segments: vec![] }),
            },
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::TRANSITIVE),
                value: PathAttrValue::NextHop(NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1))),
            },
            PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                value: PathAttrValue::MpReachNlri(mp_reach),
            },
        ];

        let path_attributes_bytes = write_path_attributes(&path_attributes, false);

        let msg = UpdateMessage {
            withdrawn_routes_len: 0,
            withdrawn_routes: vec![],
            total_path_attributes_len: path_attributes_bytes.len() as u16,
            path_attributes,
            nlri_list: vec![],
            format: DEFAULT_FORMAT,
        };

        let bytes = msg.to_bytes();
        let decoded = UpdateMessage::from_bytes(bytes, DEFAULT_FORMAT).unwrap();
        // MP_REACH next-hop (192.168.1.1) is used, NEXT_HOP (10.0.0.1) ignored
        assert_eq!(
            decoded.next_hop(),
            Some(NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn test_malformed_attribute_list_lengths_too_large() {
        // Create a message with Withdrawn Routes Length + Total Attribute Length + 4 > body_length
        let input: &[u8] = &[
            0x00, 0x04, // Withdrawn routes length = 4
            0x18, 0x0a, 0x0b, 0x0c, // Withdrawn route data (4 bytes: /24 prefix)
            0x00,
            0x64, // Total path attribute length = 100
                  // Body ends here (8 bytes total), but we claim 100 bytes of attributes
                  // Check: 4 + 100 + 4 = 108 > 8, should error
        ];

        match UpdateMessage::from_bytes(input.to_vec(), DEFAULT_FORMAT) {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList)
                );
                assert_eq!(data, Vec::<u8>::new());
            }
            _ => panic!("Expected MalformedAttributeList error"),
        }
    }

    #[test]
    fn test_attribute_flags_well_known_wrong_optional_bit() {
        // RFC 7606: flag errors on well-known attrs -> treat-as-withdraw (not session reset)
        let test_cases = vec![
            ("origin", AttrType::Origin as u8, vec![0x01, 0x00]),
            ("as_path", AttrType::AsPath as u8, vec![0x00]),
            (
                "next_hop",
                AttrType::NextHop as u8,
                vec![0x04, 0x0a, 0x00, 0x00, 0x01],
            ),
            (
                "local_pref",
                AttrType::LocalPref as u8,
                vec![0x04, 0x00, 0x00, 0x00, 0x64],
            ),
        ];

        for (name, attr_type, attr_data) in test_cases {
            let mut input = vec![PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE, attr_type];
            input.extend_from_slice(&attr_data);

            let (result, _) = read_path_attribute(&input, DEFAULT_FORMAT).unwrap();
            assert!(
                !matches!(result, PathAttrResult::Parsed(_)),
                "Failed for {}",
                name
            );
        }

        // ATOMIC_AGGREGATE -> attribute-discard
        let input = vec![
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
            AttrType::AtomicAggregate as u8,
            0x00,
        ];
        let (result, _) = read_path_attribute(&input, DEFAULT_FORMAT).unwrap();
        assert!(!matches!(result, PathAttrResult::Parsed(_)));
    }

    #[test]
    fn test_attribute_flags_well_known_partial_bit_set() {
        // RFC 7606: flag errors on well-known attrs -> attribute discarded
        let test_cases = vec![
            ("origin", AttrType::Origin as u8, vec![0x01, 0x00]),
            ("as_path", AttrType::AsPath as u8, vec![0x00]),
            (
                "next_hop",
                AttrType::NextHop as u8,
                vec![0x04, 0x0a, 0x00, 0x00, 0x01],
            ),
            (
                "local_pref",
                AttrType::LocalPref as u8,
                vec![0x04, 0x00, 0x00, 0x00, 0x64],
            ),
        ];

        for (name, attr_type, attr_data) in test_cases {
            let mut input = vec![PathAttrFlag::TRANSITIVE | PathAttrFlag::PARTIAL, attr_type];
            input.extend_from_slice(&attr_data);

            let (result, _) = read_path_attribute(&input, DEFAULT_FORMAT).unwrap();
            assert!(
                !matches!(result, PathAttrResult::Parsed(_)),
                "Failed for {}",
                name
            );
        }

        // ATOMIC_AGGREGATE -> attribute-discard
        let input = vec![
            PathAttrFlag::TRANSITIVE | PathAttrFlag::PARTIAL,
            AttrType::AtomicAggregate as u8,
            0x00,
        ];
        let (result, _) = read_path_attribute(&input, DEFAULT_FORMAT).unwrap();
        assert!(!matches!(result, PathAttrResult::Parsed(_)));
    }

    #[test]
    fn test_attribute_flags_optional_wrong_flags() {
        // RFC 7606: flag errors on optional attrs -> attribute discarded
        let test_cases = vec![
            (
                "med_missing_optional",
                AttrType::MultiExtiDisc as u8,
                PathAttrFlag::TRANSITIVE,
                vec![0x04, 0x00, 0x00, 0x00, 0x01],
            ),
            (
                "aggregator_missing_optional",
                AttrType::Aggregator as u8,
                PathAttrFlag::TRANSITIVE,
                vec![0x06, 0x00, 0x10, 0x0a, 0x0b, 0x0c, 0x0d],
            ),
        ];

        for (name, attr_type, wrong_flags, attr_data) in test_cases {
            let mut input = vec![wrong_flags, attr_type];
            input.extend_from_slice(&attr_data);

            let (result, _) = read_path_attribute(&input, DEFAULT_FORMAT).unwrap();
            assert!(
                !matches!(result, PathAttrResult::Parsed(_)),
                "Failed for {}",
                name
            );
        }
    }

    #[test]
    fn test_attribute_flags_extended_length_data() {
        // RFC 7606: ORIGIN flag error -> attribute discarded
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::EXTENDED_LENGTH,
            AttrType::Origin as u8,
            0x00,
            0x01,
            0x00,
        ];

        let (result, _) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        assert!(!matches!(result, PathAttrResult::Parsed(_)));
    }

    #[test]
    fn test_attribute_flags_aggregator_partial_bit_allowed() {
        // 2-byte ASN format (6 bytes) requires non-4byte-ASN session
        let format_2byte = MessageFormat {
            use_4byte_asn: false,
            ..DEFAULT_FORMAT
        };

        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE | PathAttrFlag::PARTIAL,
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
        let attr = result.unwrap();
        assert_eq!(
            attr.flags.0,
            PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE | PathAttrFlag::PARTIAL
        );
        assert_eq!(offset, 9);
    }

    #[test]
    fn test_attribute_flags_med_partial_bit_allowed() {
        let input: &[u8] = &[
            PathAttrFlag::OPTIONAL | PathAttrFlag::PARTIAL,
            AttrType::MultiExtiDisc as u8,
            0x04,
            0x00,
            0x00,
            0x00,
            0x01,
        ];

        let (result, offset) = read_path_attribute(input, DEFAULT_FORMAT).unwrap();
        let attr = result.unwrap();
        assert_eq!(attr.flags.0, PathAttrFlag::OPTIONAL | PathAttrFlag::PARTIAL);
        assert_eq!(offset, 7);
    }

    #[test]
    fn test_missing_well_known_attribute() {
        let test_cases = vec![
            (
                "origin",
                build_update_body(
                    &[
                        PATH_ATTR_AS_PATH_EMPTY,
                        PATH_ATTR_NEXT_HOP,
                        PATH_ATTR_LOCAL_PREF,
                    ],
                    NLRI_SINGLE,
                ),
                attr_type_code::ORIGIN,
            ),
            (
                "as_path",
                build_update_body(
                    &[
                        PATH_ATTR_ORIGIN_IGP,
                        PATH_ATTR_NEXT_HOP,
                        PATH_ATTR_LOCAL_PREF,
                    ],
                    NLRI_SINGLE,
                ),
                attr_type_code::AS_PATH,
            ),
            (
                "next_hop",
                build_update_body(
                    &[
                        PATH_ATTR_ORIGIN_IGP,
                        PATH_ATTR_AS_PATH_EMPTY,
                        PATH_ATTR_LOCAL_PREF,
                    ],
                    NLRI_SINGLE,
                ),
                attr_type_code::NEXT_HOP,
            ),
        ];

        for (name, input, _expected_missing_type) in test_cases {
            // RFC 7606: missing well-known mandatory -> treat-as-withdraw
            // Parser moves NLRI to withdrawn_routes and clears path_attributes
            let msg = UpdateMessage::from_bytes(input, DEFAULT_FORMAT).unwrap();
            assert!(
                !msg.withdrawn_routes.is_empty(),
                "Failed for {}: expected withdrawn routes",
                name
            );
            assert!(
                msg.nlri_list.is_empty(),
                "Failed for {}: NLRI should be empty after treat-as-withdraw",
                name
            );
            assert!(
                msg.path_attributes.is_empty(),
                "Failed for {}: path_attributes should be cleared",
                name
            );
        }
    }

    #[test]
    fn test_missing_well_known_attribute_mp_reach_nlri() {
        // RFC 4760 Section 3: MP_REACH_NLRI also requires ORIGIN and AS_PATH
        let mp_reach = PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
            value: PathAttrValue::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                nlri: vec![nlri_v4(10, 11, 12, 0, 24, None)],
                ls_nlri: vec![],
            }),
        };
        let mp_reach_bytes = write_path_attribute(&mp_reach, false);

        // Only MP_REACH_NLRI, missing ORIGIN and AS_PATH -> treat-as-withdraw
        let input = build_update_body(&[&mp_reach_bytes], &[]);
        let msg = UpdateMessage::from_bytes(input, DEFAULT_FORMAT).unwrap();
        assert!(
            !msg.withdrawn_routes.is_empty(),
            "MP_REACH_NLRI routes should be withdrawn"
        );
        assert!(
            msg.path_attributes.is_empty(),
            "path_attributes should be cleared"
        );
    }

    #[test]
    fn test_no_missing_well_known_attribute_without_nlri() {
        let input = build_update_body(&[], &[]);

        let result = UpdateMessage::from_bytes(input, DEFAULT_FORMAT);
        assert!(result.is_ok());
    }

    #[test]
    fn test_unrecognized_well_known_attribute() {
        // Well-known attribute (OPTIONAL=0) with unrecognized type code
        let flags = PathAttrFlag::TRANSITIVE;
        let attr_type = 200u8;
        let attr_len = 2u8;
        let attr_value = vec![0xaa, 0xbb];

        let mut input = vec![flags, attr_type, attr_len];
        input.extend_from_slice(&attr_value);

        let result = read_path_attribute(&input, DEFAULT_FORMAT);

        match result {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::UpdateMessageError(
                        UpdateMessageError::UnrecognizedWellKnownAttribute
                    )
                );
                assert_eq!(data, input);
            }
            _ => panic!("Expected UnrecognizedWellKnownAttribute error"),
        }
    }

    #[test]
    fn test_unknown_optional_attributes() {
        let test_cases = vec![
            (
                PathAttrFlag::OPTIONAL,
                200u8,
                vec![0x01, 0x02, 0x03],
                PathAttrFlag::OPTIONAL, // Non-transitive: PARTIAL bit NOT set
            ),
            (
                PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE,
                201u8,
                vec![0xde, 0xad, 0xbe, 0xef],
                PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE | PathAttrFlag::PARTIAL, // Transitive: PARTIAL bit set
            ),
        ];

        for (input_flags, attr_type, attr_value, expected_flags) in test_cases {
            let mut input = vec![input_flags, attr_type, attr_value.len() as u8];
            input.extend_from_slice(&attr_value);

            let (result, offset) = read_path_attribute(&input, DEFAULT_FORMAT).unwrap();
            let attr = result.unwrap();

            assert_eq!(
                attr,
                PathAttribute {
                    flags: PathAttrFlag(expected_flags),
                    value: PathAttrValue::Unknown {
                        type_code: attr_type,
                        flags: expected_flags,
                        data: attr_value.clone(),
                    },
                }
            );
            assert_eq!(offset as usize, input.len());

            // Roundtrip test
            let output = write_path_attribute(&attr, false);
            let (result, _) = read_path_attribute(&output, DEFAULT_FORMAT).unwrap();
            let parsed_attr = result.unwrap();
            assert_eq!(parsed_attr, attr);
        }
    }

    #[test]
    fn test_as_path_leftmost_as() {
        let test_cases = vec![
            (vec![], None),
            (
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![100, 200],
                }],
                Some(100),
            ),
            (
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSet,
                    segment_len: 2,
                    asn_list: vec![300, 400],
                }],
                Some(300),
            ),
            (
                vec![
                    AsPathSegment {
                        segment_type: AsPathSegmentType::AsSequence,
                        segment_len: 1,
                        asn_list: vec![500],
                    },
                    AsPathSegment {
                        segment_type: AsPathSegmentType::AsSequence,
                        segment_len: 1,
                        asn_list: vec![600],
                    },
                ],
                Some(500),
            ),
        ];

        for (segments, expected) in test_cases {
            let as_path = AsPath { segments };
            assert_eq!(as_path.leftmost_as(), expected);
        }
    }

    #[test]
    fn test_update_message_get_leftmost_as() {
        let mut path = test_path();
        path.attrs_mut().as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 2,
            asn_list: vec![65001, 65002],
        }];
        let msg = UpdateMessage::new(&path, vec![], DEFAULT_FORMAT);
        assert_eq!(msg.leftmost_as(), Some(65001));

        let msg_empty_path = UpdateMessage::new(&test_path(), vec![], DEFAULT_FORMAT);
        assert_eq!(msg_empty_path.leftmost_as(), None);
    }

    #[test]
    fn test_duplicate_attribute_silently_discarded() {
        // RFC 7606: duplicate non-MP attributes are silently discarded (keep first)
        let input = build_update_body(&[PATH_ATTR_ORIGIN_IGP, PATH_ATTR_ORIGIN_IGP], &[]);

        let result = UpdateMessage::from_bytes(input, DEFAULT_FORMAT).unwrap();
        // Should parse successfully, keeping only the first ORIGIN
        assert_eq!(result.origin(), Some(Origin::IGP));
    }

    #[test]
    fn test_update_message_with_communities() {
        let body = build_update_body(
            &[
                PATH_ATTR_ORIGIN_IGP,
                PATH_ATTR_AS_PATH_EMPTY,
                PATH_ATTR_NEXT_HOP,
                PATH_ATTR_COMMUNITIES_TWO,
            ],
            NLRI_SINGLE,
        );

        let msg = UpdateMessage::from_bytes(body, DEFAULT_FORMAT).unwrap();

        assert_eq!(msg.origin(), Some(Origin::IGP));
        assert_eq!(msg.communities(), Some(vec![0x00010064, 0xFFFFFF01]));

        // Verify Communities attribute has OPTIONAL | TRANSITIVE flags
        let comm_attr = msg
            .path_attributes
            .iter()
            .find(|attr| matches!(attr.value, PathAttrValue::Communities(_)))
            .expect("Communities attribute should exist");

        assert_eq!(
            comm_attr.flags,
            PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE)
        );
    }

    #[test]
    fn test_update_message_without_communities() {
        let body = build_update_body(
            &[
                PATH_ATTR_ORIGIN_IGP,
                PATH_ATTR_AS_PATH_EMPTY,
                PATH_ATTR_NEXT_HOP,
            ],
            NLRI_SINGLE,
        );

        let msg = UpdateMessage::from_bytes(body, DEFAULT_FORMAT).unwrap();

        assert_eq!(msg.communities(), None);
    }

    #[test]
    fn test_update_message_with_extended_communities() {
        let body = build_update_body(
            &[
                PATH_ATTR_ORIGIN_IGP,
                PATH_ATTR_AS_PATH_EMPTY,
                PATH_ATTR_NEXT_HOP,
                PATH_ATTR_EXTENDED_COMMUNITIES_TWO,
            ],
            NLRI_SINGLE,
        );

        let msg = UpdateMessage::from_bytes(body, DEFAULT_FORMAT).unwrap();

        assert_eq!(msg.origin(), Some(Origin::IGP));
        assert_eq!(
            msg.extended_communities(),
            Some(vec![0x0002FDE800000064u64, 0x0102C0A801010064u64])
        );

        // Verify ExtendedCommunities attribute has OPTIONAL | TRANSITIVE flags
        let ext_comm_attr = msg
            .path_attributes
            .iter()
            .find(|attr| matches!(attr.value, PathAttrValue::ExtendedCommunities(_)))
            .expect("ExtendedCommunities attribute should exist");

        assert_eq!(
            ext_comm_attr.flags,
            PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE)
        );
    }

    #[test]
    fn test_update_message_ipv6_encode_decode() {
        // Create an UPDATE message with IPv6 routes
        let ipv6_prefix = IpNetwork::V6(Ipv6Net {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            prefix_length: 32,
        });

        let next_hop = NextHopAddr::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        let mut path = test_path();
        let attrs = path.attrs_mut();
        attrs.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 1,
            asn_list: vec![65002],
        }];
        attrs.next_hop = next_hop;
        attrs.local_pref = Some(100);
        let msg = UpdateMessage::new(&path, vec![ipv6_prefix], DEFAULT_FORMAT);

        let bytes = msg.to_bytes();
        let decoded = UpdateMessage::from_bytes(bytes, DEFAULT_FORMAT).unwrap();

        assert_eq!(decoded.nlri_prefixes(), vec![ipv6_prefix]);
        assert_eq!(decoded.next_hop(), Some(next_hop));
        assert_eq!(decoded.origin(), Some(Origin::IGP));
        assert_eq!(decoded.local_pref(), Some(100));
    }

    #[test]
    fn test_strip_as4_attributes_removes_as4_path_and_aggregator() {
        use crate::bgp::msg_update_types::{Aggregator, AsPath};

        // Create an UPDATE with AS4_PATH and AS4_AGGREGATOR (protocol violation from NEW speaker)
        let mut path = test_path();
        let attrs = path.attrs_mut();
        attrs.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 1,
            asn_list: vec![65001],
        }];
        attrs.next_hop = NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let mut msg = UpdateMessage::new(&path, vec![], DEFAULT_FORMAT);

        // Manually add AS4_PATH and AS4_AGGREGATOR to simulate receiving from NEW speaker
        msg.path_attributes.push(PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::As4Path(AsPath {
                segments: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![4200000001],
                }],
            }),
        });

        msg.path_attributes.push(PathAttribute {
            flags: PathAttrFlag(PathAttrFlag::OPTIONAL | PathAttrFlag::TRANSITIVE),
            value: PathAttrValue::As4Aggregator(Aggregator {
                asn: 4200000002,
                ip_addr: Ipv4Addr::new(10, 0, 0, 1),
            }),
        });

        // Verify attributes exist before stripping
        assert!(msg.as4_path().is_some());
        assert!(msg.as4_aggregator().is_some());

        // Strip AS4 attributes (RFC 6793 Section 4.1)
        msg.strip_as4_attributes();

        // Verify attributes were removed
        assert!(msg.as4_path().is_none());
        assert!(msg.as4_aggregator().is_none());

        // Verify other attributes remain
        assert_eq!(msg.origin(), Some(Origin::IGP));
        assert!(msg.as_path().is_some());
    }

    #[test]
    fn test_strip_as4_attributes_preserves_other_attributes() {
        // Create UPDATE with various attributes but no AS4 attributes
        let mut path = test_path();
        let attrs = path.attrs_mut();
        attrs.as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 2,
            asn_list: vec![65001, 65002],
        }];
        attrs.next_hop = NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        attrs.local_pref = Some(100);
        attrs.med = Some(50);
        attrs.communities = vec![65001u32];
        let mut msg = UpdateMessage::new(&path, vec![], DEFAULT_FORMAT);

        let attr_count_before = msg.path_attributes.len();

        // Strip (should be no-op since no AS4 attributes present)
        msg.strip_as4_attributes();

        // Verify all attributes preserved
        assert_eq!(msg.path_attributes.len(), attr_count_before);
        assert_eq!(msg.origin(), Some(Origin::IGP));
        assert_eq!(msg.local_pref(), Some(100));
        assert_eq!(msg.med(), Some(50));
        assert_eq!(msg.communities(), Some(vec![65001]));
    }

    #[test]
    fn test_eor_afi_safi() {
        let format = DEFAULT_FORMAT;

        let cases = vec![
            (
                "empty UPDATE -> IPv4 Unicast EoR",
                UpdateMessage {
                    withdrawn_routes_len: 0,
                    withdrawn_routes: vec![],
                    total_path_attributes_len: 0,
                    path_attributes: vec![],
                    nlri_list: vec![],
                    format,
                },
                Some(AfiSafi::new(Afi::Ipv4, Safi::Unicast)),
            ),
            (
                "MP_UNREACH_NLRI with empty withdrawn -> IPv6 Unicast EoR",
                UpdateMessage {
                    withdrawn_routes_len: 0,
                    withdrawn_routes: vec![],
                    total_path_attributes_len: 0,
                    path_attributes: vec![PathAttribute {
                        flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                        value: PathAttrValue::MpUnreachNlri(MpUnreachNlri {
                            afi: Afi::Ipv6,
                            safi: Safi::Unicast,
                            withdrawn_routes: vec![],
                            ls_withdrawn: vec![],
                        }),
                    }],
                    nlri_list: vec![],
                    format,
                },
                Some(AfiSafi::new(Afi::Ipv6, Safi::Unicast)),
            ),
            (
                "has NLRI -> not EoR",
                UpdateMessage {
                    withdrawn_routes_len: 0,
                    withdrawn_routes: vec![],
                    total_path_attributes_len: 0,
                    path_attributes: vec![],
                    nlri_list: vec![nlri_v4(10, 0, 0, 0, 8, None)],
                    format,
                },
                None,
            ),
            (
                "MP_UNREACH_NLRI with LS withdrawn -> not EoR",
                UpdateMessage {
                    withdrawn_routes_len: 0,
                    withdrawn_routes: vec![],
                    total_path_attributes_len: 0,
                    path_attributes: vec![PathAttribute {
                        flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                        value: PathAttrValue::MpUnreachNlri(MpUnreachNlri {
                            afi: Afi::LinkState,
                            safi: Safi::LinkState,
                            withdrawn_routes: vec![],
                            ls_withdrawn: vec![LsNlri {
                                nlri_type: 1,
                                raw: vec![1, 2, 3],
                                body: None,
                                route_distinguisher: None,
                            }],
                        }),
                    }],
                    nlri_list: vec![],
                    format,
                },
                None,
            ),
            (
                "MP_UNREACH_NLRI LS empty -> LinkState EoR",
                UpdateMessage {
                    withdrawn_routes_len: 0,
                    withdrawn_routes: vec![],
                    total_path_attributes_len: 0,
                    path_attributes: vec![PathAttribute {
                        flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                        value: PathAttrValue::MpUnreachNlri(MpUnreachNlri {
                            afi: Afi::LinkState,
                            safi: Safi::LinkState,
                            withdrawn_routes: vec![],
                            ls_withdrawn: vec![],
                        }),
                    }],
                    nlri_list: vec![],
                    format,
                },
                Some(AfiSafi::new(Afi::LinkState, Safi::LinkState)),
            ),
        ];

        for (desc, msg, expected) in cases {
            assert_eq!(msg.eor_afi_safi(), expected, "{}", desc);
            assert_eq!(msg.is_eor(), expected.is_some(), "{}", desc);
        }
    }

    #[test]
    fn test_new_eor() {
        let cases = vec![
            ("IPv4 Unicast - empty UPDATE", Afi::Ipv4, Safi::Unicast),
            ("IPv6 Unicast - MP_UNREACH_NLRI", Afi::Ipv6, Safi::Unicast),
            (
                "IPv4 Multicast - MP_UNREACH_NLRI",
                Afi::Ipv4,
                Safi::Multicast,
            ),
        ];

        for (desc, afi, safi) in cases {
            let eor = UpdateMessage::new_eor(afi, safi, DEFAULT_FORMAT);

            // All EOR markers should be recognized as EOR
            assert!(eor.is_eor(), "{}: should be EOR marker", desc);

            // All should have empty withdrawn and NLRI
            assert_eq!(eor.withdrawn_routes, vec![], "{}", desc);
            assert_eq!(eor.nlri_list, vec![], "{}", desc);

            // IPv4 Unicast should have no attributes
            if matches!((afi, safi), (Afi::Ipv4, Safi::Unicast)) {
                assert_eq!(eor.path_attributes, vec![], "{}", desc);
            } else {
                // Others should have exactly one MP_UNREACH_NLRI attribute
                assert_eq!(eor.path_attributes.len(), 1, "{}", desc);

                let attr = &eor.path_attributes[0];
                assert_eq!(attr.flags, PathAttrFlag(PathAttrFlag::OPTIONAL), "{}", desc);

                match &attr.value {
                    PathAttrValue::MpUnreachNlri(mp_unreach) => {
                        assert_eq!(mp_unreach.afi, afi, "{}", desc);
                        assert_eq!(mp_unreach.safi, safi, "{}", desc);
                        assert_eq!(mp_unreach.withdrawn_routes, vec![], "{}", desc);
                    }
                    _ => panic!("{}: expected MP_UNREACH_NLRI", desc),
                }
            }
        }
    }

    #[test]
    fn test_addpath_roundtrip() {
        let ipv4_prefixes = vec![
            IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 0, 0),
                prefix_length: 24,
            }),
            IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(192, 168, 1, 0),
                prefix_length: 24,
            }),
        ];
        let ipv6_prefixes = vec![IpNetwork::V6(Ipv6Net {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            prefix_length: 32,
        })];

        let cases: Vec<(&str, Vec<IpNetwork>, NextHopAddr)> = vec![
            (
                "ipv4",
                ipv4_prefixes,
                NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            ),
            (
                "ipv6",
                ipv6_prefixes,
                NextHopAddr::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ),
        ];

        for (desc, prefixes, next_hop) in cases {
            let mut path = test_path();
            path.local_path_id = Some(42);
            path.attrs_mut().next_hop = next_hop;

            let msg = UpdateMessage::new(&path, prefixes.clone(), ADDPATH_FORMAT);
            let expected_nlri: Vec<Nlri> = prefixes
                .into_iter()
                .map(|net| Nlri {
                    prefix: net,
                    path_id: Some(42),
                })
                .collect();
            assert_eq!(msg.nlri_list(), expected_nlri, "{}", desc);

            let bytes = msg.to_bytes();
            let decoded = UpdateMessage::from_bytes(bytes, ADDPATH_FORMAT).unwrap();

            assert_eq!(decoded.nlri_list(), expected_nlri, "{}", desc);
            assert_eq!(decoded.next_hop(), Some(next_hop), "{}", desc);
        }
    }

    #[test]
    fn test_addpath_withdraw_roundtrip() {
        let cases = vec![
            (
                "ipv4",
                vec![IpNetwork::V4(Ipv4Net {
                    address: Ipv4Addr::new(10, 0, 0, 0),
                    prefix_length: 24,
                })],
            ),
            (
                "ipv6",
                vec![IpNetwork::V6(Ipv6Net {
                    address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                    prefix_length: 32,
                })],
            ),
        ];

        for (desc, prefixes) in cases {
            let withdrawn: Vec<Nlri> = prefixes
                .iter()
                .map(|prefix| Nlri {
                    prefix: *prefix,
                    path_id: Some(7),
                })
                .collect();
            let expected_nlri = withdrawn.clone();
            let msg = UpdateMessage::new_withdraw(withdrawn, ADDPATH_FORMAT);
            let bytes = msg.to_bytes();
            let decoded = UpdateMessage::from_bytes(bytes, ADDPATH_FORMAT).unwrap();

            assert_eq!(decoded.withdrawn_routes(), expected_nlri, "{}", desc);
        }
    }

    #[test]
    fn test_nlri_prefixes() {
        let prefix_10 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 8,
        });
        let prefix_20 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(20, 0, 0, 0),
            prefix_length: 8,
        });

        let msg = UpdateMessage {
            withdrawn_routes_len: 0,
            withdrawn_routes: vec![],
            total_path_attributes_len: 0,
            path_attributes: vec![PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                value: PathAttrValue::MpReachNlri(MpReachNlri {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                    nlri: vec![Nlri {
                        prefix: prefix_10,
                        path_id: None,
                    }],
                    ls_nlri: vec![],
                }),
            }],
            nlri_list: vec![Nlri {
                prefix: prefix_20,
                path_id: None,
            }],
            format: DEFAULT_FORMAT,
        };

        let prefixes = msg.nlri_prefixes();
        assert_eq!(prefixes, vec![prefix_20, prefix_10]);
    }

    #[test]
    fn test_nlri_list() {
        let nlri_mp = nlri_v4(10, 0, 0, 0, 8, None);
        let nlri_traditional = nlri_v4(20, 0, 0, 0, 8, None);

        let msg = UpdateMessage {
            withdrawn_routes_len: 0,
            withdrawn_routes: vec![],
            total_path_attributes_len: 0,
            path_attributes: vec![PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                value: PathAttrValue::MpReachNlri(MpReachNlri {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                    nlri: vec![nlri_mp],
                    ls_nlri: vec![],
                }),
            }],
            nlri_list: vec![nlri_traditional],
            format: DEFAULT_FORMAT,
        };

        assert_eq!(msg.nlri_list(), vec![nlri_traditional, nlri_mp]);
    }

    #[test]
    fn test_withdrawn_routes() {
        let withdrawn_mp = nlri_v4(10, 0, 0, 0, 8, None);
        let withdrawn_traditional = nlri_v4(20, 0, 0, 0, 8, None);

        let msg = UpdateMessage {
            withdrawn_routes_len: 0,
            withdrawn_routes: vec![withdrawn_traditional],
            total_path_attributes_len: 0,
            path_attributes: vec![PathAttribute {
                flags: PathAttrFlag(PathAttrFlag::OPTIONAL),
                value: PathAttrValue::MpUnreachNlri(MpUnreachNlri {
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    withdrawn_routes: vec![withdrawn_mp],
                    ls_withdrawn: vec![],
                }),
            }],
            nlri_list: vec![],
            format: DEFAULT_FORMAT,
        };

        assert_eq!(
            msg.withdrawn_routes(),
            vec![withdrawn_traditional, withdrawn_mp]
        );
    }

    #[test]
    fn test_addpath_disabled_no_path_id() {
        let format = DEFAULT_FORMAT;
        let msg = UpdateMessage::new(&test_path(), vec![], format);
        assert!(msg.nlri_list().is_empty());

        let decoded = UpdateMessage::from_bytes(msg.to_bytes(), format).unwrap();
        assert!(decoded.nlri_list().is_empty());
    }

    #[test]
    fn test_ls_update_roundtrip() {
        use crate::bgp::bgpls_attr::{build_ls_attr, LsAttrTlv, NodeAttrTlv};
        use crate::bgp::bgpls_nlri::{
            build_ls_nlri, LsDescriptors, LsNlriType, LsProtocolId, NodeDescriptor,
        };

        struct Case {
            name: &'static str,
            has_ls_attr: bool,
        }

        let cases = vec![
            Case {
                name: "with type-29 attribute",
                has_ls_attr: true,
            },
            Case {
                name: "without type-29 attribute (valid per RFC 9552 Section 8.2.2)",
                has_ls_attr: false,
            },
        ];

        for tc in cases {
            let ls_nlri = build_ls_nlri(
                LsNlriType::Node,
                LsProtocolId::IsIsL1,
                42,
                LsDescriptors::Node {
                    local_node: NodeDescriptor {
                        igp_router_id: Some(vec![1, 2, 3, 4]),
                        ..NodeDescriptor::default()
                    },
                },
                None,
            );

            let mut path = test_path();
            if tc.has_ls_attr {
                path.attrs_mut().ls_attr = Some(build_ls_attr(vec![LsAttrTlv::Node(
                    NodeAttrTlv::Name("test-node".to_string()),
                )]));
            }

            let ls_family = AfiSafi::new(Afi::LinkState, Safi::LinkState);
            let msg =
                UpdateMessage::new_ls(&path, vec![ls_nlri.clone()], ls_family, DEFAULT_FORMAT);

            assert_eq!(msg.ls_nlri_list().len(), 1, "case: {}", tc.name);
            assert_eq!(msg.ls_attr().is_some(), tc.has_ls_attr, "case: {}", tc.name);

            let decoded = UpdateMessage::from_bytes(msg.to_bytes(), DEFAULT_FORMAT).unwrap();
            assert_eq!(decoded.ls_nlri_list().len(), 1, "case: {}", tc.name);
            assert_eq!(
                decoded.ls_nlri_list()[0].raw,
                ls_nlri.raw,
                "case: {}",
                tc.name
            );
            assert_eq!(
                decoded.ls_attr().is_some(),
                tc.has_ls_attr,
                "case: {}",
                tc.name
            );
        }
    }

    #[test]
    fn test_ls_withdraw_roundtrip() {
        use crate::bgp::bgpls_nlri::{
            build_ls_nlri, LsDescriptors, LsNlriType, LsProtocolId, NodeDescriptor,
        };

        let ls_nlri = build_ls_nlri(
            LsNlriType::Node,
            LsProtocolId::IsIsL1,
            0,
            LsDescriptors::Node {
                local_node: NodeDescriptor {
                    igp_router_id: Some(vec![5]),
                    ..NodeDescriptor::default()
                },
            },
            None,
        );

        let ls_family = AfiSafi::new(Afi::LinkState, Safi::LinkState);
        let msg = UpdateMessage::new_ls_withdraw(vec![ls_nlri.clone()], ls_family, DEFAULT_FORMAT);

        let decoded = UpdateMessage::from_bytes(msg.to_bytes(), DEFAULT_FORMAT).unwrap();
        let decoded_ls = decoded.ls_withdrawn_list();
        assert_eq!(decoded_ls.len(), 1);
        assert_eq!(decoded_ls[0].raw, ls_nlri.raw);
    }
}
