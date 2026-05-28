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

use crate::bgp::bgpls_attr::LsAttr;
use crate::bgp::community::LLGR_STALE;
use crate::bgp::merge_as_paths;
use crate::bgp::msg::AddPathMask;
use crate::bgp::msg_update::{
    Aggregator, AsPathSegment, AsPathSegmentType, NextHopAddr, Origin, PathAttribute, UpdateMessage,
};
use crate::bgp::msg_update_types::{AsPath, LargeCommunity, AS_TRANS};
use crate::bgp::multiprotocol::AfiSafi;
use crate::rib::types::RouteSource;
use crate::rpki::vrp::RpkiValidation;
use std::cmp::Ordering;
use std::net::IpAddr;
use std::sync::Arc;

/// BGP path attributes - all BGP protocol attributes for a path.
/// Compiler-checked equality (no manual PartialEq needed).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathAttrs {
    pub origin: Origin,
    pub as_path: Vec<AsPathSegment>,
    pub next_hop: NextHopAddr,
    pub source: RouteSource,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    pub atomic_aggregate: bool,
    pub aggregator: Option<Aggregator>,
    pub communities: Vec<u32>,
    pub extended_communities: Vec<u64>,
    pub large_communities: Vec<LargeCommunity>,
    pub unknown_attrs: Vec<PathAttribute>,
    /// RFC 4456: ORIGINATOR_ID attribute for route reflector loop prevention
    pub originator_id: Option<std::net::Ipv4Addr>,
    /// RFC 4456: CLUSTER_LIST attribute for route reflector loop prevention
    pub cluster_list: Vec<std::net::Ipv4Addr>,
    /// RFC 9552: BGP-LS Attribute (type 29) carrying link-state properties
    pub ls_attr: Option<LsAttr>,
}

/// Represents a BGP path with allocation metadata and attributes.
/// Production code should compare .attrs (not full path) to avoid unnecessary churn.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Path {
    /// None = not allocated (adj-rib-in), Some(id) = loc-rib allocated by PathIdAllocator
    pub local_path_id: Option<u32>,
    /// Path ID received from peer (None = no ADD-PATH negotiated)
    pub remote_path_id: Option<u32>,
    /// BGP path attributes (Arc for copy-on-write: clone is ref-count bump,
    /// deep copy only on mutation via attrs_mut()).
    pub attrs: Arc<PathAttrs>,
    /// RFC 4724: Marked stale during Graceful Restart, cleared on replacement
    pub stale: bool,
    /// RFC 6811: RPKI origin validation state (local metadata, never serialized)
    pub rpki_state: RpkiValidation,
}

impl Path {
    /// Mutable access to attrs with copy-on-write semantics.
    /// If the Arc is shared, this clones the inner PathAttrs.
    pub fn attrs_mut(&mut self) -> &mut PathAttrs {
        Arc::make_mut(&mut self.attrs)
    }

    // Accessor methods that delegate to attrs - keeps existing code working
    pub fn origin(&self) -> Origin {
        self.attrs.origin
    }

    pub fn as_path(&self) -> &Vec<AsPathSegment> {
        &self.attrs.as_path
    }

    pub fn next_hop(&self) -> &NextHopAddr {
        &self.attrs.next_hop
    }

    pub fn source(&self) -> RouteSource {
        self.attrs.source
    }

    pub fn is_from_peer(&self, peer_ip: IpAddr) -> bool {
        self.attrs.source.peer_ip() == Some(peer_ip)
    }

    pub fn local_pref(&self) -> Option<u32> {
        self.attrs.local_pref
    }

    pub fn med(&self) -> Option<u32> {
        self.attrs.med
    }

    pub fn atomic_aggregate(&self) -> bool {
        self.attrs.atomic_aggregate
    }

    pub fn aggregator(&self) -> Option<Aggregator> {
        self.attrs.aggregator.clone()
    }

    pub fn communities(&self) -> &Vec<u32> {
        &self.attrs.communities
    }

    pub fn extended_communities(&self) -> &Vec<u64> {
        &self.attrs.extended_communities
    }

    pub fn large_communities(&self) -> &Vec<LargeCommunity> {
        &self.attrs.large_communities
    }

    pub fn unknown_attrs(&self) -> &Vec<PathAttribute> {
        &self.attrs.unknown_attrs
    }

    pub fn originator_id(&self) -> Option<std::net::Ipv4Addr> {
        self.attrs.originator_id
    }

    pub fn cluster_list(&self) -> &Vec<std::net::Ipv4Addr> {
        &self.attrs.cluster_list
    }

    /// Returns the local path ID if ADD-PATH is enabled for this AFI/SAFI
    pub fn path_id_for(&self, add_path: &AddPathMask, afi_safi: &AfiSafi) -> Option<u32> {
        if add_path.contains(afi_safi) {
            self.local_path_id
        } else {
            None
        }
    }

    /// Same source peer and same remote path ID (ADD-PATH identity).
    pub fn matches_remote(&self, other: &Path) -> bool {
        self.attrs.source == other.attrs.source && self.remote_path_id == other.remote_path_id
    }
}

impl Path {
    /// Create a Path from an UPDATE message. Returns None if required attributes are missing.
    /// peer_supports_4byte_asn: Whether the peer that sent this UPDATE supports 4-byte ASN
    pub fn from_update_msg(
        update_msg: &UpdateMessage,
        source: RouteSource,
        peer_supports_4byte_asn: bool,
    ) -> Option<Self> {
        let origin = update_msg.origin()?;
        let as_path_segments = update_msg.as_path()?;
        let next_hop = update_msg.next_hop()?;

        let as_path =
            Self::merge_as4_path_if_needed(update_msg, as_path_segments, peer_supports_4byte_asn);
        let aggregator = Self::get_aggregator(update_msg, peer_supports_4byte_asn);

        Some(Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            rpki_state: RpkiValidation::NotFound,
            attrs: Arc::new(PathAttrs {
                origin,
                as_path,
                next_hop,
                source,
                local_pref: update_msg.local_pref(),
                med: update_msg.med(),
                atomic_aggregate: update_msg.atomic_aggregate(),
                aggregator,
                communities: update_msg.communities().unwrap_or_default(),
                extended_communities: update_msg.extended_communities().unwrap_or_default(),
                large_communities: update_msg.large_communities().unwrap_or_default(),
                unknown_attrs: update_msg.unknown_attrs(),
                originator_id: update_msg.originator_id(),
                cluster_list: update_msg.cluster_list().unwrap_or_default(),
                ls_attr: update_msg.ls_attr(),
            }),
        })
    }

    /// RFC 6793: Merge AS4_PATH into AS_PATH if peer is an OLD speaker
    /// AS4_PATH/AS4_AGGREGATOR MUST NOT be sent between NEW speakers
    fn merge_as4_path_if_needed(
        update_msg: &UpdateMessage,
        as_path_segments: Vec<AsPathSegment>,
        peer_supports_4byte_asn: bool,
    ) -> Vec<AsPathSegment> {
        // NEW speakers never send AS4_PATH - use AS_PATH directly
        if peer_supports_4byte_asn {
            return as_path_segments;
        }

        // RFC 6793 Section 4.2.3: Check AGGREGATOR to decide whether to merge AS4_PATH
        // If AGGREGATOR.asn != AS_TRANS, ignore AS4_PATH (OLD speaker aggregated or stale)
        // If AGGREGATOR.asn == AS_TRANS, merge AS4_PATH (NEW speaker with 4-byte ASN aggregated)
        if let Some(aggregator) = update_msg.aggregator() {
            if aggregator.asn != AS_TRANS as u32 {
                return as_path_segments;
            }
        }

        // Merge AS4_PATH if present
        if let Some(as4_path_segs) = update_msg.as4_path() {
            merge_as_paths(
                &AsPath {
                    segments: as_path_segments,
                },
                &AsPath {
                    segments: as4_path_segs,
                },
            )
            .segments
        } else {
            as_path_segments
        }
    }

    /// RFC 6793: Get AGGREGATOR, merging AS4_AGGREGATOR if needed
    fn get_aggregator(
        update_msg: &UpdateMessage,
        peer_supports_4byte_asn: bool,
    ) -> Option<Aggregator> {
        // NEW speaker - use AGGREGATOR directly
        if peer_supports_4byte_asn {
            return update_msg.aggregator();
        }

        // OLD speaker sent AGGREGATOR - check if we should use AS4_AGGREGATOR
        if let Some(agg) = update_msg.aggregator() {
            if agg.asn == AS_TRANS as u32 {
                // AS_TRANS in AGGREGATOR - prefer AS4_AGGREGATOR if present
                update_msg.as4_aggregator().or(Some(agg))
            } else {
                // Real 2-byte ASN or stale AS4_AGGREGATOR
                Some(agg)
            }
        } else {
            None
        }
    }

    /// Calculate AS_PATH length for best path selection per RFC 4271
    /// AS_SEQUENCE counts each ASN, AS_SET counts as 1 regardless of size
    /// Confederation segments are not counted per RFC 5065
    fn as_path_length(&self) -> usize {
        self.as_path()
            .iter()
            .map(|segment| match segment.segment_type {
                AsPathSegmentType::AsSequence => segment.asn_list.len(),
                AsPathSegmentType::AsSet => 1,
                AsPathSegmentType::AsConfedSequence | AsPathSegmentType::AsConfedSet => 0,
            })
            .sum()
    }

    /// Determine neighboring AS per RFC 4271 Section 9.1.2.2(c)
    /// Returns the first AS in the AS_PATH if present, None for locally originated routes
    fn neighboring_as(&self) -> Option<u32> {
        // Find first AS_SEQUENCE segment and return its first ASN
        for segment in self.as_path() {
            if segment.segment_type == AsPathSegmentType::AsSequence && !segment.asn_list.is_empty()
            {
                return Some(segment.asn_list[0]);
            }
        }
        // Empty AS_PATH or no AS_SEQUENCE (locally originated or aggregated routes)
        None
    }

    /// Extract origin AS from AS_PATH (RFC 6811 Section 2).
    /// Returns None for empty AS_PATH (caller should use local AS).
    /// Returns Some(0) for AS_SET/confederation final segment (cannot match any VRP).
    pub fn origin_as(&self) -> Option<u32> {
        let last = self.as_path().last()?;
        match last.segment_type {
            AsPathSegmentType::AsSequence => last.asn_list.last().copied(),
            _ => Some(0),
        }
    }
}

impl Path {
    /// Compare paths for BGP best path selection per RFC 4271 Section 9.1.2.2
    /// Returns Ordering::Greater if self is better (higher preference)
    pub fn best_path_cmp(&self, other: &Self) -> std::cmp::Ordering {
        // RFC 9494: LLGR_STALE routes are least preferred
        let self_llgr = self.attrs.communities.contains(&LLGR_STALE);
        let other_llgr = other.attrs.communities.contains(&LLGR_STALE);
        if self_llgr != other_llgr {
            return if other_llgr {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        // Step 1: Prefer the route with the highest degree of preference (LOCAL_PREF)
        let self_local_pref = self.local_pref().unwrap_or(100);
        let other_local_pref = other.local_pref().unwrap_or(100);
        match self_local_pref.cmp(&other_local_pref) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Step 2: Prefer the route with the shortest AS_PATH
        // AS_SEQUENCE counts each ASN, AS_SET counts as 1
        match other.as_path_length().cmp(&self.as_path_length()) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Step 3: Prefer the route with the lowest ORIGIN type (IGP < EGP < INCOMPLETE)
        let self_origin = self.origin() as u8;
        let other_origin = other.origin() as u8;
        match other_origin.cmp(&self_origin) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Step 4: Prefer the route with the lowest MULTI_EXIT_DISC (MED)
        // RFC 4271 Section 9.1.2.2(c): MED is only comparable between routes
        // learned from the same neighboring AS
        let self_neighbor = self.neighboring_as();
        let other_neighbor = other.neighboring_as();
        if self_neighbor == other_neighbor {
            let self_med = self.med().unwrap_or(0);
            let other_med = other.med().unwrap_or(0);
            match other_med.cmp(&self_med) {
                Ordering::Greater => return Ordering::Greater,
                Ordering::Less => return Ordering::Less,
                Ordering::Equal => {}
            }
        }
        // If from different neighboring AS, skip MED comparison

        // Step 5: Prefer eBGP-learned routes over iBGP-learned routes
        match (&self.source(), &other.source()) {
            (RouteSource::Ebgp { .. }, RouteSource::Ibgp { .. }) => return Ordering::Greater,
            (RouteSource::Ibgp { .. }, RouteSource::Ebgp { .. }) => return Ordering::Less,
            // Local routes are considered better than any BGP-learned route
            (RouteSource::Local, RouteSource::Ebgp { .. } | RouteSource::Ibgp { .. }) => {
                return Ordering::Greater
            }
            (RouteSource::Ebgp { .. } | RouteSource::Ibgp { .. }, RouteSource::Local) => {
                return Ordering::Less
            }
            _ => {}
        }

        // RFC 4456 Section 9: Prefer shorter CLUSTER_LIST
        match other.cluster_list().len().cmp(&self.cluster_list().len()) {
            Ordering::Greater => return Ordering::Greater,
            Ordering::Less => return Ordering::Less,
            Ordering::Equal => {}
        }

        // RFC 4456 Section 9: Use ORIGINATOR_ID instead of BGP ID for iBGP tie-breaking
        if let (
            RouteSource::Ibgp {
                bgp_id: self_bgp_id,
                ..
            },
            RouteSource::Ibgp {
                bgp_id: other_bgp_id,
                ..
            },
        ) = (&self.source(), &other.source())
        {
            let self_id = self.originator_id().unwrap_or(*self_bgp_id);
            let other_id = other.originator_id().unwrap_or(*other_bgp_id);
            match other_id.cmp(&self_id) {
                Ordering::Greater => return Ordering::Greater,
                Ordering::Less => return Ordering::Less,
                Ordering::Equal => {}
            }
        }

        // Step 7: If both paths are external, prefer the route from the BGP speaker
        // with the lowest BGP Identifier
        match (&self.source(), &other.source()) {
            (RouteSource::Ebgp { bgp_id: a, .. }, RouteSource::Ebgp { bgp_id: b, .. }) => {
                b.cmp(a) // reverse for "prefer lower"
            }
            (RouteSource::Ibgp { bgp_id: a, .. }, RouteSource::Ibgp { bgp_id: b, .. }) => {
                b.cmp(a) // also break ties for iBGP routes
            }
            _ => Ordering::Equal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::DEFAULT_FORMAT;
    use crate::net::IpNetwork;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn test_bgp_id(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(1, 1, 1, last)
    }

    fn make_base_path() -> Path {
        Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            rpki_state: RpkiValidation::NotFound,
            attrs: Arc::new(PathAttrs {
                origin: Origin::IGP,
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                local_pref: Some(100),
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

    #[test]
    fn test_llgr_stale_ordering() {
        // (name, communities1, local_pref1, communities2, local_pref2, expected)
        let tests = [
            (
                "non-stale preferred over stale",
                vec![],
                100,
                vec![LLGR_STALE],
                100,
                Ordering::Greater,
            ),
            (
                "stale loses to non-stale",
                vec![LLGR_STALE],
                100,
                vec![],
                100,
                Ordering::Less,
            ),
            (
                "both stale falls through to next tiebreaker",
                vec![LLGR_STALE],
                200,
                vec![LLGR_STALE],
                100,
                Ordering::Greater,
            ),
        ];

        for (name, communities1, lp1, communities2, lp2, expected) in tests {
            let mut path1 = make_base_path();
            let mut path2 = make_base_path();
            let attrs1 = path1.attrs_mut();
            attrs1.communities = communities1;
            attrs1.local_pref = Some(lp1);
            let attrs2 = path2.attrs_mut();
            attrs2.communities = communities2;
            attrs2.local_pref = Some(lp2);
            assert_eq!(path1.best_path_cmp(&path2), expected, "test case: {}", name);
        }
    }

    #[test]
    fn test_local_pref_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.attrs_mut().local_pref = Some(200);
        path2.attrs_mut().local_pref = Some(100);

        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_as_path_length_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.attrs_mut().as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 1,
            asn_list: vec![65001],
        }];
        path2.attrs_mut().as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 2,
            asn_list: vec![65001, 65002],
        }];

        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_as_set_length_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        // path1: AS_SET with 3 ASNs (counts as length 1)
        path1.attrs_mut().as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSet,
            segment_len: 3,
            asn_list: vec![65001, 65002, 65003],
        }];
        // path2: AS_SEQUENCE with 2 ASNs (counts as length 2)
        path2.attrs_mut().as_path = vec![AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 2,
            asn_list: vec![65001, 65002],
        }];

        // path1 (AS_SET, length=1) should be preferred over path2 (AS_SEQUENCE, length=2)
        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_origin_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.attrs_mut().origin = Origin::IGP;
        path2.attrs_mut().origin = Origin::INCOMPLETE;

        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_med_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.attrs_mut().med = Some(50);
        path2.attrs_mut().med = Some(100);

        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_med_missing_treated_as_zero() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.attrs_mut().med = None; // treated as 0
        path2.attrs_mut().med = Some(100);

        // path1 (MED=0) should be preferred over path2 (MED=100)
        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_local_vs_ebgp_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.attrs_mut().source = RouteSource::Local;
        path2.attrs_mut().source = RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: test_bgp_id(1),
        };

        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_local_vs_ibgp_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.attrs_mut().source = RouteSource::Local;
        path2.attrs_mut().source = RouteSource::Ibgp {
            peer_ip: test_ip(1),
            bgp_id: test_bgp_id(1),
            rr_client: false,
        };

        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_ebgp_vs_ibgp_ordering() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.attrs_mut().source = RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: test_bgp_id(1),
        };
        path2.attrs_mut().source = RouteSource::Ibgp {
            peer_ip: test_ip(2),
            bgp_id: test_bgp_id(2),
            rr_client: false,
        };

        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_peer_bgp_id_tiebreaker() {
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.attrs_mut().source = RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: test_bgp_id(1),
        };
        path2.attrs_mut().source = RouteSource::Ebgp {
            peer_ip: test_ip(2),
            bgp_id: test_bgp_id(2),
        };

        // Lower BGP ID should win
        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_originator_id_tiebreaker() {
        // RFC 4456: iBGP routes should use ORIGINATOR_ID for tie-breaking
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        let attrs1 = path1.attrs_mut();
        attrs1.source = RouteSource::Ibgp {
            peer_ip: test_ip(1),
            bgp_id: test_bgp_id(10), // Higher peer BGP ID
            rr_client: false,
        };
        attrs1.originator_id = Some(test_bgp_id(1));
        let attrs2 = path2.attrs_mut();
        attrs2.source = RouteSource::Ibgp {
            peer_ip: test_ip(2),
            bgp_id: test_bgp_id(1), // Lower peer BGP ID
            rr_client: false,
        };
        // path1 has lower ORIGINATOR_ID, should win despite higher peer BGP ID
        attrs2.originator_id = Some(test_bgp_id(2));

        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_originator_id_fallback_to_peer_id() {
        // RFC 4456: If no ORIGINATOR_ID, fall back to peer's BGP ID
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.attrs_mut().source = RouteSource::Ibgp {
            peer_ip: test_ip(1),
            bgp_id: test_bgp_id(1),
            rr_client: false,
        };
        path2.attrs_mut().source = RouteSource::Ibgp {
            peer_ip: test_ip(2),
            bgp_id: test_bgp_id(2),
            rr_client: false,
        };
        // No ORIGINATOR_ID set, should use peer BGP ID
        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_cluster_list_length() {
        // RFC 4456: Prefer shorter CLUSTER_LIST
        let mut path1 = make_base_path();
        let mut path2 = make_base_path();
        path1.attrs_mut().cluster_list = vec![test_bgp_id(1)];
        path2.attrs_mut().cluster_list = vec![test_bgp_id(1), test_bgp_id(2)];

        assert_eq!(path1.best_path_cmp(&path2), Ordering::Greater);
    }

    #[test]
    fn test_from_update_msg() {
        let source = RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: test_bgp_id(1),
        };

        // Valid UPDATE with all required attrs
        let path = Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            rpki_state: RpkiValidation::NotFound,
            attrs: Arc::new(PathAttrs {
                origin: Origin::IGP,
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                source: RouteSource::Local,
                local_pref: Some(100),
                med: Some(50),
                atomic_aggregate: true,
                aggregator: None,
                communities: vec![],
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
                ls_attr: None,
            }),
        };
        let prefix: IpNetwork = "10.0.0.0/24".parse().unwrap();
        let update = UpdateMessage::new(&path, vec![prefix], DEFAULT_FORMAT);
        let path = Path::from_update_msg(&update, source, false);
        assert!(path.is_some());
        let path = path.unwrap();
        assert_eq!(path.origin(), Origin::IGP);
        assert_eq!(
            path.next_hop(),
            &NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(path.local_pref(), Some(100));
        assert_eq!(path.med(), Some(50));
        assert!(path.atomic_aggregate());

        // Missing required attrs -> None
        let empty_update = UpdateMessage::new_withdraw(vec![], DEFAULT_FORMAT);
        assert!(Path::from_update_msg(&empty_update, source, false).is_none());
    }

    #[test]
    fn test_neighboring_as() {
        let tests = [
            (
                "AS_SEQUENCE with multiple ASNs",
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                }],
                Some(65001),
            ),
            ("empty AS_PATH", vec![], None),
            (
                "AS_SET then AS_SEQUENCE",
                vec![
                    AsPathSegment {
                        segment_type: AsPathSegmentType::AsSet,
                        segment_len: 2,
                        asn_list: vec![65001, 65002],
                    },
                    AsPathSegment {
                        segment_type: AsPathSegmentType::AsSequence,
                        segment_len: 1,
                        asn_list: vec![65003],
                    },
                ],
                Some(65003),
            ),
        ];

        for (name, as_path, expected) in tests {
            let mut path = make_base_path();
            path.attrs_mut().as_path = as_path;
            assert_eq!(path.neighboring_as(), expected, "test case: {}", name);
        }
    }

    #[test]
    fn test_med_comparison() {
        let tests = [
            (
                "same AS - lower MED wins",
                RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                Some(50),
                RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                Some(100),
                Ordering::Greater, // path1 wins due to lower MED
            ),
            (
                "different AS - MED not compared",
                RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                Some(100),
                RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65002],
                }],
                Some(10),
                Ordering::Equal, // MED skipped, both eBGP from same peer
            ),
            (
                "local routes - MED compared",
                RouteSource::Local,
                vec![],
                Some(50),
                RouteSource::Local,
                vec![],
                Some(100),
                Ordering::Greater, // path1 wins due to lower MED
            ),
            (
                "local vs external - MED not compared",
                RouteSource::Local,
                vec![],
                Some(100),
                RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                Some(10),
                Ordering::Greater, // path1 wins at step 5 (Local > eBGP)
            ),
        ];

        for (name, src1, as_path1, med1, src2, as_path2, med2, expected) in tests {
            let mut path1 = make_base_path();
            let attrs1 = path1.attrs_mut();
            attrs1.source = src1;
            attrs1.as_path = as_path1;
            attrs1.med = med1;

            let mut path2 = make_base_path();
            let attrs2 = path2.attrs_mut();
            attrs2.source = src2;
            attrs2.as_path = as_path2;
            attrs2.med = med2;

            assert_eq!(path1.best_path_cmp(&path2), expected, "test case: {}", name);
        }
    }

    #[test]
    fn test_matches_remote() {
        let path1 = make_base_path();
        let mut path2 = make_base_path();

        // Same source, same remote_path_id (both None) -> matches
        assert!(path1.matches_remote(&path2));

        // Different source -> no match
        path2.attrs_mut().source = RouteSource::Ebgp {
            peer_ip: test_ip(2),
            bgp_id: test_bgp_id(2),
        };
        assert!(!path1.matches_remote(&path2));

        // Same source, different remote_path_id -> no match
        path2.attrs_mut().source = path1.attrs.source;
        path2.remote_path_id = Some(1);
        assert!(!path1.matches_remote(&path2));

        // Both have same remote_path_id -> matches
        let mut path3 = make_base_path();
        path3.remote_path_id = Some(5);
        let mut path4 = make_base_path();
        path4.remote_path_id = Some(5);
        assert!(path3.matches_remote(&path4));

        // Same remote_path_id, different source -> no match
        path4.attrs_mut().source = RouteSource::Ebgp {
            peer_ip: test_ip(2),
            bgp_id: test_bgp_id(2),
        };
        assert!(!path3.matches_remote(&path4));
    }

    #[test]
    fn test_origin_as() {
        let tests = [
            (
                "normal AS_SEQUENCE with two ASNs",
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                }],
                Some(65002),
            ),
            (
                "single AS in AS_SEQUENCE",
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                Some(65001),
            ),
            ("empty AS_PATH", vec![], None),
            (
                "AS_SET as final segment",
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSet,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                }],
                Some(0),
            ),
            (
                "AS_CONFED_SEQUENCE as final segment",
                vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsConfedSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                Some(0),
            ),
            (
                "AS_SEQUENCE then AS_SET - last segment is AS_SET",
                vec![
                    AsPathSegment {
                        segment_type: AsPathSegmentType::AsSequence,
                        segment_len: 1,
                        asn_list: vec![65001],
                    },
                    AsPathSegment {
                        segment_type: AsPathSegmentType::AsSet,
                        segment_len: 1,
                        asn_list: vec![65002],
                    },
                ],
                Some(0),
            ),
            (
                "AS_SET then AS_SEQUENCE - last segment is AS_SEQUENCE",
                vec![
                    AsPathSegment {
                        segment_type: AsPathSegmentType::AsSet,
                        segment_len: 1,
                        asn_list: vec![65001],
                    },
                    AsPathSegment {
                        segment_type: AsPathSegmentType::AsSequence,
                        segment_len: 2,
                        asn_list: vec![65002, 65003],
                    },
                ],
                Some(65003),
            ),
        ];

        for (name, as_path, expected) in tests {
            let mut path = make_base_path();
            path.attrs_mut().as_path = as_path;
            assert_eq!(path.origin_as(), expected, "test case: {}", name);
        }
    }

    #[test]
    fn test_is_from_peer() {
        let path = make_base_path(); // source peer_ip = test_ip(1)
        assert!(path.is_from_peer(test_ip(1)));
        assert!(!path.is_from_peer(test_ip(2)));
    }
}
