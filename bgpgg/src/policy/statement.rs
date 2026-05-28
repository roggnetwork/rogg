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

use crate::bgp::bgpls_nlri::LsProtocolId;
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::net::IpNetwork;
use crate::policy::sets::{
    AsPathSet, CommunitySet, DefinedSets, ExtCommunitySet, LargeCommunitySet, NeighborSet,
    PrefixSet,
};
use crate::rib::{Path, RouteKey, RouteSource};
use crate::rpki::vrp::rpki_validation_to_config;
use crate::rpki::vrp::RpkiValidation;
use conf::bgp::{
    ActionsConfig, CommunityActionConfig, ConditionsConfig, ExtCommunityActionConfig,
    LargeCommunityActionConfig, LocalPrefActionConfig, MatchOptionConfig, MatchSetRefConfig,
    MedActionConfig, StatementConfig,
};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

// ============================================================================
// Public types (re-exported)
// ============================================================================

/// Route type for matching route source
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteType {
    Ebgp,
    Ibgp,
    Local,
}

/// Community modification operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommunityOp {
    Add(Vec<u32>),
    Remove(Vec<u32>),
    Replace(Vec<u32>),
}

/// Extended Community modification operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtCommunityOp {
    Add(Vec<u64>),
    Remove(Vec<u64>),
    Replace(Vec<u64>),
}

/// Large Community modification operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LargeCommunityOp {
    Add(Vec<crate::bgp::msg_update_types::LargeCommunity>),
    Remove(Vec<crate::bgp::msg_update_types::LargeCommunity>),
    Replace(Vec<crate::bgp::msg_update_types::LargeCommunity>),
}

/// AFI/SAFI match for policy conditions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfiSafiMatch {
    Ipv4Unicast,
    Ipv6Unicast,
    BgpLs,
}

/// BGP-LS NLRI type match for policy conditions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsNlriTypeMatch {
    Node,
    Link,
    PrefixV4,
    PrefixV6,
}

/// BGP-LS protocol ID match for policy conditions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsProtocolIdMatch {
    IsIsL1,
    IsIsL2,
    OspfV2,
    Direct,
    Static,
    OspfV3,
}

// ============================================================================
// Statement - the main type
// ============================================================================

/// A policy statement: if conditions match, apply actions
#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    conditions: Vec<Condition>,
    actions: Vec<Action>,
}

impl Statement {
    pub fn new() -> Self {
        Self {
            conditions: Vec::new(),
            actions: Vec::new(),
        }
    }

    /// Add a condition that must match for this statement to apply
    pub fn when(mut self, condition: Condition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Add an action to apply if all conditions match
    pub fn then(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }

    /// Convert statement back to config format (for API responses)
    pub fn to_config(&self) -> StatementConfig {
        let mut conditions = ConditionsConfig::default();

        // Extract conditions
        for condition in &self.conditions {
            match condition {
                Condition::PrefixSet(arc_set, opt) => {
                    conditions.match_prefix_set = Some(MatchSetRefConfig {
                        set_name: arc_set.name.clone(),
                        match_option: *opt,
                    });
                }
                Condition::Prefix(ip) => {
                    conditions.prefix = Some(ip.to_string());
                }
                Condition::NeighborSet(arc_set, opt) => {
                    conditions.match_neighbor_set = Some(MatchSetRefConfig {
                        set_name: arc_set.name.clone(),
                        match_option: *opt,
                    });
                }
                Condition::Neighbor(ip) => {
                    conditions.neighbor = Some(ip.to_string());
                }
                Condition::AsPathSet(arc_set, opt) => {
                    conditions.match_as_path_set = Some(MatchSetRefConfig {
                        set_name: arc_set.name.clone(),
                        match_option: *opt,
                    });
                }
                Condition::AsPath(asn) => {
                    conditions.has_asn = Some(*asn);
                }
                Condition::CommunitySet(arc_set, opt) => {
                    conditions.match_community_set = Some(MatchSetRefConfig {
                        set_name: arc_set.name.clone(),
                        match_option: *opt,
                    });
                }
                Condition::ExtCommunitySet(arc_set, opt) => {
                    conditions.match_ext_community_set = Some(MatchSetRefConfig {
                        set_name: arc_set.name.clone(),
                        match_option: *opt,
                    });
                }
                Condition::LargeCommunitySet(arc_set, opt) => {
                    conditions.match_large_community_set = Some(MatchSetRefConfig {
                        set_name: arc_set.name.clone(),
                        match_option: *opt,
                    });
                }
                Condition::Community(comm) => {
                    let high = (*comm >> 16) as u16;
                    let low = (*comm & 0xFFFF) as u16;
                    conditions.community = Some(format!("{}:{}", high, low));
                }
                Condition::RouteType(rt) => {
                    conditions.route_type = Some(match rt {
                        RouteType::Ebgp => "ebgp".to_string(),
                        RouteType::Ibgp => "ibgp".to_string(),
                        RouteType::Local => "local".to_string(),
                    });
                }
                Condition::RpkiValidation(state) => {
                    conditions.rpki_validation = Some(rpki_validation_to_config(*state));
                }
                Condition::AfiSafi(afi_safi_match) => {
                    conditions.afi_safi = Some(
                        match afi_safi_match {
                            AfiSafiMatch::Ipv4Unicast => "ipv4-unicast",
                            AfiSafiMatch::Ipv6Unicast => "ipv6-unicast",
                            AfiSafiMatch::BgpLs => "bgp-ls",
                        }
                        .to_string(),
                    );
                }
                Condition::LsNlriType(nlri_type) => {
                    conditions.ls_nlri_type = Some(
                        match nlri_type {
                            LsNlriTypeMatch::Node => "node",
                            LsNlriTypeMatch::Link => "link",
                            LsNlriTypeMatch::PrefixV4 => "prefix-v4",
                            LsNlriTypeMatch::PrefixV6 => "prefix-v6",
                        }
                        .to_string(),
                    );
                }
                Condition::LsProtocolId(proto) => {
                    conditions.ls_protocol_id = Some(
                        match proto {
                            LsProtocolIdMatch::IsIsL1 => "isis-l1",
                            LsProtocolIdMatch::IsIsL2 => "isis-l2",
                            LsProtocolIdMatch::OspfV2 => "ospfv2",
                            LsProtocolIdMatch::Direct => "direct",
                            LsProtocolIdMatch::Static => "static",
                            LsProtocolIdMatch::OspfV3 => "ospfv3",
                        }
                        .to_string(),
                    );
                }
                Condition::LsInstanceId(id) => {
                    conditions.ls_instance_id = Some(*id);
                }
                Condition::LsNodeAs(asn) => {
                    conditions.ls_node_as = Some(*asn);
                }
                Condition::LsNodeRouterId(ip) => {
                    conditions.ls_node_router_id = Some(ip.to_string());
                }
            }
        }

        let mut actions = ActionsConfig::default();

        // Extract actions
        for action in &self.actions {
            match action {
                Action::Accept => {
                    actions.accept = Some(true);
                }
                Action::Reject => {
                    actions.reject = Some(true);
                }
                Action::SetLocalPref { value, force } => {
                    actions.local_pref = Some(if *force {
                        LocalPrefActionConfig::Force {
                            value: *value,
                            force: true,
                        }
                    } else {
                        LocalPrefActionConfig::Set(*value)
                    });
                }
                Action::SetMed(value) => {
                    actions.med = value
                        .map(MedActionConfig::Set)
                        .or(Some(MedActionConfig::Remove { remove: true }));
                }
                Action::SetCommunity(op) => match op {
                    CommunityOp::Add(comms) => {
                        actions.community = Some(CommunityActionConfig {
                            operation: "add".to_string(),
                            communities: comms
                                .iter()
                                .map(|c| {
                                    let high = (*c >> 16) as u16;
                                    let low = (*c & 0xFFFF) as u16;
                                    format!("{}:{}", high, low)
                                })
                                .collect(),
                        });
                    }
                    CommunityOp::Remove(comms) => {
                        actions.community = Some(CommunityActionConfig {
                            operation: "remove".to_string(),
                            communities: comms
                                .iter()
                                .map(|c| {
                                    let high = (*c >> 16) as u16;
                                    let low = (*c & 0xFFFF) as u16;
                                    format!("{}:{}", high, low)
                                })
                                .collect(),
                        });
                    }
                    CommunityOp::Replace(comms) => {
                        actions.community = Some(CommunityActionConfig {
                            operation: "replace".to_string(),
                            communities: comms
                                .iter()
                                .map(|c| {
                                    let high = (*c >> 16) as u16;
                                    let low = (*c & 0xFFFF) as u16;
                                    format!("{}:{}", high, low)
                                })
                                .collect(),
                        });
                    }
                },
                Action::SetExtCommunity(op) => {
                    use crate::bgp::ext_community::format_extended_community;
                    match op {
                        ExtCommunityOp::Add(ecs) => {
                            actions.ext_community = Some(ExtCommunityActionConfig {
                                operation: "add".to_string(),
                                ext_communities: ecs
                                    .iter()
                                    .map(|ec| format_extended_community(*ec))
                                    .collect(),
                            });
                        }
                        ExtCommunityOp::Remove(ecs) => {
                            actions.ext_community = Some(ExtCommunityActionConfig {
                                operation: "remove".to_string(),
                                ext_communities: ecs
                                    .iter()
                                    .map(|ec| format_extended_community(*ec))
                                    .collect(),
                            });
                        }
                        ExtCommunityOp::Replace(ecs) => {
                            actions.ext_community = Some(ExtCommunityActionConfig {
                                operation: "replace".to_string(),
                                ext_communities: ecs
                                    .iter()
                                    .map(|ec| format_extended_community(*ec))
                                    .collect(),
                            });
                        }
                    }
                }
                Action::SetLargeCommunity(op) => match op {
                    LargeCommunityOp::Add(lcs) => {
                        actions.large_community = Some(LargeCommunityActionConfig {
                            operation: "add".to_string(),
                            large_communities: lcs.iter().map(|lc| lc.to_string()).collect(),
                        });
                    }
                    LargeCommunityOp::Remove(lcs) => {
                        actions.large_community = Some(LargeCommunityActionConfig {
                            operation: "remove".to_string(),
                            large_communities: lcs.iter().map(|lc| lc.to_string()).collect(),
                        });
                    }
                    LargeCommunityOp::Replace(lcs) => {
                        actions.large_community = Some(LargeCommunityActionConfig {
                            operation: "replace".to_string(),
                            large_communities: lcs.iter().map(|lc| lc.to_string()).collect(),
                        });
                    }
                },
                Action::SetRpkiState(state) => {
                    actions.set_rpki_state = Some(rpki_validation_to_config(*state));
                }
            }
        }

        StatementConfig {
            name: None,
            conditions,
            actions,
        }
    }

    /// Check if all conditions match
    fn matches(&self, route_key: &RouteKey, path: &Path) -> bool {
        // Empty conditions means match everything
        self.conditions.is_empty() || self.conditions.iter().all(|c| c.matches(route_key, path))
    }

    /// Apply all actions if conditions match
    /// Returns None if no match, Some(accept) if matched
    pub(super) fn apply(&self, route_key: &RouteKey, path: &mut Path) -> Option<bool> {
        if self.matches(route_key, path) {
            let mut accept = true;
            for action in &self.actions {
                if !action.apply(path) {
                    accept = false;
                }
            }
            Some(accept)
        } else {
            None // Didn't match, try next statement
        }
    }
}

impl Default for Statement {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Action - what statements do
// ============================================================================

/// Action enum - all possible action types
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Accept,
    Reject,
    SetLocalPref { value: u32, force: bool },
    SetMed(Option<u32>),
    SetCommunity(CommunityOp),
    SetExtCommunity(ExtCommunityOp),
    SetLargeCommunity(LargeCommunityOp),
    SetRpkiState(RpkiValidation),
}

impl Action {
    fn apply(&self, path: &mut Path) -> bool {
        match self {
            Action::Accept => true,
            Action::Reject => false,
            Action::SetLocalPref { value, force } => {
                if *force || path.local_pref().is_none() {
                    path.attrs_mut().local_pref = Some(*value);
                }
                true
            }
            Action::SetMed(value) => {
                path.attrs_mut().med = *value;
                true
            }
            Action::SetCommunity(op) => {
                match op {
                    CommunityOp::Add(to_add) => {
                        for &comm in to_add {
                            if !path.communities().contains(&comm) {
                                path.attrs_mut().communities.push(comm);
                            }
                        }
                    }
                    CommunityOp::Remove(to_remove) => {
                        path.attrs_mut()
                            .communities
                            .retain(|comm| !to_remove.contains(comm));
                    }
                    CommunityOp::Replace(new_communities) => {
                        path.attrs_mut().communities = new_communities.clone();
                    }
                }
                true
            }
            Action::SetExtCommunity(op) => {
                match op {
                    ExtCommunityOp::Add(to_add) => {
                        for &ec in to_add {
                            if !path.extended_communities().contains(&ec) {
                                path.attrs_mut().extended_communities.push(ec);
                            }
                        }
                    }
                    ExtCommunityOp::Remove(to_remove) => {
                        path.attrs_mut()
                            .extended_communities
                            .retain(|ec| !to_remove.contains(ec));
                    }
                    ExtCommunityOp::Replace(new_ext_communities) => {
                        path.attrs_mut().extended_communities = new_ext_communities.clone();
                    }
                }
                true
            }
            Action::SetLargeCommunity(op) => {
                match op {
                    LargeCommunityOp::Add(to_add) => {
                        for &lc in to_add {
                            if !path.large_communities().contains(&lc) {
                                path.attrs_mut().large_communities.push(lc);
                            }
                        }
                    }
                    LargeCommunityOp::Remove(to_remove) => {
                        path.attrs_mut()
                            .large_communities
                            .retain(|lc| !to_remove.contains(lc));
                    }
                    LargeCommunityOp::Replace(new_large_communities) => {
                        path.attrs_mut().large_communities = new_large_communities.clone();
                    }
                }
                true
            }
            Action::SetRpkiState(state) => {
                path.rpki_state = *state;
                true
            }
        }
    }
}

// ============================================================================
// Condition - what statements match
// ============================================================================

/// Condition enum - all possible condition types
#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    Prefix(IpNetwork),
    PrefixSet(Arc<PrefixSet>, MatchOptionConfig),
    Neighbor(IpAddr),
    NeighborSet(Arc<NeighborSet>, MatchOptionConfig),
    AsPath(u32),
    AsPathSet(Arc<AsPathSet>, MatchOptionConfig),
    Community(u32),
    CommunitySet(Arc<CommunitySet>, MatchOptionConfig),
    ExtCommunitySet(Arc<ExtCommunitySet>, MatchOptionConfig),
    LargeCommunitySet(Arc<LargeCommunitySet>, MatchOptionConfig),
    RouteType(RouteType),
    RpkiValidation(RpkiValidation),
    AfiSafi(AfiSafiMatch),
    LsNlriType(LsNlriTypeMatch),
    LsProtocolId(LsProtocolIdMatch),
    LsInstanceId(u64),
    LsNodeAs(u32),
    LsNodeRouterId(IpAddr),
}

impl Condition {
    fn matches(&self, route_key: &RouteKey, path: &Path) -> bool {
        match self {
            Condition::Prefix(p) => match route_key {
                RouteKey::Prefix(prefix) => prefix == p,
                RouteKey::LinkState(_) => false,
            },
            Condition::PrefixSet(set, match_opt) => match route_key {
                RouteKey::Prefix(prefix) => match match_opt {
                    MatchOptionConfig::Any => set.prefixes.iter().any(|pm| pm.contains(prefix)),
                    MatchOptionConfig::All => set.prefixes.iter().all(|pm| pm.contains(prefix)),
                    MatchOptionConfig::Invert => !set.prefixes.iter().any(|pm| pm.contains(prefix)),
                },
                RouteKey::LinkState(_) => false,
            },
            Condition::Neighbor(neighbor) => path
                .source()
                .peer_ip()
                .map(|ip| ip == *neighbor)
                .unwrap_or(false),
            Condition::NeighborSet(set, match_opt) => {
                let Some(peer_ip) = path.source().peer_ip() else {
                    return false;
                };
                match match_opt {
                    MatchOptionConfig::Any => set.neighbors.contains(&peer_ip),
                    MatchOptionConfig::All => set.neighbors.iter().all(|n| *n == peer_ip),
                    MatchOptionConfig::Invert => !set.neighbors.contains(&peer_ip),
                }
            }
            Condition::AsPath(asn) => path
                .as_path()
                .iter()
                .flat_map(|segment| segment.asn_list.iter())
                .any(|&path_asn| path_asn == *asn),
            Condition::AsPathSet(set, match_opt) => {
                let as_path_str = path
                    .as_path()
                    .iter()
                    .flat_map(|segment| segment.asn_list.iter())
                    .map(|asn| asn.to_string())
                    .collect::<Vec<_>>()
                    .join("_");
                match match_opt {
                    MatchOptionConfig::Any => set.patterns.iter().any(|r| r.is_match(&as_path_str)),
                    MatchOptionConfig::All => set.patterns.iter().all(|r| r.is_match(&as_path_str)),
                    MatchOptionConfig::Invert => {
                        !set.patterns.iter().any(|r| r.is_match(&as_path_str))
                    }
                }
            }
            Condition::Community(community) => path.communities().contains(community),
            Condition::CommunitySet(set, match_opt) => match match_opt {
                MatchOptionConfig::Any => path
                    .communities()
                    .iter()
                    .any(|c| set.communities.contains(c)),
                MatchOptionConfig::All => path
                    .communities()
                    .iter()
                    .all(|c| set.communities.contains(c)),
                MatchOptionConfig::Invert => !path
                    .communities()
                    .iter()
                    .any(|c| set.communities.contains(c)),
            },
            Condition::ExtCommunitySet(set, match_opt) => match match_opt {
                MatchOptionConfig::Any => path
                    .extended_communities()
                    .iter()
                    .any(|ec| set.ext_communities.contains(ec)),
                MatchOptionConfig::All => path
                    .extended_communities()
                    .iter()
                    .all(|ec| set.ext_communities.contains(ec)),
                MatchOptionConfig::Invert => !path
                    .extended_communities()
                    .iter()
                    .any(|ec| set.ext_communities.contains(ec)),
            },
            Condition::LargeCommunitySet(set, match_opt) => match match_opt {
                MatchOptionConfig::Any => path
                    .large_communities()
                    .iter()
                    .any(|lc| set.large_communities.contains(lc)),
                MatchOptionConfig::All => path
                    .large_communities()
                    .iter()
                    .all(|lc| set.large_communities.contains(lc)),
                MatchOptionConfig::Invert => !path
                    .large_communities()
                    .iter()
                    .any(|lc| set.large_communities.contains(lc)),
            },
            Condition::RouteType(route_type) => matches!(
                (route_type, path.source()),
                (RouteType::Ebgp, RouteSource::Ebgp { .. })
                    | (RouteType::Ibgp, RouteSource::Ibgp { .. })
                    | (RouteType::Local, RouteSource::Local)
            ),
            Condition::RpkiValidation(state) => path.rpki_state == *state,
            Condition::AfiSafi(afi_safi_match) => {
                let route_afi_safi = route_key.afi_safi();
                match afi_safi_match {
                    AfiSafiMatch::Ipv4Unicast => {
                        route_afi_safi == AfiSafi::new(Afi::Ipv4, Safi::Unicast)
                    }
                    AfiSafiMatch::Ipv6Unicast => {
                        route_afi_safi == AfiSafi::new(Afi::Ipv6, Safi::Unicast)
                    }
                    AfiSafiMatch::BgpLs => {
                        route_afi_safi == AfiSafi::new(Afi::LinkState, Safi::LinkState)
                            || route_afi_safi == AfiSafi::new(Afi::LinkState, Safi::LinkStateVpn)
                    }
                }
            }
            Condition::LsNlriType(nlri_type_match) => match route_key {
                RouteKey::LinkState(ls) => matches!(
                    (nlri_type_match, ls.nlri_type),
                    (LsNlriTypeMatch::Node, 1)
                        | (LsNlriTypeMatch::Link, 2)
                        | (LsNlriTypeMatch::PrefixV4, 3)
                        | (LsNlriTypeMatch::PrefixV6, 4)
                ),
                _ => false,
            },
            Condition::LsProtocolId(proto_match) => match route_key {
                RouteKey::LinkState(ls) => ls.body.as_ref().is_some_and(|body| {
                    let expected = match proto_match {
                        LsProtocolIdMatch::IsIsL1 => LsProtocolId::IsIsL1,
                        LsProtocolIdMatch::IsIsL2 => LsProtocolId::IsIsL2,
                        LsProtocolIdMatch::OspfV2 => LsProtocolId::OspfV2,
                        LsProtocolIdMatch::Direct => LsProtocolId::Direct,
                        LsProtocolIdMatch::Static => LsProtocolId::Static,
                        LsProtocolIdMatch::OspfV3 => LsProtocolId::OspfV3,
                    };
                    body.protocol_id() == Some(expected)
                }),
                _ => false,
            },
            Condition::LsInstanceId(id) => match route_key {
                RouteKey::LinkState(ls) => {
                    ls.body.as_ref().is_some_and(|body| body.identifier == *id)
                }
                _ => false,
            },
            Condition::LsNodeAs(asn) => match route_key {
                RouteKey::LinkState(ls) => ls
                    .body
                    .as_ref()
                    .is_some_and(|body| body.descriptors.local_node().as_number == Some(*asn)),
                _ => false,
            },
            Condition::LsNodeRouterId(ip) => match route_key {
                RouteKey::LinkState(ls) => ls.body.as_ref().is_some_and(|body| {
                    body.descriptors
                        .local_node()
                        .igp_router_id
                        .as_ref()
                        .is_some_and(|rid| match ip {
                            IpAddr::V4(v4) => rid.as_slice() == v4.octets(),
                            IpAddr::V6(v6) => rid.as_slice() == v6.octets(),
                        })
                }),
                _ => false,
            },
        }
    }
}

// ============================================================================
// Internal functions (config parsing)
// ============================================================================

/// Build a statement from config
pub(super) fn build_statement(
    def: &StatementConfig,
    defined_sets: &DefinedSets,
) -> Result<Statement, String> {
    let mut stmt = Statement::new();

    // Add conditions
    stmt = add_conditions(stmt, &def.conditions, defined_sets)?;

    // Add actions
    stmt = add_actions(stmt, &def.actions)?;

    Ok(stmt)
}

/// Add conditions to a statement
fn add_conditions(
    mut stmt: Statement,
    cond: &ConditionsConfig,
    defined_sets: &DefinedSets,
) -> Result<Statement, String> {
    // Set-based conditions - resolve sets at construction time
    if let Some(ref match_set) = cond.match_prefix_set {
        let prefix_set = defined_sets
            .prefix_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("prefix-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(Condition::PrefixSet(
            Arc::new(prefix_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_neighbor_set {
        let neighbor_set = defined_sets
            .neighbor_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("neighbor-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(Condition::NeighborSet(
            Arc::new(neighbor_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_as_path_set {
        let as_path_set = defined_sets
            .as_path_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("as-path-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(Condition::AsPathSet(
            Arc::new(as_path_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_community_set {
        let community_set = defined_sets
            .community_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("community-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(Condition::CommunitySet(
            Arc::new(community_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_ext_community_set {
        let ext_community_set = defined_sets
            .ext_community_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("ext-community-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(Condition::ExtCommunitySet(
            Arc::new(ext_community_set.clone()),
            match_set.match_option,
        ));
    }

    if let Some(ref match_set) = cond.match_large_community_set {
        let large_community_set = defined_sets
            .large_community_sets
            .get(&match_set.set_name)
            .ok_or_else(|| format!("large-community-set '{}' not found", match_set.set_name))?;

        stmt = stmt.when(Condition::LargeCommunitySet(
            Arc::new(large_community_set.clone()),
            match_set.match_option,
        ));
    }

    // Direct conditions (backward compat)
    if let Some(ref prefix_str) = cond.prefix {
        let prefix = IpNetwork::from_str(prefix_str)
            .map_err(|e| format!("invalid prefix '{}': {}", prefix_str, e))?;
        stmt = stmt.when(Condition::Prefix(prefix));
    }

    if let Some(ref neighbor_str) = cond.neighbor {
        let neighbor = IpAddr::from_str(neighbor_str)
            .map_err(|e| format!("invalid neighbor '{}': {}", neighbor_str, e))?;
        stmt = stmt.when(Condition::Neighbor(neighbor));
    }

    if let Some(asn) = cond.has_asn {
        stmt = stmt.when(Condition::AsPath(asn));
    }

    if let Some(ref route_type_str) = cond.route_type {
        let route_type = match route_type_str.as_str() {
            "ebgp" => RouteType::Ebgp,
            "ibgp" => RouteType::Ibgp,
            "local" => RouteType::Local,
            _ => {
                return Err(format!(
                    "invalid route-type '{}' (must be 'ebgp', 'ibgp', or 'local')",
                    route_type_str
                ))
            }
        };
        stmt = stmt.when(Condition::RouteType(route_type));
    }

    if let Some(ref community_str) = cond.community {
        let community = parse_community_value(community_str)?;
        stmt = stmt.when(Condition::Community(community));
    }

    if let Some(rpki_config) = cond.rpki_validation {
        stmt = stmt.when(Condition::RpkiValidation(rpki_config.into()));
    }

    if let Some(ref afi_safi_str) = cond.afi_safi {
        let afi_safi = match afi_safi_str.as_str() {
            "ipv4-unicast" => AfiSafiMatch::Ipv4Unicast,
            "ipv6-unicast" => AfiSafiMatch::Ipv6Unicast,
            "bgp-ls" => AfiSafiMatch::BgpLs,
            _ => {
                return Err(format!(
                    "invalid afi-safi '{}' (must be 'ipv4-unicast', 'ipv6-unicast', or 'bgp-ls')",
                    afi_safi_str
                ))
            }
        };
        stmt = stmt.when(Condition::AfiSafi(afi_safi));
    }

    if let Some(ref nlri_type_str) = cond.ls_nlri_type {
        let nlri_type = match nlri_type_str.as_str() {
            "node" => LsNlriTypeMatch::Node,
            "link" => LsNlriTypeMatch::Link,
            "prefix-v4" => LsNlriTypeMatch::PrefixV4,
            "prefix-v6" => LsNlriTypeMatch::PrefixV6,
            _ => {
                return Err(format!(
                "invalid ls-nlri-type '{}' (must be 'node', 'link', 'prefix-v4', or 'prefix-v6')",
                nlri_type_str
            ))
            }
        };
        stmt = stmt.when(Condition::LsNlriType(nlri_type));
    }

    if let Some(ref proto_str) = cond.ls_protocol_id {
        let proto = match proto_str.as_str() {
            "isis-l1" => LsProtocolIdMatch::IsIsL1,
            "isis-l2" => LsProtocolIdMatch::IsIsL2,
            "ospfv2" => LsProtocolIdMatch::OspfV2,
            "direct" => LsProtocolIdMatch::Direct,
            "static" => LsProtocolIdMatch::Static,
            "ospfv3" => LsProtocolIdMatch::OspfV3,
            _ => {
                return Err(format!(
                    "invalid ls-protocol-id '{}' (must be 'isis-l1', 'isis-l2', 'ospfv2', 'ospfv3', 'direct', or 'static')",
                    proto_str
                ))
            }
        };
        stmt = stmt.when(Condition::LsProtocolId(proto));
    }

    if let Some(instance_id) = cond.ls_instance_id {
        stmt = stmt.when(Condition::LsInstanceId(instance_id));
    }

    if let Some(asn) = cond.ls_node_as {
        stmt = stmt.when(Condition::LsNodeAs(asn));
    }

    if let Some(ref router_id_str) = cond.ls_node_router_id {
        let router_id = IpAddr::from_str(router_id_str)
            .map_err(|e| format!("invalid ls-node-router-id '{}': {}", router_id_str, e))?;
        stmt = stmt.when(Condition::LsNodeRouterId(router_id));
    }

    Ok(stmt)
}

/// Add actions to a statement
fn add_actions(mut stmt: Statement, actions: &ActionsConfig) -> Result<Statement, String> {
    // Local preference
    if let Some(ref lp_action) = actions.local_pref {
        match lp_action {
            LocalPrefActionConfig::Set(val) => {
                stmt = stmt.then(Action::SetLocalPref {
                    value: *val,
                    force: false,
                });
            }
            LocalPrefActionConfig::Force { value, force } => {
                stmt = stmt.then(Action::SetLocalPref {
                    value: *value,
                    force: *force,
                });
            }
        }
    }

    // MED
    if let Some(ref med_action) = actions.med {
        match med_action {
            MedActionConfig::Set(val) => {
                stmt = stmt.then(Action::SetMed(Some(*val)));
            }
            MedActionConfig::Remove { .. } => {
                stmt = stmt.then(Action::SetMed(None));
            }
        }
    }

    // Community
    if let Some(ref comm_action) = actions.community {
        let communities = comm_action
            .communities
            .iter()
            .map(|s| parse_community_value(s))
            .collect::<Result<Vec<_>, _>>()?;

        let action = match comm_action.operation.as_str() {
            "add" => Action::SetCommunity(CommunityOp::Add(communities)),
            "remove" => Action::SetCommunity(CommunityOp::Remove(communities)),
            "replace" => Action::SetCommunity(CommunityOp::Replace(communities)),
            _ => {
                return Err(format!(
                    "invalid community operation '{}' (must be 'add', 'remove', or 'replace')",
                    comm_action.operation
                ))
            }
        };
        stmt = stmt.then(action);
    }

    // Extended Community
    if let Some(ref ec_action) = actions.ext_community {
        use crate::bgp::ext_community::parse_extended_community;

        let ext_communities = ec_action
            .ext_communities
            .iter()
            .map(|s| parse_extended_community(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("invalid extended community: {}", e))?;

        let action = match ec_action.operation.as_str() {
            "add" => Action::SetExtCommunity(ExtCommunityOp::Add(ext_communities)),
            "remove" => Action::SetExtCommunity(ExtCommunityOp::Remove(ext_communities)),
            "replace" => Action::SetExtCommunity(ExtCommunityOp::Replace(ext_communities)),
            _ => {
                return Err(format!(
                "invalid extended community operation '{}' (must be 'add', 'remove', or 'replace')",
                ec_action.operation
            ))
            }
        };
        stmt = stmt.then(action);
    }

    // Large Community
    if let Some(ref lc_action) = actions.large_community {
        use crate::bgp::large_community::parse_large_community;

        let large_communities = lc_action
            .large_communities
            .iter()
            .map(|s| parse_large_community(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("invalid large community: {}", e))?;

        let action = match lc_action.operation.as_str() {
            "add" => Action::SetLargeCommunity(LargeCommunityOp::Add(large_communities)),
            "remove" => Action::SetLargeCommunity(LargeCommunityOp::Remove(large_communities)),
            "replace" => Action::SetLargeCommunity(LargeCommunityOp::Replace(large_communities)),
            _ => {
                return Err(format!(
                "invalid large community operation '{}' (must be 'add', 'remove', or 'replace')",
                lc_action.operation
            ))
            }
        };
        stmt = stmt.then(action);
    }

    if let Some(rpki_config) = actions.set_rpki_state {
        stmt = stmt.then(Action::SetRpkiState(rpki_config.into()));
    }

    // Accept/Reject (should be last)
    if actions.accept == Some(true) {
        stmt = stmt.then(Action::Accept);
    }
    if actions.reject == Some(true) {
        stmt = stmt.then(Action::Reject);
    }

    Ok(stmt)
}

/// Parse community string in format "65000:100" or decimal
fn parse_community_value(s: &str) -> Result<u32, String> {
    // Try decimal format first
    if let Ok(val) = s.parse::<u32>() {
        return Ok(val);
    }

    // Try "65000:100" format
    if let Some((high, low)) = s.split_once(':') {
        let high_val = high
            .parse::<u16>()
            .map_err(|_| format!("invalid high part '{}' in community", high))?;
        let low_val = low
            .parse::<u16>()
            .map_err(|_| format!("invalid low part '{}' in community", low))?;
        return Ok((high_val as u32) << 16 | (low_val as u32));
    }

    Err(format!(
        "invalid community format '{}' (expected '65000:100' or decimal)",
        s
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::bgpls_nlri::{LsDescriptors, LsNlri, LsNlriBody, LsNlriType, NodeDescriptor};
    use crate::net::Ipv4Net;
    use crate::policy::test_helpers::{create_path, test_prefix};
    use crate::policy::Policy;
    use crate::rib::RouteSource;
    use conf::bgp::PolicyDefinitionConfig;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn prefix_key(prefix: IpNetwork) -> RouteKey {
        RouteKey::Prefix(prefix)
    }

    fn test_prefix_key() -> RouteKey {
        prefix_key(test_prefix())
    }

    /// Create an LS route key with configurable fields for testing.
    fn make_ls_route_key(
        nlri_type: LsNlriType,
        protocol_id: u8,
        identifier: u64,
        as_number: Option<u32>,
        igp_router_id: Option<Vec<u8>>,
    ) -> RouteKey {
        RouteKey::LinkState(Box::new(LsNlri {
            nlri_type: nlri_type as u16,
            raw: vec![],
            body: Some(LsNlriBody {
                protocol_id,
                identifier,
                descriptors: LsDescriptors::Node {
                    local_node: NodeDescriptor {
                        as_number,
                        igp_router_id,
                        ..Default::default()
                    },
                },
            }),
            route_distinguisher: None,
        }))
    }

    #[test]
    fn test_statement_no_conditions() {
        let statement = Statement::new().then(Action::SetLocalPref {
            value: 100,
            force: false,
        });
        let mut path = create_path(RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
        });
        assert_eq!(statement.apply(&test_prefix_key(), &mut path), Some(true));
        assert_eq!(path.local_pref(), Some(100));
    }

    #[test]
    fn test_statement_condition() {
        let prefix = test_prefix();
        let other_prefix = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(192, 168, 1, 0),
            prefix_length: 24,
        });
        let statement =
            Statement::new()
                .when(Condition::Prefix(prefix))
                .then(Action::SetLocalPref {
                    value: 200,
                    force: false,
                });
        let mut path = create_path(RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
        });

        assert_eq!(statement.apply(&prefix_key(prefix), &mut path), Some(true));
        assert_eq!(path.local_pref(), Some(200));

        path.attrs_mut().local_pref = None;
        assert_eq!(statement.apply(&prefix_key(other_prefix), &mut path), None);
        assert_eq!(path.local_pref(), None);

        // Prefix conditions ignore LS routes
        let ls_key = make_ls_route_key(LsNlriType::Node, 4, 0, None, None);
        assert_eq!(statement.apply(&ls_key, &mut path), None);
    }

    #[test]
    fn test_statement_multiple_conditions() {
        let prefix = test_prefix();
        let statement = Statement::new()
            .when(Condition::Prefix(prefix))
            .when(Condition::Neighbor(test_ip(1)))
            .then(Action::SetLocalPref {
                value: 200,
                force: false,
            });

        let mut path1 = create_path(RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
        });
        assert_eq!(statement.apply(&prefix_key(prefix), &mut path1), Some(true));
        assert_eq!(path1.local_pref(), Some(200));

        let mut path2 = create_path(RouteSource::Ebgp {
            peer_ip: test_ip(2),
            bgp_id: std::net::Ipv4Addr::new(2, 2, 2, 2),
        });
        assert_eq!(statement.apply(&prefix_key(prefix), &mut path2), None);
        assert_eq!(path2.local_pref(), None);
    }

    #[test]
    fn test_statement_multiple_actions() {
        let statement = Statement::new()
            .then(Action::SetLocalPref {
                value: 200,
                force: false,
            })
            .then(Action::SetMed(None));
        let mut path = create_path(RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
        });
        path.attrs_mut().med = Some(100);
        assert_eq!(statement.apply(&test_prefix_key(), &mut path), Some(true));
        assert_eq!(path.local_pref(), Some(200));
        assert_eq!(path.med(), None);
    }

    #[test]
    fn test_statement_reject() {
        let statement = Statement::new().then(Action::Reject);
        let mut path = create_path(RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
        });
        assert_eq!(statement.apply(&test_prefix_key(), &mut path), Some(false));
    }

    #[test]
    fn test_policy_accept_all() {
        let policy = Policy::new("test".to_string()).with(Statement::new().then(Action::Accept));
        let mut path = create_path(RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
        });
        assert!(policy.accept(&test_prefix_key(), &mut path));
    }

    #[test]
    fn test_policy_empty_rejects() {
        let policy = Policy::new("test".to_string());
        let mut path = create_path(RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
        });
        assert!(!policy.accept(&test_prefix_key(), &mut path));
    }

    #[test]
    fn test_policy_statement_ordering() {
        let prefix = test_prefix();
        let other_prefix = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(192, 168, 1, 0),
            prefix_length: 24,
        });
        let policy = Policy::new("test".to_string())
            .with(
                Statement::new()
                    .when(Condition::Prefix(prefix))
                    .then(Action::SetLocalPref {
                        value: 200,
                        force: false,
                    }),
            )
            .with(Statement::new().then(Action::SetLocalPref {
                value: 100,
                force: false,
            }));

        let mut path1 = create_path(RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
        });
        assert!(policy.accept(&prefix_key(prefix), &mut path1));
        assert_eq!(path1.local_pref(), Some(200));

        let mut path2 = create_path(RouteSource::Ebgp {
            peer_ip: test_ip(1),
            bgp_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
        });
        assert!(policy.accept(&prefix_key(other_prefix), &mut path2));
        assert_eq!(path2.local_pref(), Some(100));
    }

    #[test]
    fn test_parse_community_value() {
        // Decimal format
        assert_eq!(parse_community_value("65536").unwrap(), 65536);

        // AS:NN format
        assert_eq!(
            parse_community_value("65000:100").unwrap(),
            (65000 << 16) | 100
        );

        // Invalid formats
        assert!(parse_community_value("invalid").is_err());
        assert!(parse_community_value("65000:").is_err());
        assert!(parse_community_value(":100").is_err());
    }

    #[test]
    fn test_policy_from_config() {
        use conf::bgp::ConditionsConfig;

        let defined_sets = DefinedSets::default();

        let policy_def = PolicyDefinitionConfig {
            name: "test-policy".to_string(),
            statements: vec![
                StatementConfig {
                    name: Some("stmt1".to_string()),
                    conditions: ConditionsConfig {
                        prefix: Some("10.0.0.0/8".to_string()),
                        ..Default::default()
                    },
                    actions: ActionsConfig {
                        local_pref: Some(LocalPrefActionConfig::Set(200)),
                        accept: Some(true),
                        ..Default::default()
                    },
                },
                StatementConfig {
                    name: Some("stmt2".to_string()),
                    conditions: ConditionsConfig {
                        prefix: Some("192.168.0.0/16".to_string()),
                        ..Default::default()
                    },
                    actions: ActionsConfig {
                        reject: Some(true),
                        ..Default::default()
                    },
                },
            ],
        };

        // Parse from config
        let actual = Policy::from_config(&policy_def, &defined_sets).unwrap();

        // Build expected policy manually
        let expected = Policy::new("test-policy".to_string())
            .with(
                Statement::new()
                    .when(Condition::Prefix("10.0.0.0/8".parse().unwrap()))
                    .then(Action::SetLocalPref {
                        value: 200,
                        force: false,
                    })
                    .then(Action::Accept),
            )
            .with(
                Statement::new()
                    .when(Condition::Prefix("192.168.0.0/16".parse().unwrap()))
                    .then(Action::Reject),
            );

        // Now we can directly compare policies!
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_afi_safi_condition() {
        let mut path = create_path(RouteSource::Local);
        let ipv4_key = test_prefix_key();
        let ls_key = make_ls_route_key(LsNlriType::Node, 4, 0, Some(65001), None);

        let cases = vec![
            // (condition, route_key, expected)
            (AfiSafiMatch::Ipv4Unicast, &ipv4_key, true),
            (AfiSafiMatch::BgpLs, &ipv4_key, false),
            (AfiSafiMatch::BgpLs, &ls_key, true),
            (AfiSafiMatch::Ipv4Unicast, &ls_key, false),
            (AfiSafiMatch::Ipv6Unicast, &ipv4_key, false),
            (AfiSafiMatch::Ipv6Unicast, &ls_key, false),
        ];
        for (afi_safi_match, route_key, expected) in cases {
            let cond = Condition::AfiSafi(afi_safi_match);
            assert_eq!(
                cond.matches(route_key, &path),
                expected,
                "AfiSafi({:?}) vs {:?}",
                afi_safi_match,
                route_key.afi_safi()
            );
        }

        // Verify it works in a statement (accept BGP-LS, reject everything else)
        let policy = Policy::new("test".to_string())
            .with(
                Statement::new()
                    .when(Condition::AfiSafi(AfiSafiMatch::BgpLs))
                    .then(Action::Accept),
            )
            .with(Statement::new().then(Action::Reject));

        assert!(policy.accept(&ls_key, &mut path));
        assert!(!policy.accept(&ipv4_key, &mut path));
    }

    #[test]
    fn test_ls_nlri_type_condition() {
        let path = create_path(RouteSource::Local);
        let cases = vec![
            (LsNlriTypeMatch::Node, LsNlriType::Node, true),
            (LsNlriTypeMatch::Node, LsNlriType::Link, false),
            (LsNlriTypeMatch::Link, LsNlriType::Link, true),
            (LsNlriTypeMatch::PrefixV4, LsNlriType::PrefixV4, true),
            (LsNlriTypeMatch::PrefixV6, LsNlriType::PrefixV6, true),
            (LsNlriTypeMatch::PrefixV4, LsNlriType::PrefixV6, false),
        ];
        for (match_type, nlri_type, expected) in cases {
            let key = make_ls_route_key(nlri_type, 4, 0, None, None);
            let cond = Condition::LsNlriType(match_type);
            assert_eq!(
                cond.matches(&key, &path),
                expected,
                "LsNlriType({:?}) vs {:?}",
                match_type,
                nlri_type
            );
        }

        // Prefix routes never match
        assert!(!Condition::LsNlriType(LsNlriTypeMatch::Node).matches(&test_prefix_key(), &path));

        // No body (opaque NLRI) — nlri_type is always available
        let opaque_key = RouteKey::LinkState(Box::new(LsNlri {
            nlri_type: 1,
            raw: vec![],
            body: None,
            route_distinguisher: None,
        }));
        assert!(Condition::LsNlriType(LsNlriTypeMatch::Node).matches(&opaque_key, &path));
    }

    #[test]
    fn test_ls_protocol_id_condition() {
        use crate::bgp::bgpls_nlri::LsProtocolId as Proto;

        let path = create_path(RouteSource::Local);
        let cases = vec![
            (LsProtocolIdMatch::Direct, Proto::Direct as u8, true),
            (LsProtocolIdMatch::Static, Proto::Static as u8, true),
            (LsProtocolIdMatch::OspfV2, Proto::OspfV2 as u8, true),
            (LsProtocolIdMatch::OspfV3, Proto::OspfV3 as u8, true),
            (LsProtocolIdMatch::IsIsL1, Proto::IsIsL1 as u8, true),
            (LsProtocolIdMatch::IsIsL2, Proto::IsIsL2 as u8, true),
            (LsProtocolIdMatch::Direct, Proto::Static as u8, false),
            (LsProtocolIdMatch::OspfV2, Proto::OspfV3 as u8, false),
        ];
        for (match_proto, proto_id, expected) in cases {
            let key = make_ls_route_key(LsNlriType::Node, proto_id, 0, None, None);
            let cond = Condition::LsProtocolId(match_proto);
            assert_eq!(
                cond.matches(&key, &path),
                expected,
                "LsProtocolId({:?}) vs proto_id={}",
                match_proto,
                proto_id
            );
        }

        // No body -> false
        let opaque = RouteKey::LinkState(Box::new(LsNlri {
            nlri_type: 1,
            raw: vec![],
            body: None,
            route_distinguisher: None,
        }));
        assert!(!Condition::LsProtocolId(LsProtocolIdMatch::Direct).matches(&opaque, &path));
    }

    #[test]
    fn test_ls_instance_id_condition() {
        let path = create_path(RouteSource::Local);
        let key = make_ls_route_key(LsNlriType::Node, 4, 42, None, None);

        assert!(Condition::LsInstanceId(42).matches(&key, &path));
        assert!(!Condition::LsInstanceId(99).matches(&key, &path));
        assert!(!Condition::LsInstanceId(42).matches(&test_prefix_key(), &path));

        // No body -> false
        let opaque = RouteKey::LinkState(Box::new(LsNlri {
            nlri_type: 1,
            raw: vec![],
            body: None,
            route_distinguisher: None,
        }));
        assert!(!Condition::LsInstanceId(42).matches(&opaque, &path));
    }

    #[test]
    fn test_ls_node_as_condition() {
        let path = create_path(RouteSource::Local);
        let key = make_ls_route_key(LsNlriType::Node, 4, 0, Some(65001), None);

        assert!(Condition::LsNodeAs(65001).matches(&key, &path));
        assert!(!Condition::LsNodeAs(65002).matches(&key, &path));

        // No AS number set
        let key_no_as = make_ls_route_key(LsNlriType::Node, 4, 0, None, None);
        assert!(!Condition::LsNodeAs(65001).matches(&key_no_as, &path));

        // Prefix routes never match
        assert!(!Condition::LsNodeAs(65001).matches(&test_prefix_key(), &path));

        // No body -> false
        let opaque = RouteKey::LinkState(Box::new(LsNlri {
            nlri_type: 1,
            raw: vec![],
            body: None,
            route_distinguisher: None,
        }));
        assert!(!Condition::LsNodeAs(65001).matches(&opaque, &path));
    }

    #[test]
    fn test_ls_node_router_id_condition() {
        let path = create_path(RouteSource::Local);
        let router_id = Ipv4Addr::new(10, 0, 0, 1);
        let key = make_ls_route_key(
            LsNlriType::Node,
            4,
            0,
            None,
            Some(router_id.octets().to_vec()),
        );

        // Match
        assert!(Condition::LsNodeRouterId(IpAddr::V4(router_id)).matches(&key, &path));
        // Mismatch
        assert!(
            !Condition::LsNodeRouterId(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))).matches(&key, &path)
        );
        // No router ID set
        let key_no_rid = make_ls_route_key(LsNlriType::Node, 4, 0, None, None);
        assert!(!Condition::LsNodeRouterId(IpAddr::V4(router_id)).matches(&key_no_rid, &path));
        // Prefix routes never match
        assert!(
            !Condition::LsNodeRouterId(IpAddr::V4(router_id)).matches(&test_prefix_key(), &path)
        );

        // No body -> false
        let opaque = RouteKey::LinkState(Box::new(LsNlri {
            nlri_type: 1,
            raw: vec![],
            body: None,
            route_distinguisher: None,
        }));
        assert!(!Condition::LsNodeRouterId(IpAddr::V4(router_id)).matches(&opaque, &path));
    }

    #[test]
    fn test_combined_ls_conditions() {
        let mut path = create_path(RouteSource::Local);
        let key = make_ls_route_key(LsNlriType::Node, 4, 0, Some(65001), None);

        let policy = Policy::new("test".to_string()).with(
            Statement::new()
                .when(Condition::AfiSafi(AfiSafiMatch::BgpLs))
                .when(Condition::LsNlriType(LsNlriTypeMatch::Node))
                .when(Condition::LsNodeAs(65001))
                .then(Action::Accept),
        );

        // All three conditions match
        assert!(policy.accept(&key, &mut path));

        // Wrong NLRI type -> no match -> reject
        let link_key = make_ls_route_key(LsNlriType::Link, 4, 0, Some(65001), None);
        assert!(!policy.accept(&link_key, &mut path));

        // Wrong AS -> no match -> reject
        let wrong_as_key = make_ls_route_key(LsNlriType::Node, 4, 0, Some(65002), None);
        assert!(!policy.accept(&wrong_as_key, &mut path));
    }

    #[test]
    fn test_ls_condition_config() {
        let defined_sets = DefinedSets::default();

        // Valid config roundtrips correctly
        let config = StatementConfig {
            name: None,
            conditions: ConditionsConfig {
                afi_safi: Some("bgp-ls".to_string()),
                ls_nlri_type: Some("node".to_string()),
                ls_protocol_id: Some("direct".to_string()),
                ls_instance_id: Some(42),
                ls_node_as: Some(65001),
                ls_node_router_id: Some("10.0.0.1".to_string()),
                ..Default::default()
            },
            actions: ActionsConfig {
                accept: Some(true),
                ..Default::default()
            },
        };
        let statement = build_statement(&config, &defined_sets).unwrap();
        let roundtripped = statement.to_config();
        assert_eq!(roundtripped.conditions.afi_safi, Some("bgp-ls".to_string()));
        assert_eq!(
            roundtripped.conditions.ls_nlri_type,
            Some("node".to_string())
        );
        assert_eq!(
            roundtripped.conditions.ls_protocol_id,
            Some("direct".to_string())
        );
        assert_eq!(roundtripped.conditions.ls_instance_id, Some(42));
        assert_eq!(roundtripped.conditions.ls_node_as, Some(65001));
        assert_eq!(
            roundtripped.conditions.ls_node_router_id,
            Some("10.0.0.1".to_string())
        );

        // Invalid values rejected
        let invalid_cases = vec![
            (
                "afi_safi",
                ConditionsConfig {
                    afi_safi: Some("invalid".to_string()),
                    ..Default::default()
                },
            ),
            (
                "ls_nlri_type",
                ConditionsConfig {
                    ls_nlri_type: Some("invalid".to_string()),
                    ..Default::default()
                },
            ),
            (
                "ls_protocol_id",
                ConditionsConfig {
                    ls_protocol_id: Some("invalid".to_string()),
                    ..Default::default()
                },
            ),
            (
                "ls_node_router_id",
                ConditionsConfig {
                    ls_node_router_id: Some("not-an-ip".to_string()),
                    ..Default::default()
                },
            ),
        ];
        for (field, conditions) in invalid_cases {
            let config = StatementConfig {
                name: None,
                conditions,
                actions: ActionsConfig {
                    accept: Some(true),
                    ..Default::default()
                },
            };
            assert!(
                build_statement(&config, &defined_sets).is_err(),
                "expected error for invalid {}",
                field
            );
        }
    }
}
