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

//! Route propagation logic for BGP UPDATE messages

use crate::bgp::bgpls_nlri::LsNlri;
use crate::bgp::community;
use crate::bgp::ext_community::{
    from_rpki_state_community, is_rpki_state_community, is_transitive,
};
use crate::bgp::msg::{Message, MessageFormat, MAX_MESSAGE_SIZE};
use crate::bgp::msg_update::{AsPathSegment, AsPathSegmentType, UpdateMessage};
use crate::bgp::msg_update_types::{
    NextHopAddr, PathAttribute, NO_ADVERTISE, NO_EXPORT, NO_EXPORT_SUBCONFED,
};
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::log::{error, info, warn};
use crate::net::IpNetwork;
use crate::peer::BgpState;
use crate::peer::PeerCapabilities;
use crate::peer::PeerOp;
use crate::policy::{AfiSafiPolicies, PolicyResult};
use crate::rib::rib_loc::{LocRib, RouteDelta};
use crate::rib::{
    split_withdrawals, AdjRibOut, Path, PathAttrs, RouteKey, RoutePath, RouteSource, Withdrawal,
};
use crate::rpki::vrp::RpkiValidation;

#[cfg(test)]
use crate::policy::Policy;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};

use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// A batch of route announcements sharing the same AFI and path attributes.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct AnnouncementBatch {
    pub afi_safi: AfiSafi,
    pub path: Arc<Path>,
    pub keys: Vec<RouteKey>,
}

impl AnnouncementBatch {
    /// Build an UpdateMessage from this batch.
    pub fn to_update(&self, format: MessageFormat) -> UpdateMessage {
        match self.afi_safi.afi {
            Afi::Ipv4 | Afi::Ipv6 => {
                let prefixes: Vec<IpNetwork> = self
                    .keys
                    .iter()
                    .filter_map(|k| match k {
                        RouteKey::Prefix(p) => Some(*p),
                        _ => None,
                    })
                    .collect();
                UpdateMessage::new(&self.path, prefixes, format)
            }
            Afi::LinkState => {
                let ls_nlri: Vec<LsNlri> = self
                    .keys
                    .iter()
                    .filter_map(|k| match k {
                        RouteKey::LinkState(nlri) => Some((**nlri).clone()),
                        _ => None,
                    })
                    .collect();
                UpdateMessage::new_ls(&self.path, ls_nlri, self.afi_safi, format)
            }
        }
    }
}

/// Bundles per-peer parameters needed for route export
pub struct PeerExportContext<'a> {
    pub peer_addr: IpAddr,
    pub peer_tx: &'a mpsc::UnboundedSender<PeerOp>,
    pub local_asn: u32,
    pub peer_asn: u32,
    pub local_next_hop: IpAddr,
    /// RFC 2545: local link-local IPv6 for 32-byte next-hop in MP_REACH_NLRI
    pub local_link_local: Option<Ipv6Addr>,
    /// Vec already includes RFC 8212 fallback (eBGP deny-all, iBGP accept-all).
    pub export_policies: &'a AfiSafiPolicies,
    pub rr_client: bool,
    pub rs_client: bool,
    pub cluster_id: Ipv4Addr,
    pub send_format: MessageFormat,
    pub negotiated_afi_safis: &'a HashSet<AfiSafi>,
    pub next_hop_self: bool,
    /// RFC 8326: tag exported routes with GRACEFUL_SHUTDOWN community (65535:0).
    pub graceful_shutdown: bool,
    /// Negotiated capabilities for this peer
    pub capabilities: &'a PeerCapabilities,
    /// RFC 8097: attach RPKI state extended community on export
    pub send_rpki_community: bool,
}

impl<'a> PeerExportContext<'a> {
    /// Returns AFI/SAFIs to propagate. Falls back to IPv4/Unicast if no multiprotocol
    /// capabilities were negotiated (RFC 4760).
    fn is_ebgp(&self) -> bool {
        self.local_asn != self.peer_asn
    }

    fn is_ibgp(&self) -> bool {
        self.local_asn == self.peer_asn
    }

    fn afi_safis(&self) -> Vec<AfiSafi> {
        if self.negotiated_afi_safis.is_empty() {
            vec![AfiSafi::new(Afi::Ipv4, Safi::Unicast)]
        } else {
            self.negotiated_afi_safis.iter().copied().collect()
        }
    }
}

/// Check if a path should be exported to a peer (pre-policy filtering).
fn should_export_to_peer(path: &Path, ctx: &PeerExportContext) -> bool {
    // RFC 4456: iBGP reflection requires at least one RR client
    if ctx.is_ibgp() && path.source().is_ibgp() && !path.source().is_rr_client() && !ctx.rr_client {
        return false;
    }

    // Don't send a path back to the peer it was learned from
    if path.source().peer_ip() == Some(ctx.peer_addr) {
        return false;
    }

    // RFC 1997: NO_ADVERTISE, NO_EXPORT, NO_EXPORT_SUBCONFED
    if should_filter_by_community(path.communities(), ctx.local_asn, ctx.peer_asn) {
        return false;
    }

    // RFC 9494 Section 4.3: LLGR_STALE routes SHOULD NOT be advertised to a peer
    // from which LLGR capability was not received.
    if path.communities().contains(&community::LLGR_STALE) && ctx.capabilities.llgr.is_none() {
        return false;
    }

    true
}

/// Check if a route should be filtered based on well-known communities
/// RFC 1997 Section 3: Well-known communities
fn should_filter_by_community(communities: &[u32], local_asn: u32, peer_asn: u32) -> bool {
    if communities.contains(&NO_ADVERTISE) {
        return true;
    }

    let is_ebgp = local_asn != peer_asn;

    if is_ebgp && (communities.contains(&NO_EXPORT) || communities.contains(&NO_EXPORT_SUBCONFED)) {
        return true;
    }

    false
}

/// Check if we should propagate routes to this peer
pub fn should_propagate_to_peer(
    peer_addr: IpAddr,
    peer_state: BgpState,
    originating_peer: Option<IpAddr>,
) -> bool {
    // Skip the peer that sent us the original update (if any)
    if let Some(orig_peer) = originating_peer {
        if peer_addr == orig_peer {
            return false;
        }
    }

    // Only send to established peers
    peer_state == BgpState::Established
}

/// Build AS path for export to a peer
/// RFC 4271 Section 5.1.2:
/// - Local routes to eBGP: [local_asn]
/// - Local routes to iBGP: [] (empty)
/// - Learned routes to eBGP: prepend local_asn to first AS_SEQUENCE (or create new segment)
/// - Learned routes to iBGP: unchanged
///
/// RFC 7947: Route servers preserve AS_PATH unchanged (no local ASN prepending)
///
/// Preserves AS_SET segments during propagation
pub fn build_export_as_path(path: &Path, ctx: &PeerExportContext) -> Vec<AsPathSegment> {
    // RFC 7947: Route servers preserve AS_PATH (no prepending)
    if ctx.rs_client {
        return path.as_path().clone();
    }

    // Truly locally originated routes (empty AS_PATH)
    if matches!(path.source(), RouteSource::Local) && path.as_path().is_empty() {
        if ctx.is_ebgp() {
            // eBGP: AS_PATH = [local_asn]
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![ctx.local_asn],
            }]
        } else {
            // iBGP: AS_PATH = [] (empty)
            vec![]
        }
    } else if ctx.is_ebgp() {
        prepend_local_asn(path.as_path(), ctx.local_asn)
    } else {
        // iBGP: preserve AS_PATH unchanged
        path.as_path().clone()
    }
}

/// Prepend local ASN to AS_PATH for eBGP export
/// RFC 4271: Prepend to existing AS_SEQUENCE or create new segment
fn prepend_local_asn(as_path: &[AsPathSegment], local_asn: u32) -> Vec<AsPathSegment> {
    let mut new_segments = Vec::new();

    if let Some(first) = as_path.first() {
        if first.segment_type == AsPathSegmentType::AsSequence {
            // Prepend to existing AS_SEQUENCE
            let mut new_asn_list = vec![local_asn];
            new_asn_list.extend_from_slice(&first.asn_list);
            new_segments.push(AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: new_asn_list.len() as u8,
                asn_list: new_asn_list,
            });
            new_segments.extend_from_slice(&as_path[1..]);
        } else {
            // First segment is AS_SET, create new AS_SEQUENCE segment
            new_segments.push(AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![local_asn],
            });
            new_segments.extend_from_slice(as_path);
        }
    } else {
        // Empty AS_PATH, create new AS_SEQUENCE
        new_segments.push(AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: 1,
            asn_list: vec![local_asn],
        });
    }

    new_segments
}

/// Determine LOCAL_PREF to include in UPDATE message
///
/// RFC 4271 Section 5.1.5:
/// - iBGP: LOCAL_PREF SHALL be included
/// - eBGP: LOCAL_PREF MUST NOT be included
///
/// RFC 7947: Route servers follow the same session type rules
pub fn build_export_local_pref(path: &Path, ctx: &PeerExportContext) -> Option<u32> {
    if ctx.local_asn == ctx.peer_asn {
        path.local_pref()
    } else {
        None
    }
}

/// Determine MULTI_EXIT_DISC (MED) to include in UPDATE message
///
/// RFC 4271 Section 5.1.4:
/// - iBGP: MED MAY be propagated to other BGP speakers within the same AS
/// - eBGP: MED MUST NOT be propagated to other neighboring ASes
///
/// RFC 7947: Route servers preserve MED unchanged
pub fn build_export_med(path: &Path, ctx: &PeerExportContext) -> Option<u32> {
    if ctx.rs_client {
        return path.med();
    }

    // iBGP: preserve MED unchanged
    if ctx.is_ibgp() {
        return path.med();
    }

    // eBGP: only send MED if route originated from our AS
    // Check source for local routes (before iBGP propagation changes it to Ibgp)
    if matches!(path.source(), RouteSource::Local) {
        return path.med();
    }

    // eBGP: source may be Ibgp if route transited iBGP, so inspect AS_PATH instead
    match path.as_path().first() {
        None => path.med(), // Empty AS_PATH means local route
        Some(segment) if segment.asn_list.first() != Some(&ctx.local_asn) => None, // External AS
        Some(segment) if segment.segment_type == AsPathSegmentType::AsSet => None, // RFC 4271 9.2.2.2
        Some(_) => path.med(), // Route from our AS
    }
}

/// Filter extended communities for export to peer
/// RFC 4360: Non-transitive extended communities (bit 6 = 1) must be filtered when advertising to eBGP peers
/// RFC 7947: Route servers preserve ALL communities (both transitive and non-transitive)
pub fn build_export_extended_communities(path: &Path, ctx: &PeerExportContext) -> Vec<u64> {
    // RFC 7947: Route servers preserve ALL communities
    if ctx.rs_client {
        return path.extended_communities().clone();
    }

    if ctx.is_ebgp() {
        // Filter out non-transitive extended communities (RFC 4360 Section 6)
        path.extended_communities()
            .iter()
            .filter(|&&extcomm| is_transitive(extcomm))
            .copied()
            .collect()
    } else {
        let mut communities = path.extended_communities().clone();

        // RFC 8097: attach RPKI state extended community
        if ctx.send_rpki_community {
            communities.retain(|ec| !is_rpki_state_community(*ec));
            communities.push(from_rpki_state_community(path.rpki_state.to_u8()));
        }

        communities
    }
}

/// Build communities for export to peer.
/// RFC 8326: inject GRACEFUL_SHUTDOWN community when the flag is set on this peer session.
pub fn build_export_communities(path: &Path, ctx: &PeerExportContext) -> Vec<u32> {
    let mut comms = path.attrs.communities.clone();
    if ctx.graceful_shutdown && !comms.contains(&community::GRACEFUL_SHUTDOWN) {
        comms.push(community::GRACEFUL_SHUTDOWN);
    }
    comms
}

/// Build unknown attributes for export to peer.
/// RFC 7947 Section 2.2: Route servers preserve all unknown attributes (transitive and non-transitive).
/// RFC 4271: Normal eBGP only forwards optional transitive attributes.
fn build_export_unknown_attrs(path: &Path, ctx: &PeerExportContext) -> Vec<PathAttribute> {
    if ctx.rs_client {
        return path.attrs.unknown_attrs.clone();
    }

    if ctx.is_ebgp() {
        // eBGP: only forward optional transitive unknown attributes (RFC 4271)
        path.attrs
            .unknown_attrs
            .iter()
            .filter(|attr| attr.is_unknown_transitive())
            .cloned()
            .collect()
    } else {
        // iBGP: propagate all unknown attributes within the AS
        path.attrs.unknown_attrs.clone()
    }
}

/// Send a serialized UPDATE to a peer with logging.
fn send_update(ctx: &PeerExportContext, msg: UpdateMessage, count: usize, label: &str) {
    let serialized = msg.serialize();
    if let Err(e) = ctx.peer_tx.send(PeerOp::SendUpdate(serialized)) {
        error!(peer_addr = %ctx.peer_addr, error = %e, "failed to send {label} to peer");
    } else {
        info!(count, peer_addr = %ctx.peer_addr, "propagated {label} to peer");
    }
}

/// Send withdrawal messages to a peer, splitting IP, LS, and LS-VPN into separate UPDATEs.
fn send_withdrawals(ctx: &PeerExportContext, withdrawn: Vec<Withdrawal>, format: MessageFormat) {
    if withdrawn.is_empty() {
        return;
    }

    let (ip_withdrawn, ls_withdrawn, ls_vpn_withdrawn) = split_withdrawals(&withdrawn);

    if !ip_withdrawn.is_empty() {
        let count = ip_withdrawn.len();
        send_update(
            ctx,
            UpdateMessage::new_withdraw(ip_withdrawn, format),
            count,
            "withdrawals",
        );
    }

    let ls_afi_safi = AfiSafi::new(Afi::LinkState, Safi::LinkState);
    let ls_vpn_afi_safi = AfiSafi::new(Afi::LinkState, Safi::LinkStateVpn);

    if !ls_withdrawn.is_empty() {
        let count = ls_withdrawn.len();
        send_update(
            ctx,
            UpdateMessage::new_ls_withdraw(ls_withdrawn, ls_afi_safi, format),
            count,
            "LS withdrawals",
        );
    }

    if !ls_vpn_withdrawn.is_empty() {
        let count = ls_vpn_withdrawn.len();
        send_update(
            ctx,
            UpdateMessage::new_ls_withdraw(ls_vpn_withdrawn, ls_vpn_afi_safi, format),
            count,
            "LS-VPN withdrawals",
        );
    }
}

/// Batching key: AFI/SAFI + path attributes + local_path_id.
/// AFI/SAFI ensures different families never share a batch (RFC 4271 Section 6.3).
type BatchingKey = (AfiSafi, Arc<PathAttrs>, Option<u32>);

/// Group announcements by path attributes to enable batching
/// Returns a vector of batches, where each batch contains a path and all prefixes sharing those attributes
pub(crate) fn batch_announcements(to_announce: &[RoutePath]) -> Vec<AnnouncementBatch> {
    let mut batches: HashMap<BatchingKey, AnnouncementBatch> = HashMap::new();

    for RoutePath { key, path } in to_announce {
        let afi_safi = key.afi_safi();
        let batch_key = (afi_safi, Arc::clone(&path.attrs), path.local_path_id);
        let batch = batches
            .entry(batch_key)
            .or_insert_with(|| AnnouncementBatch {
                afi_safi,
                path: Arc::clone(path),
                keys: Vec::new(),
            });
        batch.keys.push(key.clone());
    }

    batches.into_values().collect()
}

fn address_families_match(next_hop: &NextHopAddr, ip_addr: IpAddr) -> bool {
    matches!(
        (next_hop, ip_addr),
        (NextHopAddr::Ipv4(_), IpAddr::V4(_))
            | (NextHopAddr::Ipv6(_), IpAddr::V6(_))
            | (NextHopAddr::Ipv6WithLinkLocal(_, _), IpAddr::V6(_))
    )
}

fn build_ebgp_next_hop(
    path: &Path,
    local_next_hop: IpAddr,
    prefix: &IpNetwork,
) -> Option<NextHopAddr> {
    if address_families_match(path.next_hop(), local_next_hop) {
        // Same address family - rewrite to local interface
        Some(local_next_hop.into())
    } else if !path.next_hop().is_unspecified() {
        // Cross-family with explicit next hop - preserve it
        Some(*path.next_hop())
    } else {
        // Cross-family without explicit next hop - can't advertise
        warn!(
            %prefix,
            "filtering cross-family route without explicit next hop"
        );
        None
    }
}

fn build_ibgp_next_hop(
    path: &Path,
    local_next_hop: IpAddr,
    prefix: &IpNetwork,
) -> Option<NextHopAddr> {
    if !path.source().is_local() {
        // Learned route - preserve next hop
        return Some(*path.next_hop());
    }

    // Locally originated route
    if !path.next_hop().is_unspecified() {
        // Explicit next hop - preserve it
        Some(*path.next_hop())
    } else if address_families_match(path.next_hop(), local_next_hop) {
        // Same address family - use local interface
        Some(local_next_hop.into())
    } else {
        // Cross-family without explicit next hop - can't advertise
        warn!(
            %prefix,
            "filtering cross-family route without explicit next hop"
        );
        None
    }
}

/// Build the NEXT_HOP for export to a peer
/// RFC 4271 Section 5.1.3: Rewrite NEXT_HOP to local interface address
/// RFC 2545/4760: Cross-family (e.g., IPv6 route over IPv4 session) must preserve explicit next hop
/// RFC 7947: Route servers preserve NEXT_HOP unchanged
fn build_export_next_hop(
    path: &Path,
    ctx: &PeerExportContext,
    route_key: &RouteKey,
) -> Option<NextHopAddr> {
    // RFC 9552 Section 5.5: next hop usually set to local endpoint by producers.
    // As propagator, follow standard BGP rules: eBGP/next-hop-self rewrite,
    // iBGP/RS preserve (next-hop used for tiebreak per Section 5.5).
    if matches!(route_key, RouteKey::LinkState(_)) {
        if ctx.rs_client {
            return Some(*path.next_hop());
        }
        if ctx.is_ebgp() || ctx.next_hop_self {
            return Some(ctx.local_next_hop.into());
        }
        return Some(*path.next_hop());
    }

    let prefix = match route_key {
        RouteKey::Prefix(p) => p,
        RouteKey::LinkState(_) => return Some(*path.next_hop()),
    };

    // RFC 7947: Route servers preserve NEXT_HOP unchanged
    if ctx.rs_client {
        return Some(*path.next_hop());
    }

    let next_hop = if ctx.is_ebgp() {
        build_ebgp_next_hop(path, ctx.local_next_hop, prefix)
    } else if ctx.next_hop_self {
        Some(ctx.local_next_hop.into())
    } else {
        build_ibgp_next_hop(path, ctx.local_next_hop, prefix)
    };

    // RFC 2545: for eBGP IPv6, include link-local in 32-byte next-hop
    match (next_hop, ctx.local_link_local) {
        (Some(NextHopAddr::Ipv6(global)), Some(link_local)) if ctx.is_ebgp() => {
            Some(NextHopAddr::Ipv6WithLinkLocal(global, link_local))
        }
        _ => next_hop,
    }
}

/// Build export attributes from a post-policy path. Returns None if next hop
/// cannot be built (cross-family routes without explicit next hop).
fn build_export_attrs(
    path: &Path,
    ctx: &PeerExportContext,
    route_key: &RouteKey,
) -> Option<Arc<PathAttrs>> {
    // RFC 4456: RR attributes (skip for RS clients)
    let (originator_id, cluster_list) = if ctx.rs_client {
        (None, Vec::new()) // RS doesn't add RR attributes
    } else {
        build_export_rr_attrs(path, ctx, ctx.is_ibgp())
    };

    Some(Arc::new(PathAttrs {
        origin: path.attrs.origin,
        as_path: build_export_as_path(path, ctx),
        next_hop: build_export_next_hop(path, ctx, route_key)?,
        source: path.attrs.source,
        local_pref: build_export_local_pref(path, ctx),
        med: build_export_med(path, ctx),
        atomic_aggregate: path.attrs.atomic_aggregate,
        aggregator: path.attrs.aggregator.clone(),
        communities: build_export_communities(path, ctx),
        extended_communities: build_export_extended_communities(path, ctx),
        large_communities: path.attrs.large_communities.clone(),
        unknown_attrs: build_export_unknown_attrs(path, ctx),
        originator_id,
        cluster_list,
        ls_attr: path.attrs.ls_attr.clone(),
    }))
}

/// Build RR attributes for export (originator_id, cluster_list).
fn build_export_rr_attrs(
    path: &Path,
    ctx: &PeerExportContext,
    is_ibgp: bool,
) -> (Option<Ipv4Addr>, Vec<Ipv4Addr>) {
    // RFC 4456: RR attributes are non-transitive, strip for eBGP.
    // For iBGP: preserve when reflecting or when explicitly set.
    let preserve = is_ibgp && (path.source().is_ibgp() || path.originator_id().is_some());
    if !preserve {
        return (None, Vec::new());
    }

    // RFC 4456: When reflecting, set ORIGINATOR_ID and prepend cluster_id
    if path.source().is_ibgp() {
        let originator_id = path
            .attrs
            .originator_id
            .or_else(|| path.attrs.source.bgp_id());
        let mut cluster_list = path.attrs.cluster_list.clone();
        cluster_list.insert(0, ctx.cluster_id);
        (originator_id, cluster_list)
    } else {
        (path.attrs.originator_id, path.attrs.cluster_list.clone())
    }
}

/// Apply per-prefix export filtering and attribute transformation for a peer.
/// Returns None if the path should be filtered (RR rules, source-peer, community, policy).
fn compute_export_path(
    route_key: &RouteKey,
    path: &Arc<Path>,
    ctx: &PeerExportContext,
) -> Option<Path> {
    if !should_export_to_peer(path, ctx) {
        return None;
    }

    let mut exported = Path::clone(path);
    let policies = ctx
        .export_policies
        .get(&route_key.afi_safi())
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    if !evaluate_export_policy(policies, route_key, &mut exported) {
        return None;
    }

    Some(Path {
        local_path_id: exported.local_path_id,
        remote_path_id: exported.remote_path_id,
        attrs: build_export_attrs(&exported, ctx, route_key)?,
        stale: false,
        rpki_state: RpkiValidation::NotFound,
    })
}

/// Compute filtered and transformed routes for a peer
/// Returns Vec of (prefix, transformed_path) ready to advertise
///
/// RFC 4456 Route Reflector rules for iBGP routes to iBGP peers:
/// - Route from client -> reflect to all (clients + non-clients)
/// - Route from non-client -> reflect to clients only
/// - Sets ORIGINATOR_ID and prepends cluster_id to CLUSTER_LIST when reflecting
pub fn compute_routes_for_peer(
    to_announce: &[RoutePath],
    ctx: &PeerExportContext,
) -> Vec<RoutePath> {
    to_announce
        .iter()
        .filter_map(|RoutePath { key, path }| {
            compute_export_path(key, path, ctx)
                .map(|exported_path| RoutePath::new(key.clone(), exported_path))
        })
        .collect()
}

/// Evaluate export policies. Returns true if accepted.
fn evaluate_export_policy(
    policies: &[Arc<crate::policy::Policy>],
    route_key: &RouteKey,
    path: &mut Path,
) -> bool {
    for policy in policies {
        match policy.evaluate(route_key, path) {
            PolicyResult::Accept => return true,
            PolicyResult::Reject => return false,
            PolicyResult::Continue => continue,
        }
    }
    false
}

const CHUNK_SIZE: usize = 10_000;

/// Export all routes to a peer, filtering through export policy.
/// Returns the routes that were actually sent (post-policy).
pub fn export_all_routes_to_peer(
    routes: &[RoutePath],
    ctx: &PeerExportContext,
    format: MessageFormat,
) -> Vec<RoutePath> {
    let mut all_sent = Vec::new();
    for chunk in routes.chunks(CHUNK_SIZE) {
        let filtered = compute_routes_for_peer(chunk, ctx);
        send_batched_announcements(ctx, &filtered, format);
        all_sent.extend(filtered);
    }
    all_sent
}

/// Batch and send announcements to a peer.
/// Batch announcements by shared path attributes and send to peer.
/// Each batch becomes one UPDATE. Dispatches to new() or new_ls() based on route family.
fn send_batched_announcements(
    ctx: &PeerExportContext,
    to_send: &[RoutePath],
    format: MessageFormat,
) {
    let batches = batch_announcements(to_send);

    for batch in batches {
        let update_msg = batch.to_update(format);

        let serialized = update_msg.serialize();
        if serialized.len() > MAX_MESSAGE_SIZE as usize {
            warn!(peer_addr = %ctx.peer_addr, count = batch.keys.len(),
                  size = serialized.len(), max_size = MAX_MESSAGE_SIZE,
                  "UPDATE exceeds maximum size, not advertising");
            continue;
        }

        if let Err(e) = ctx.peer_tx.send(PeerOp::SendUpdate(serialized)) {
            error!(peer_addr = %ctx.peer_addr, error = %e, "failed to send UPDATE to peer");
        } else {
            info!(count = batch.keys.len(), peer_addr = %ctx.peer_addr, "propagated routes to peer");
        }
    }
}

/// Select paths for export to a peer, applying export policy.
///
/// - ADD-PATH peers: all paths that pass policy
/// - Non-ADD-PATH RS clients: iterate in preference order, return first accepted (RFC 7947 route iteration)
/// - Normal peers: best path only
fn select_paths_for_export(
    route_key: &RouteKey,
    send_add_path: bool,
    loc_rib: &LocRib,
    ctx: &PeerExportContext,
) -> Vec<RoutePath> {
    if send_add_path {
        loc_rib
            .get_all_paths(route_key)
            .iter()
            .filter_map(|path| {
                compute_export_path(route_key, path, ctx)
                    .map(|exported_path| RoutePath::new(route_key.clone(), exported_path))
            })
            .collect()
    } else if ctx.rs_client {
        // RFC 7947 route iteration: try paths in preference order, return first that passes policy.
        for path in loc_rib.get_all_paths(route_key) {
            if let Some(p) = compute_export_path(route_key, &path, ctx) {
                return vec![RoutePath::new(route_key.clone(), p)];
            }
        }
        vec![]
    } else {
        loc_rib
            .get_best_path(route_key)
            .into_iter()
            .filter_map(|path| {
                compute_export_path(route_key, path, ctx)
                    .map(|exported_path| RoutePath::new(route_key.clone(), exported_path))
            })
            .collect()
    }
}

/// Build withdrawal NLRIs for stale paths.
/// ADD-PATH mode: one withdrawal per path_id. Normal mode: one withdrawal if all paths removed.
fn build_withdrawals_for_route(
    route_key: &RouteKey,
    stale_paths: &[Arc<Path>],
    export_paths: &[RoutePath],
    send_add_path: bool,
) -> Vec<Withdrawal> {
    if send_add_path {
        stale_paths
            .iter()
            .filter_map(|path| path.local_path_id.map(|pid| (route_key.clone(), Some(pid))))
            .collect()
    } else if export_paths.is_empty() && !stale_paths.is_empty() {
        vec![(route_key.clone(), None)]
    } else {
        vec![]
    }
}

/// Export paths to a peer and update adj-rib-out.
///
/// For each changed prefix, computes the desired export state and diffs against
/// adj-rib-out. Withdrawals fall out naturally when a prefix has no exportable path
/// (filtered, withdrawn, or absent) but exists in adj-rib-out.
///
/// Unified for both ADD-PATH and non-ADD-PATH peers. The only difference is:
/// - Candidate selection: all paths (ADD-PATH) vs best path only
/// - Withdrawal NLRIs: path_id included (ADD-PATH) vs omitted
pub fn propagate_routes_to_peer(
    ctx: &PeerExportContext,
    delta: &RouteDelta,
    loc_rib: &LocRib,
    adj_rib_out: &mut AdjRibOut,
) {
    for afi_safi in ctx.afi_safis() {
        let send_add_path = ctx.send_format.add_path.contains(&afi_safi);
        // ADD-PATH peers need all changed paths to track per-path state.
        // RFC 7947: RS clients without ADD-PATH also need all changes to avoid path hiding.
        let route_keys = if send_add_path || ctx.rs_client {
            &delta.changed
        } else {
            &delta.best_changed
        };

        let mut announcements: Vec<RoutePath> = Vec::new();
        let mut withdrawals: Vec<Withdrawal> = Vec::new();

        for route_key in route_keys {
            if route_key.afi_safi() != afi_safi {
                continue;
            }

            let export_paths = select_paths_for_export(route_key, send_add_path, loc_rib, ctx);
            let stale_paths = adj_rib_out.stale_paths(route_key, &export_paths);

            withdrawals.extend(build_withdrawals_for_route(
                route_key,
                &stale_paths,
                &export_paths,
                send_add_path,
            ));

            announcements.extend(export_paths);

            for path in &stale_paths {
                if let Some(pid) = path.local_path_id {
                    adj_rib_out.remove_path(route_key, pid);
                }
            }
        }

        send_withdrawals(ctx, withdrawals, ctx.send_format);
        send_batched_announcements(ctx, &announcements, ctx.send_format);

        for RoutePath { key, path } in announcements {
            adj_rib_out.insert(key, path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::PendingRoute;
    use super::*;
    use crate::bgp::msg::AddPathMask;
    use crate::bgp::msg_update::{attr_flags, Origin, PathAttrFlag, PathAttrValue};
    use crate::bgp::multiprotocol::Safi;
    use crate::net::{IpNetwork, Ipv4Net};
    use crate::policy::statement::{Action, Condition};
    use crate::policy::Statement;
    use crate::rib::rib_loc::LocRib;
    use crate::rib::{PathAttrs, RouteKey, RoutePath, RouteSource};

    fn test_ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn test_bgp_id(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(1, 1, 1, last)
    }

    fn make_path(source: RouteSource, as_path: Vec<AsPathSegment>, next_hop: NextHopAddr) -> Path {
        Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            rpki_state: RpkiValidation::NotFound,
            attrs: Arc::new(PathAttrs {
                origin: Origin::IGP,
                as_path,
                next_hop,
                source,
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

    fn as_seq(asns: Vec<u32>) -> AsPathSegment {
        AsPathSegment {
            segment_type: AsPathSegmentType::AsSequence,
            segment_len: asns.len() as u8,
            asn_list: asns,
        }
    }

    /// Build a per-family export-policy lookup that applies the same
    /// `policies` list to every common test family (IPv4/IPv6 unicast,
    /// LinkState). Tests that need per-family discrimination should
    /// build their own HashMap.
    fn test_export_policies(policies: Vec<Arc<Policy>>) -> AfiSafiPolicies {
        let mut map = HashMap::new();
        for fam in [
            AfiSafi::new(Afi::Ipv4, Safi::Unicast),
            AfiSafi::new(Afi::Ipv6, Safi::Unicast),
            AfiSafi::new(Afi::LinkState, Safi::LinkState),
        ] {
            map.insert(fam, policies.clone());
        }
        map
    }

    fn make_peer_export_ctx(
        local_asn: u32,
        peer_asn: u32,
        rs_client: bool,
        next_hop_self: bool,
        send_rpki_community: bool,
    ) -> PeerExportContext<'static> {
        let (tx, _rx) = mpsc::unbounded_channel();
        // Leak the channel to get 'static lifetime for test
        let tx_static: &'static mpsc::UnboundedSender<PeerOp> = Box::leak(Box::new(tx));

        // Default test setup: negotiate both IPv4 and IPv6 Unicast
        let negotiated: &'static HashSet<AfiSafi> = Box::leak(Box::new(
            vec![
                AfiSafi::new(Afi::Ipv4, Safi::Unicast),
                AfiSafi::new(Afi::Ipv6, Safi::Unicast),
            ]
            .into_iter()
            .collect(),
        ));
        let empty_policies: &'static AfiSafiPolicies = Box::leak(Box::new(AfiSafiPolicies::new()));

        let capabilities: &'static PeerCapabilities =
            Box::leak(Box::new(PeerCapabilities::default()));

        PeerExportContext {
            peer_addr: test_ip(1),
            peer_tx: tx_static,
            local_asn,
            peer_asn,
            local_next_hop: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            local_link_local: None,
            export_policies: empty_policies,
            rr_client: false,
            rs_client,
            cluster_id: Ipv4Addr::new(1, 1, 1, 1),
            send_format: MessageFormat {
                use_4byte_asn: false,
                add_path: AddPathMask::NONE,
                is_ebgp: local_asn != peer_asn,
                enhanced_rr: false,
            },
            negotiated_afi_safis: negotiated,
            next_hop_self,
            graceful_shutdown: false,
            capabilities,
            send_rpki_community,
        }
    }

    #[test]
    fn test_should_propagate_to_peer() {
        // Should propagate to established peer when no originating peer
        assert!(should_propagate_to_peer(
            test_ip(2),
            BgpState::Established,
            None
        ));

        // Should propagate to established peer when different from originating peer
        assert!(should_propagate_to_peer(
            test_ip(2),
            BgpState::Established,
            Some(test_ip(1))
        ));

        // Should NOT propagate to same peer that sent the route
        assert!(!should_propagate_to_peer(
            test_ip(2),
            BgpState::Established,
            Some(test_ip(2))
        ));

        // Should NOT propagate to non-established peer
        assert!(!should_propagate_to_peer(
            test_ip(3),
            BgpState::Connect,
            Some(test_ip(1))
        ));
    }

    #[test]
    fn test_build_export_as_path() {
        struct TestCase {
            name: &'static str,
            path_as_path: Vec<AsPathSegment>,
            path_source: RouteSource,
            local_asn: u32,
            peer_asn: u32,
            rs_client: bool,
            expected_as_path: Vec<Vec<u32>>, // List of ASN sequences
        }

        let test_cases = vec![
            TestCase {
                name: "local route to eBGP: prepend local ASN",
                path_as_path: vec![],
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                expected_as_path: vec![vec![65000]],
            },
            TestCase {
                name: "local route to iBGP: empty AS_PATH",
                path_as_path: vec![],
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                expected_as_path: vec![],
            },
            TestCase {
                name: "learned route to eBGP: prepend local ASN",
                path_as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                }],
                path_source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                expected_as_path: vec![vec![65000, 65001, 65002]],
            },
            TestCase {
                name: "learned route to iBGP: preserve AS_PATH",
                path_as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65003],
                }],
                path_source: RouteSource::Ibgp {
                    peer_ip: test_ip(2),
                    bgp_id: test_bgp_id(2),
                    rr_client: false,
                },
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                expected_as_path: vec![vec![65003]],
            },
            TestCase {
                name: "RS client: preserve AS_PATH (no prepending)",
                path_as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                }],
                path_source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                local_asn: 65000,
                peer_asn: 65003,
                rs_client: true,
                expected_as_path: vec![vec![65001, 65002]],
            },
            TestCase {
                name: "RS client with local route: preserve AS_PATH",
                path_as_path: vec![],
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: true,
                expected_as_path: vec![],
            },
        ];

        for test_case in test_cases {
            let path = make_path(
                test_case.path_source,
                test_case.path_as_path,
                NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
            );

            let ctx = make_peer_export_ctx(
                test_case.local_asn,
                test_case.peer_asn,
                test_case.rs_client,
                false,
                false,
            );
            let result = build_export_as_path(&path, &ctx);

            // Convert result to Vec<Vec<u32>> for easier comparison
            let result_asns: Vec<Vec<u32>> =
                result.iter().map(|seg| seg.asn_list.clone()).collect();

            assert_eq!(
                result_asns, test_case.expected_as_path,
                "Test case '{}' failed: expected {:?}, got {:?}",
                test_case.name, test_case.expected_as_path, result_asns
            );
        }
    }

    #[test]
    fn test_batch_announcements() {
        let path_a = Arc::new(make_path(
            RouteSource::Local,
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65000],
            }],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        ));

        let path_b = Arc::new(make_path(
            RouteSource::Local,
            vec![AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 1,
                asn_list: vec![65000],
            }],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 2)),
        ));

        let p1 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 1, 0),
            prefix_length: 24,
        });
        let p2 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 2, 0),
            prefix_length: 24,
        });
        let p3 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 3, 0),
            prefix_length: 24,
        });
        let announcements = vec![
            RoutePath {
                key: RouteKey::Prefix(p1),
                path: Arc::clone(&path_a),
            },
            RoutePath {
                key: RouteKey::Prefix(p2),
                path: Arc::clone(&path_b),
            },
            RoutePath {
                key: RouteKey::Prefix(p3),
                path: Arc::clone(&path_a),
            },
        ];

        let mut actual = batch_announcements(&announcements);
        actual.sort_by_key(|batch| batch.keys.len());

        assert_eq!(
            actual,
            vec![
                AnnouncementBatch {
                    afi_safi: AfiSafi::new(Afi::Ipv4, Safi::Unicast),
                    path: Arc::clone(&path_b),
                    keys: vec![RouteKey::Prefix(p2)],
                },
                AnnouncementBatch {
                    afi_safi: AfiSafi::new(Afi::Ipv4, Safi::Unicast),
                    path: Arc::clone(&path_a),
                    keys: vec![RouteKey::Prefix(p1), RouteKey::Prefix(p3)],
                },
            ]
        );
    }

    #[test]
    fn test_as_set_preservation_ebgp() {
        // Route with AS_SET should be preserved when exporting to eBGP
        let path_with_as_set = make_path(
            RouteSource::Ebgp {
                peer_ip: test_ip(1),
                bgp_id: test_bgp_id(1),
            },
            vec![
                AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                },
                AsPathSegment {
                    segment_type: AsPathSegmentType::AsSet,
                    segment_len: 3,
                    asn_list: vec![65003, 65004, 65005],
                },
            ],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        );

        // Export to eBGP peer should prepend local ASN and preserve AS_SET
        let ctx = make_peer_export_ctx(65000, 65100, false, false, false);
        let result = build_export_as_path(&path_with_as_set, &ctx);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[0].asn_list, vec![65000, 65001, 65002]);
        assert_eq!(result[1].segment_type, AsPathSegmentType::AsSet);
        assert_eq!(result[1].asn_list, vec![65003, 65004, 65005]);
    }

    #[test]
    fn test_as_set_first_segment_ebgp() {
        // Route starting with AS_SET should create new AS_SEQUENCE for local ASN
        let path_starting_with_as_set = make_path(
            RouteSource::Ebgp {
                peer_ip: test_ip(1),
                bgp_id: test_bgp_id(1),
            },
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
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        );

        // Export to eBGP should create new AS_SEQUENCE segment for local ASN
        let ctx = make_peer_export_ctx(65000, 65100, false, false, false);
        let result = build_export_as_path(&path_starting_with_as_set, &ctx);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[0].asn_list, vec![65000]);
        assert_eq!(result[1].segment_type, AsPathSegmentType::AsSet);
        assert_eq!(result[1].asn_list, vec![65001, 65002]);
        assert_eq!(result[2].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[2].asn_list, vec![65003]);
    }

    #[test]
    fn test_as_set_preservation_ibgp() {
        // Route with AS_SET should be preserved unchanged when exporting to iBGP
        let path_with_as_set = make_path(
            RouteSource::Ebgp {
                peer_ip: test_ip(1),
                bgp_id: test_bgp_id(1),
            },
            vec![
                AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 2,
                    asn_list: vec![65001, 65002],
                },
                AsPathSegment {
                    segment_type: AsPathSegmentType::AsSet,
                    segment_len: 3,
                    asn_list: vec![65003, 65004, 65005],
                },
            ],
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        );

        // Export to iBGP peer should preserve AS_PATH unchanged
        let ctx = make_peer_export_ctx(65000, 65000, false, false, false);
        let result = build_export_as_path(&path_with_as_set, &ctx);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].segment_type, AsPathSegmentType::AsSequence);
        assert_eq!(result[0].asn_list, vec![65001, 65002]);
        assert_eq!(result[1].segment_type, AsPathSegmentType::AsSet);
        assert_eq!(result[1].asn_list, vec![65003, 65004, 65005]);
    }

    #[test]
    fn test_build_export_next_hop() {
        let router_id = Ipv4Addr::new(1, 1, 1, 1);
        let prefix: IpNetwork = "10.0.0.0/24".parse().unwrap();
        let prefix = RouteKey::Prefix(prefix);

        struct TestCase {
            name: &'static str,
            path_next_hop: NextHopAddr,
            path_source: RouteSource,
            local_asn: u32,
            peer_asn: u32,
            rs_client: bool,
            next_hop_self: bool,
            expected: NextHopAddr,
        }

        let test_cases = vec![
            TestCase {
                name: "iBGP: local route with unspecified NH -> set to local",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::UNSPECIFIED),
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                next_hop_self: false,
                expected: NextHopAddr::Ipv4(router_id),
            },
            TestCase {
                name: "iBGP: local route with explicit NH -> preserve",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                next_hop_self: false,
                expected: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
            },
            TestCase {
                name: "iBGP: learned route -> preserve NH",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 2, 1)),
                path_source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                next_hop_self: false,
                expected: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 2, 1)),
            },
            TestCase {
                name: "eBGP: local route with unspecified NH -> set to local",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::UNSPECIFIED),
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                next_hop_self: false,
                expected: NextHopAddr::Ipv4(router_id),
            },
            TestCase {
                name: "eBGP: local route with explicit NH -> rewrite to local",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                next_hop_self: false,
                expected: NextHopAddr::Ipv4(router_id),
            },
            TestCase {
                name: "eBGP: learned route -> rewrite to local",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 3, 1)),
                path_source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                next_hop_self: false,
                expected: NextHopAddr::Ipv4(router_id),
            },
            TestCase {
                name: "RS client: preserve original NH",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 3, 1)),
                path_source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: true,
                next_hop_self: false,
                expected: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 3, 1)),
            },
            TestCase {
                name: "iBGP + next_hop_self: learned route -> rewrite to local",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 9, 1)),
                path_source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                next_hop_self: true,
                expected: NextHopAddr::Ipv4(router_id),
            },
            TestCase {
                name: "iBGP + next_hop_self: local route with unspecified NH -> set to local",
                path_next_hop: NextHopAddr::Ipv4(Ipv4Addr::UNSPECIFIED),
                path_source: RouteSource::Local,
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                next_hop_self: true,
                expected: NextHopAddr::Ipv4(router_id),
            },
        ];

        for test_case in test_cases {
            let path = make_path(test_case.path_source, vec![], test_case.path_next_hop);

            let ctx = make_peer_export_ctx(
                test_case.local_asn,
                test_case.peer_asn,
                test_case.rs_client,
                test_case.next_hop_self,
                false,
            );
            let result = build_export_next_hop(&path, &ctx, &prefix);

            assert_eq!(
                result,
                Some(test_case.expected),
                "Test case '{}' failed: expected {:?}, got {:?}",
                test_case.name,
                Some(test_case.expected),
                result
            );
        }
    }

    #[test]
    fn test_build_export_local_pref() {
        let path = Path {
            local_path_id: None,
            remote_path_id: None,
            stale: false,
            rpki_state: RpkiValidation::NotFound,
            attrs: Arc::new(PathAttrs {
                origin: Origin::IGP,
                as_path: vec![],
                next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                source: RouteSource::Local,
                local_pref: Some(200),
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
        };

        // iBGP: include LOCAL_PREF
        let ctx_ibgp = make_peer_export_ctx(65001, 65001, false, false, false);
        assert_eq!(build_export_local_pref(&path, &ctx_ibgp), Some(200));

        // eBGP: MUST NOT include LOCAL_PREF
        let ctx_ebgp = make_peer_export_ctx(65001, 65002, false, false, false);
        assert_eq!(build_export_local_pref(&path, &ctx_ebgp), None);
    }

    #[test]
    fn test_build_export_med() {
        struct TestCase {
            name: &'static str,
            as_path: Vec<AsPathSegment>,
            source: RouteSource,
            local_asn: u32,
            peer_asn: u32,
            rs_client: bool,
            expected_med: Option<u32>,
        }

        let test_cases = vec![
            // Local routes (empty AS_PATH)
            TestCase {
                name: "local route to iBGP",
                as_path: vec![],
                source: RouteSource::Local,
                local_asn: 65001,
                peer_asn: 65001,
                rs_client: false,
                expected_med: Some(50),
            },
            TestCase {
                name: "local route to eBGP",
                as_path: vec![],
                source: RouteSource::Local,
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: false,
                expected_med: Some(50),
            },
            TestCase {
                name: "local route to RS client",
                as_path: vec![],
                source: RouteSource::Local,
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: true,
                expected_med: Some(50),
            },
            // Local route with non-empty AS_PATH (defensive check for API misuse)
            TestCase {
                name: "local route with non-empty AS_PATH to eBGP",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65099], // Different from local_asn
                }],
                source: RouteSource::Local,
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: false,
                expected_med: Some(50), // Should send MED because source=Local
            },
            // Route from our AS
            TestCase {
                name: "route from our AS to iBGP",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65001,
                peer_asn: 65001,
                rs_client: false,
                expected_med: Some(50),
            },
            TestCase {
                name: "route from our AS to eBGP",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65001],
                }],
                source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: false,
                expected_med: Some(50),
            },
            // Route from external AS (the critical bug case)
            TestCase {
                name: "route from external AS to iBGP",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65000],
                }],
                source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65001,
                peer_asn: 65001,
                rs_client: false,
                expected_med: Some(50),
            },
            TestCase {
                name: "route from external AS to eBGP (must strip MED)",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65000],
                }],
                source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: false,
                expected_med: None,
            },
            // AS_SET handling (RFC 4271 9.2.2.2)
            TestCase {
                name: "AS_SET as first segment to eBGP (must strip MED)",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSet,
                    segment_len: 2,
                    asn_list: vec![65001, 65003],
                }],
                source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: false,
                expected_med: None,
            },
            TestCase {
                name: "AS_SET as first segment to iBGP",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSet,
                    segment_len: 2,
                    asn_list: vec![65001, 65003],
                }],
                source: RouteSource::Ibgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                    rr_client: false,
                },
                local_asn: 65001,
                peer_asn: 65001,
                rs_client: false,
                expected_med: Some(50),
            },
            // Route server transparency
            TestCase {
                name: "RS client always preserves MED",
                as_path: vec![AsPathSegment {
                    segment_type: AsPathSegmentType::AsSequence,
                    segment_len: 1,
                    asn_list: vec![65000],
                }],
                source: RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                local_asn: 65001,
                peer_asn: 65002,
                rs_client: true,
                expected_med: Some(50),
            },
        ];

        for test_case in test_cases {
            let path = Path {
                local_path_id: None,
                remote_path_id: None,
                stale: false,
                rpki_state: RpkiValidation::NotFound,
                attrs: Arc::new(PathAttrs {
                    origin: Origin::IGP,
                    as_path: test_case.as_path,
                    next_hop: NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
                    source: test_case.source,
                    local_pref: Some(100),
                    med: Some(50),
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
            };

            let ctx = make_peer_export_ctx(
                test_case.local_asn,
                test_case.peer_asn,
                test_case.rs_client,
                false,
                false,
            );
            let result = build_export_med(&path, &ctx);
            assert_eq!(
                result, test_case.expected_med,
                "Test case '{}' failed: expected {:?}, got {:?}",
                test_case.name, test_case.expected_med, result
            );
        }
    }

    #[test]
    fn test_send_announcements_oversized_message() {
        // RFC 4271 Section 9.2: Messages exceeding MAX_MESSAGE_SIZE must not be sent
        let (tx, mut rx) = mpsc::unbounded_channel();
        let peer_addr = test_ip(1);
        let policy =
            Arc::new(Policy::new("test".to_string()).with(Statement::new().then(Action::Accept)));

        // Create huge AS_PATH to make UPDATE message exceed 4096 bytes
        // Multiple AS_SEQUENCE segments with 255 ASNs each = ~4000 bytes total
        let mut as_path = vec![];
        for seg in 0..10 {
            let mut asn_list = vec![];
            for i in 0..255 {
                asn_list.push(65000 + ((seg * 255 + i) % 536));
            }
            as_path.push(AsPathSegment {
                segment_type: AsPathSegmentType::AsSequence,
                segment_len: 255,
                asn_list,
            });
        }

        let path = make_path(
            RouteSource::Ebgp {
                peer_ip: test_ip(2),
                bgp_id: test_bgp_id(2),
            },
            as_path,
            NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1)),
        );

        // Just one prefix, but huge AS_PATH should make UPDATE > 4096 bytes
        let prefix = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        });
        let routes = vec![RoutePath {
            key: RouteKey::Prefix(prefix),
            path: Arc::new(path),
        }];

        // Send announcements - should skip due to size
        let policies = vec![policy];
        let export_policies = test_export_policies(policies);
        let negotiated: HashSet<AfiSafi> = vec![
            AfiSafi::new(Afi::Ipv4, Safi::Unicast),
            AfiSafi::new(Afi::Ipv6, Safi::Unicast),
        ]
        .into_iter()
        .collect();
        let ctx = PeerExportContext {
            peer_addr,
            peer_tx: &tx,
            local_asn: 65000,
            peer_asn: 65001,
            local_next_hop: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            local_link_local: None,
            export_policies: &export_policies,
            rr_client: false,
            rs_client: false,
            cluster_id: Ipv4Addr::new(1, 1, 1, 1),
            send_format: MessageFormat {
                use_4byte_asn: false,
                add_path: AddPathMask::NONE,
                is_ebgp: false,
                enhanced_rr: false,
            },
            negotiated_afi_safis: &negotiated,
            next_hop_self: false,
            graceful_shutdown: false,
            capabilities: &PeerCapabilities::default(),
            send_rpki_community: false,
        };
        let filtered = compute_routes_for_peer(&routes, &ctx);
        send_batched_announcements(
            &ctx,
            &filtered,
            MessageFormat {
                use_4byte_asn: false,
                add_path: AddPathMask::NONE,
                is_ebgp: false,
                enhanced_rr: false,
            },
        );

        // Verify no message was sent
        assert!(
            rx.try_recv().is_err(),
            "Oversized UPDATE should not be sent"
        );
    }

    #[test]
    fn test_should_filter_by_community_no_advertise() {
        use crate::bgp::msg_update_types::NO_ADVERTISE;

        let communities = vec![NO_ADVERTISE, 65001];
        assert!(should_filter_by_community(&communities, 65000, 65001));
        assert!(should_filter_by_community(&communities, 65000, 65000));
    }

    #[test]
    fn test_should_filter_by_community_no_export_ebgp() {
        use crate::bgp::msg_update_types::NO_EXPORT;

        let communities = vec![NO_EXPORT, 65001];
        assert!(
            should_filter_by_community(&communities, 65000, 65001),
            "NO_EXPORT should filter for eBGP"
        );
        assert!(
            !should_filter_by_community(&communities, 65000, 65000),
            "NO_EXPORT should not filter for iBGP"
        );
    }

    #[test]
    fn test_should_filter_by_community_no_export_subconfed_ebgp() {
        use crate::bgp::msg_update_types::NO_EXPORT_SUBCONFED;

        let communities = vec![NO_EXPORT_SUBCONFED];
        assert!(
            should_filter_by_community(&communities, 65000, 65001),
            "NO_EXPORT_SUBCONFED should filter for eBGP"
        );
        assert!(
            !should_filter_by_community(&communities, 65000, 65000),
            "NO_EXPORT_SUBCONFED should not filter for iBGP"
        );
    }

    #[test]
    fn test_should_filter_by_community_regular() {
        let communities = vec![65001, 65002];
        assert!(
            !should_filter_by_community(&communities, 65000, 65001),
            "Regular communities should not filter"
        );
        assert!(
            !should_filter_by_community(&communities, 65000, 65000),
            "Regular communities should not filter"
        );
    }

    #[test]
    fn test_build_export_extended_communities() {
        let transitive = 0x0002FDE800000064u64; // Transitive extended community
        let non_transitive = 0x4002FDE800000064u64; // Non-transitive extended community
        let rpki_valid = from_rpki_state_community(RpkiValidation::VALID);
        let rpki_not_found = from_rpki_state_community(RpkiValidation::NOT_FOUND);

        struct TestCase {
            name: &'static str,
            local_asn: u32,
            peer_asn: u32,
            rs_client: bool,
            send_rpki_community: bool,
            rpki_state: RpkiValidation,
            input_communities: Vec<u64>,
            expected: Vec<u64>,
        }

        let test_cases = vec![
            TestCase {
                name: "eBGP filters non-transitive",
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                send_rpki_community: false,
                rpki_state: RpkiValidation::NotFound,
                input_communities: vec![transitive, non_transitive],
                expected: vec![transitive],
            },
            TestCase {
                name: "iBGP keeps all",
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                send_rpki_community: false,
                rpki_state: RpkiValidation::NotFound,
                input_communities: vec![transitive, non_transitive],
                expected: vec![transitive, non_transitive],
            },
            TestCase {
                name: "RS client preserves all (including non-transitive)",
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: true,
                send_rpki_community: false,
                rpki_state: RpkiValidation::NotFound,
                input_communities: vec![transitive, non_transitive],
                expected: vec![transitive, non_transitive],
            },
            TestCase {
                name: "iBGP send_rpki_community attaches RPKI state",
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                send_rpki_community: true,
                rpki_state: RpkiValidation::Valid,
                input_communities: vec![transitive],
                expected: vec![transitive, rpki_valid],
            },
            TestCase {
                name: "iBGP send_rpki_community replaces existing RPKI state",
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                send_rpki_community: true,
                rpki_state: RpkiValidation::NotFound,
                input_communities: vec![transitive, rpki_valid],
                expected: vec![transitive, rpki_not_found],
            },
            TestCase {
                name: "eBGP send_rpki_community does not attach (non-transitive)",
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                send_rpki_community: true,
                rpki_state: RpkiValidation::Valid,
                input_communities: vec![transitive],
                expected: vec![transitive],
            },
        ];

        for test_case in test_cases {
            let path = Path {
                local_path_id: None,
                remote_path_id: None,
                stale: false,
                rpki_state: test_case.rpki_state,
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
                    extended_communities: test_case.input_communities,
                    large_communities: vec![],
                    unknown_attrs: vec![],
                    originator_id: None,
                    cluster_list: vec![],
                    ls_attr: None,
                }),
            };

            let ctx = make_peer_export_ctx(
                test_case.local_asn,
                test_case.peer_asn,
                test_case.rs_client,
                false,
                test_case.send_rpki_community,
            );
            let result = build_export_extended_communities(&path, &ctx);
            assert_eq!(
                result, test_case.expected,
                "Test case '{}' failed: expected {:?}, got {:?}",
                test_case.name, test_case.expected, result
            );
        }
    }

    #[test]
    fn test_build_export_unknown_attrs() {
        let transitive_attr = PathAttribute::new(
            PathAttrFlag(attr_flags::OPTIONAL | attr_flags::TRANSITIVE),
            PathAttrValue::Unknown {
                type_code: 200,
                flags: attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
                data: vec![0xde, 0xad, 0xbe, 0xef],
            },
        );
        let non_transitive_attr = PathAttribute::new(
            PathAttrFlag(attr_flags::OPTIONAL),
            PathAttrValue::Unknown {
                type_code: 201,
                flags: attr_flags::OPTIONAL,
                data: vec![0xca, 0xfe],
            },
        );

        struct TestCase {
            name: &'static str,
            local_asn: u32,
            peer_asn: u32,
            rs_client: bool,
            expected_count: usize,
        }

        let test_cases = vec![
            TestCase {
                name: "eBGP filters non-transitive unknown attrs",
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: false,
                expected_count: 1, // transitive only
            },
            TestCase {
                name: "iBGP passes all unknown attrs",
                local_asn: 65000,
                peer_asn: 65000,
                rs_client: false,
                expected_count: 2,
            },
            TestCase {
                name: "RS client preserves all unknown attrs (RFC 7947 Section 2.2)",
                local_asn: 65000,
                peer_asn: 65001,
                rs_client: true,
                expected_count: 2,
            },
        ];

        for test_case in test_cases {
            let mut path = make_path(
                RouteSource::Ebgp {
                    peer_ip: test_ip(1),
                    bgp_id: test_bgp_id(1),
                },
                vec![],
                NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            );
            path.attrs_mut().unknown_attrs =
                vec![transitive_attr.clone(), non_transitive_attr.clone()];

            let ctx = make_peer_export_ctx(
                test_case.local_asn,
                test_case.peer_asn,
                test_case.rs_client,
                false,
                false,
            );
            let result = build_export_unknown_attrs(&path, &ctx);
            assert_eq!(
                result.len(),
                test_case.expected_count,
                "Test case '{}' failed: expected {} attrs, got {}",
                test_case.name,
                test_case.expected_count,
                result.len()
            );
        }
    }

    #[test]
    fn test_apply_rr_attributes() {
        let cluster_id = Ipv4Addr::new(1, 1, 1, 1);
        let peer_bgp_id = Ipv4Addr::new(2, 2, 2, 2);

        // Sets ORIGINATOR_ID from source when not present
        let mut path = make_path(
            RouteSource::Ibgp {
                peer_ip: test_ip(1),
                bgp_id: peer_bgp_id,
                rr_client: false,
            },
            vec![],
            NextHopAddr::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        );
        let negotiated: HashSet<AfiSafi> = vec![
            AfiSafi::new(Afi::Ipv4, Safi::Unicast),
            AfiSafi::new(Afi::Ipv6, Safi::Unicast),
        ]
        .into_iter()
        .collect();
        let empty_policies = AfiSafiPolicies::new();
        let ctx = PeerExportContext {
            peer_addr: test_ip(2),
            peer_tx: &tokio::sync::mpsc::unbounded_channel().0,
            local_asn: 65000,
            peer_asn: 65000,
            local_next_hop: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            local_link_local: None,
            export_policies: &empty_policies,
            rr_client: false,
            rs_client: false,
            cluster_id,
            send_format: MessageFormat {
                use_4byte_asn: false,
                add_path: AddPathMask::NONE,
                is_ebgp: false,
                enhanced_rr: false,
            },
            negotiated_afi_safis: &negotiated,
            next_hop_self: false,
            graceful_shutdown: false,
            capabilities: &PeerCapabilities::default(),
            send_rpki_community: false,
        };
        let (originator_id, cluster_list) = build_export_rr_attrs(&path, &ctx, true);
        assert_eq!(originator_id, Some(peer_bgp_id));
        assert_eq!(cluster_list, vec![cluster_id]);

        // Preserves existing ORIGINATOR_ID, prepends to CLUSTER_LIST
        let existing_originator = Ipv4Addr::new(3, 3, 3, 3);
        let existing_cluster = Ipv4Addr::new(4, 4, 4, 4);
        let attrs = path.attrs_mut();
        attrs.originator_id = Some(existing_originator);
        attrs.cluster_list = vec![existing_cluster];
        let (originator_id, cluster_list) = build_export_rr_attrs(&path, &ctx, true);
        assert_eq!(originator_id, Some(existing_originator));
        assert_eq!(cluster_list, vec![cluster_id, existing_cluster]);
    }

    #[test]
    fn test_select_paths_rs_route_iteration() {
        let prefix = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 24,
        });
        let nh1 = NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 1));
        let nh2 = NextHopAddr::Ipv4(Ipv4Addr::new(192, 168, 1, 2));

        // path1 (best, bgp_id 1.1.1.1): rejected by policy (sourced from test_ip(2))
        // path2 (second-best, bgp_id 1.1.1.2): accepted
        let path1 = make_path(
            RouteSource::Ebgp {
                peer_ip: test_ip(2),
                bgp_id: test_bgp_id(1),
            },
            vec![as_seq(vec![65001])],
            nh1,
        );

        let path2 = make_path(
            RouteSource::Ebgp {
                peer_ip: test_ip(3),
                bgp_id: test_bgp_id(2),
            },
            vec![as_seq(vec![65002])],
            nh2,
        );

        let mut loc_rib = LocRib::default();
        loc_rib.apply_peer_update(
            test_ip(2),
            &[PendingRoute::Announce(RoutePath::new(
                RouteKey::Prefix(prefix),
                path1,
            ))],
            |_, _| true,
        );
        loc_rib.apply_peer_update(
            test_ip(3),
            &[PendingRoute::Announce(RoutePath::new(
                RouteKey::Prefix(prefix),
                path2,
            ))],
            |_, _| true,
        );
        assert_eq!(loc_rib.get_all_paths(&RouteKey::Prefix(prefix)).len(), 2);

        let policies = vec![Arc::new(
            Policy::new("test".to_string())
                .with(
                    Statement::new()
                        .when(Condition::Neighbor(test_ip(2)))
                        .then(Action::Reject),
                )
                .with(Statement::new().then(Action::Accept)),
        )];
        let export_policies = test_export_policies(policies);
        let rs_ctx = PeerExportContext {
            export_policies: &export_policies,
            ..make_peer_export_ctx(65000, 65003, true, false, false)
        };
        let non_rs_ctx = PeerExportContext {
            export_policies: &export_policies,
            ..make_peer_export_ctx(65000, 65003, false, false, false)
        };

        // RS client iterates to path2 (passes policy)
        let route_key = RouteKey::Prefix(prefix);
        let result = select_paths_for_export(&route_key, false, &loc_rib, &rs_ctx);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path.attrs.next_hop, nh2);

        // Non-RS client only checks best path (path1) -> rejected
        let result = select_paths_for_export(&route_key, false, &loc_rib, &non_rs_ctx);
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_export_communities() {
        let make_path = |communities: Vec<u32>| Path {
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
                communities,
                extended_communities: vec![],
                large_communities: vec![],
                unknown_attrs: vec![],
                originator_id: None,
                cluster_list: vec![],
                ls_attr: None,
            }),
        };

        struct TestCase {
            name: &'static str,
            graceful_shutdown: bool,
            input_communities: Vec<u32>,
            expected: Vec<u32>,
        }

        let other_community = 0x00010064u32; // 1:100
        let gshut = community::GRACEFUL_SHUTDOWN;

        let test_cases = vec![
            TestCase {
                name: "flag off, empty",
                graceful_shutdown: false,
                input_communities: vec![],
                expected: vec![],
            },
            TestCase {
                name: "flag on, empty: GRACEFUL_SHUTDOWN added",
                graceful_shutdown: true,
                input_communities: vec![],
                expected: vec![gshut],
            },
            TestCase {
                name: "flag on, already present: no duplicate",
                graceful_shutdown: true,
                input_communities: vec![gshut],
                expected: vec![gshut],
            },
            TestCase {
                name: "flag off, other community preserved unchanged",
                graceful_shutdown: false,
                input_communities: vec![other_community],
                expected: vec![other_community],
            },
            TestCase {
                name: "flag on, other community: GRACEFUL_SHUTDOWN appended",
                graceful_shutdown: true,
                input_communities: vec![other_community],
                expected: vec![other_community, gshut],
            },
        ];

        for test_case in test_cases {
            let path = make_path(test_case.input_communities);
            let mut ctx = make_peer_export_ctx(65001, 65002, false, false, false);
            ctx.graceful_shutdown = test_case.graceful_shutdown;
            let result = build_export_communities(&path, &ctx);
            assert_eq!(
                result, test_case.expected,
                "Test case '{}' failed",
                test_case.name
            );
        }
    }

    #[test]
    fn test_is_ebgp_is_ibgp() {
        let ebgp_ctx = make_peer_export_ctx(65001, 65002, false, false, false);
        assert!(ebgp_ctx.is_ebgp());
        assert!(!ebgp_ctx.is_ibgp());

        let ibgp_ctx = make_peer_export_ctx(65001, 65001, false, false, false);
        assert!(!ibgp_ctx.is_ebgp());
        assert!(ibgp_ctx.is_ibgp());
    }
}
