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

use super::{AdminState, BgpServer, BmpOp, BmpPeerStats, ConnectionType, PeerInfo};
use crate::bgp::community;
use crate::bgp::ext_community::is_rpki_state_community;
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::msg_open_types::StaleFilter;
use crate::bgp::msg_route_refresh::RouteRefreshSubtype;
use crate::bgp::msg_update::NextHopAddr;
use crate::bgp::msg_update_types::AS_TRANS;
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::log::{debug, info, warn};
use crate::net::{get_interface_link_local, IpNetwork};
use crate::peer::{BgpState, PeerCapabilities, PeerOp, PendingRoute};
use crate::policy::{AfiSafiPolicies, PolicyResult};
use crate::rib::rib_loc::RouteDelta;
use crate::rib::{Path, RouteKey, RoutePath};
use crate::rpki::vrp::{Vrp, VrpTable};
use crate::types::PeerDownReason;
use conf::bgp::{AddPathSend, MaxPrefixAction, MaxPrefixSetting, PeerConfig};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::oneshot;

// Server operations sent from peer tasks to the main server loop
pub enum ServerOp {
    PeerStateChanged {
        peer_ip: IpAddr,
        state: BgpState,
        conn_type: ConnectionType,
    },
    PeerHandshakeComplete {
        peer_ip: IpAddr,
        asn: u32,
        conn_type: ConnectionType,
    },
    /// Sent when peer receives OPEN message, for collision detection (RFC 4271 Section 6.8)
    OpenReceived {
        peer_ip: IpAddr,
        bgp_id: u32,
        conn_type: ConnectionType,
    },
    /// Connection info sent when peer establishes
    PeerConnectionInfo {
        peer_ip: IpAddr,
        local_address: IpAddr,
        local_port: u16,
        remote_port: u16,
        sent_open: OpenMessage,
        received_open: OpenMessage,
        negotiated_capabilities: PeerCapabilities,
        conn_type: ConnectionType,
    },
    PeerUpdate {
        peer_ip: IpAddr,
        routes: Vec<PendingRoute>,
    },
    PeerDisconnected {
        peer_ip: IpAddr,
        reason: PeerDownReason,
        gr_afi_safis: Vec<AfiSafi>,
        conn_type: ConnectionType,
    },
    /// Set peer's admin state (e.g., when max prefix limit exceeded)
    SetAdminState { peer_ip: IpAddr, state: AdminState },
    /// Route Refresh request from peer
    RouteRefresh {
        peer_ip: IpAddr,
        afi: Afi,
        safi: Safi,
    },
    /// RFC 7313: Beginning of Route Refresh from peer
    RouteRefreshBoRR {
        peer_ip: IpAddr,
        afi: Afi,
        safi: Safi,
    },
    /// RFC 7313: End of Route Refresh from peer
    RouteRefreshEoRR {
        peer_ip: IpAddr,
        afi: Afi,
        safi: Safi,
    },
    /// Graceful Restart timer expired for a peer (RFC 4724)
    GracefulRestartTimerExpired {
        peer_ip: IpAddr,
        /// RFC 9494: LLGR-capable AFI/SAFIs and their stale times from peer capability
        llgr_afi_safis: Vec<(AfiSafi, u32)>,
    },
    /// RFC 9494: Long-Lived Graceful Restart stale timer expired for a peer's AFI/SAFI
    LlgrTimerExpired { peer_ip: IpAddr, afi_safi: AfiSafi },
    /// RFC 7313: Enhanced route refresh stale TTL expired for a peer's AFI/SAFI
    EnhancedRrStaleTimerExpired { peer_ip: IpAddr, afi_safi: AfiSafi },
    /// Graceful Restart completed for a peer (all EORs received)
    GracefulRestartComplete { peer_ip: IpAddr, afi_safi: AfiSafi },
    /// Server signals peer that loc-rib has been sent
    LocalRibSent { peer_ip: IpAddr, afi_safi: AfiSafi },
    /// Query BMP statistics for all established peers
    GetBmpStatistics {
        response: oneshot::Sender<Vec<BmpPeerStats>>,
    },
    /// VRP table update from RtrManager (RPKI).
    VrpUpdate { added: Vec<Vrp>, removed: Vec<Vrp> },
}

impl BgpServer {
    pub(crate) async fn handle_server_op(&mut self, op: ServerOp) {
        match op {
            ServerOp::PeerStateChanged {
                peer_ip,
                state,
                conn_type,
            } => {
                self.handle_peer_state_changed(peer_ip, state, conn_type)
                    .await;
            }
            ServerOp::PeerHandshakeComplete {
                peer_ip,
                asn,
                conn_type,
            } => {
                self.handle_peer_handshake_complete(peer_ip, asn, conn_type);
            }
            ServerOp::PeerUpdate { peer_ip, routes } => {
                self.handle_peer_update(peer_ip, routes).await;
            }
            ServerOp::OpenReceived {
                peer_ip,
                bgp_id,
                conn_type,
            } => {
                self.handle_open_received(peer_ip, bgp_id, conn_type).await;
            }
            ServerOp::PeerConnectionInfo {
                peer_ip,
                local_address,
                local_port,
                remote_port,
                sent_open,
                received_open,
                negotiated_capabilities,
                conn_type,
            } => {
                self.handle_peer_connection_info(
                    peer_ip,
                    local_address,
                    local_port,
                    remote_port,
                    sent_open,
                    received_open,
                    negotiated_capabilities,
                    conn_type,
                );
            }
            ServerOp::PeerDisconnected {
                peer_ip,
                reason,
                gr_afi_safis,
                conn_type,
            } => {
                self.handle_peer_disconnected(peer_ip, reason, gr_afi_safis, conn_type)
                    .await;
            }
            ServerOp::SetAdminState { peer_ip, state } => {
                if let Some(peer) = self.peers.get_mut(&peer_ip) {
                    peer.admin_state = state;
                }
            }
            ServerOp::RouteRefresh { peer_ip, afi, safi } => {
                self.handle_route_refresh(peer_ip, afi, safi).await;
            }
            ServerOp::RouteRefreshBoRR { peer_ip, afi, safi } => {
                self.handle_route_refresh_borr(peer_ip, afi, safi).await;
            }
            ServerOp::RouteRefreshEoRR { peer_ip, afi, safi } => {
                self.handle_route_refresh_eorr(peer_ip, afi, safi).await;
            }
            ServerOp::GracefulRestartTimerExpired {
                peer_ip,
                llgr_afi_safis,
            } => {
                self.handle_gr_timer_expired(peer_ip, llgr_afi_safis).await;
            }
            ServerOp::GracefulRestartComplete { peer_ip, afi_safi } => {
                info!(%peer_ip, %afi_safi, "Graceful Restart completed for AFI/SAFI");
                self.clear_stale_afi_safi(peer_ip, afi_safi).await;
            }
            ServerOp::LlgrTimerExpired { peer_ip, afi_safi } => {
                info!(%peer_ip, %afi_safi, "LLGR stale timer expired");
                self.clear_stale_afi_safi(peer_ip, afi_safi).await;
            }
            ServerOp::EnhancedRrStaleTimerExpired { peer_ip, afi_safi } => {
                self.handle_enhanced_rr_stale_expired(peer_ip, afi_safi)
                    .await;
            }
            ServerOp::LocalRibSent { peer_ip, afi_safi } => {
                if let Some(peer) = self.peers.get(&peer_ip) {
                    if let Some(conn) = peer.established_conn() {
                        if let Some(peer_tx) = &conn.peer_tx {
                            let _ = peer_tx.send(PeerOp::LocalRibSent { afi_safi });
                        }
                    }
                }
            }
            ServerOp::GetBmpStatistics { response } => {
                self.handle_get_bmp_statistics(response);
            }
            ServerOp::VrpUpdate { added, removed } => {
                self.handle_vrp_update(added, removed).await;
            }
        }
    }

    async fn handle_peer_state_changed(
        &mut self,
        peer_ip: IpAddr,
        state: BgpState,
        conn_type: ConnectionType,
    ) {
        let Some(peer) = self.peers.get_mut(&peer_ip) else {
            return;
        };

        // Route to correct slot by conn_type
        let slot = peer.slot_mut(conn_type);
        let Some(conn) = slot.as_mut() else {
            return;
        };

        conn.state = state;
        info!(%peer_ip, ?state, ?conn_type, "peer state changed");

        // When peer becomes Established, send BMP PeerUp and propagate all routes
        if state == BgpState::Established {
            self.handle_peer_established(peer_ip).await;
        }
    }

    fn handle_peer_handshake_complete(
        &mut self,
        peer_ip: IpAddr,
        asn: u32,
        conn_type: ConnectionType,
    ) {
        let is_ebgp = asn != self.config.asn;
        let Some(peer_config) = self.config.find_peer(peer_ip).cloned() else {
            return;
        };

        let (import_policies, export_policies) = self.build_peer_policies(&peer_config, is_ebgp);

        if let Some(peer) = self.peers.get_mut(&peer_ip) {
            if let Some(conn) = peer.slot_mut(conn_type).as_mut() {
                conn.asn = Some(asn);
            }
            peer.import_policies = import_policies;
            peer.export_policies = export_policies;
            info!(%peer_ip, asn, ?conn_type, "peer handshake complete");
        }
    }

    /// Resolve (import, export) policy maps for every configured family.
    /// Falls back to IPv4 Unicast if no families are configured (RFC 4760).
    fn build_peer_policies(
        &self,
        peer_config: &PeerConfig,
        is_ebgp: bool,
    ) -> (AfiSafiPolicies, AfiSafiPolicies) {
        let mut by_family: HashMap<AfiSafi, (&[String], &[String])> = peer_config
            .afi_safis
            .iter()
            .map(|c| {
                (
                    AfiSafi::new(c.afi, c.safi),
                    (c.import_policy.as_slice(), c.export_policy.as_slice()),
                )
            })
            .collect();
        if by_family.is_empty() {
            by_family.insert(AfiSafi::new(Afi::Ipv4, Safi::Unicast), (&[], &[]));
        }

        let mut import_policies = AfiSafiPolicies::new();
        let mut export_policies = AfiSafiPolicies::new();
        for (family, (imports, exports)) in by_family {
            import_policies.insert(family, self.resolve_policies(imports, is_ebgp));
            export_policies.insert(family, self.resolve_policies(exports, is_ebgp));
        }
        (import_policies, export_policies)
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_peer_connection_info(
        &mut self,
        peer_ip: IpAddr,
        local_address: IpAddr,
        local_port: u16,
        remote_port: u16,
        sent_open: OpenMessage,
        received_open: OpenMessage,
        negotiated_capabilities: PeerCapabilities,
        conn_type: ConnectionType,
    ) {
        let local_link_local = self
            .config
            .find_peer(peer_ip)
            .and_then(|cfg| cfg.interface.as_ref())
            .and_then(|iface| get_interface_link_local(iface).ok());

        if let Some(peer) = self.peers.get_mut(&peer_ip) {
            if let Some(conn) = peer.slot_mut(conn_type).as_mut() {
                conn.conn_info = Some(super::ConnectionInfo {
                    sent_open,
                    received_open,
                    local_address,
                    local_port,
                    remote_port,
                    local_link_local,
                });
                conn.capabilities = Some(negotiated_capabilities);
            }
        }
    }

    /// Handle OPEN message received - store BGP ID and check collision (RFC 4271 6.8)
    async fn handle_open_received(
        &mut self,
        peer_ip: IpAddr,
        bgp_id: u32,
        conn_type: ConnectionType,
    ) {
        // Update BGP ID for correct slot
        if let Some(peer) = self.peers.get_mut(&peer_ip) {
            if let Some(conn) = peer.slot_mut(conn_type).as_mut() {
                conn.bgp_id = Some(bgp_id);
                info!(%peer_ip, ?conn_type, bgp_id, "stored BGP ID in slot");
            } else {
                crate::log::error!(%peer_ip, ?conn_type, "OpenReceived but slot is None!");
            }
        } else {
            crate::log::error!(%peer_ip, "OpenReceived but peer not found!");
        }

        // Check for collision
        self.check_collision(peer_ip).await;
    }

    /// Check and resolve connection collision per RFC 4271 6.8.
    /// With slot-based design: outgoing and incoming are fixed slots.
    async fn check_collision(&mut self, peer_ip: IpAddr) {
        let Some(peer) = self.peers.get_mut(&peer_ip) else {
            return;
        };

        // Need both slots occupied for collision
        let (out, inc) = match (&peer.outgoing, &peer.incoming) {
            (Some(out), Some(inc)) => (out, inc),
            _ => return,
        };

        // Both must have BGP IDs (both received OPEN)
        let Some(out_bgp_id) = out.bgp_id else {
            return;
        };
        let Some(inc_bgp_id) = inc.bgp_id else {
            return;
        };

        // RFC 4271 6.8: Connection initiated by higher BGP ID wins
        // - Outgoing = we initiated -> wins if local > remote
        // - Incoming = remote initiated -> wins if remote > local
        // Note: inc_bgp_id and out_bgp_id are both the REMOTE's ID (from their OPEN)
        let local_bgp_id = u32::from(self.config.router_id);

        // Remote initiated (incoming) wins if remote BGP ID > local BGP ID
        let incoming_wins = inc_bgp_id > local_bgp_id;

        info!(%peer_ip, local_bgp_id, out_bgp_id, inc_bgp_id, incoming_wins, "resolving collision");

        if incoming_wins {
            // Close outgoing, keep incoming
            if let Some(tx) = &out.peer_tx {
                let _ = tx.send(PeerOp::CollisionLost);
            }
            peer.outgoing = None;
            info!(%peer_ip, "collision: outgoing closed, incoming wins");

            // If incoming was already Established, handle it now
            if peer.incoming.as_ref().map(|c| c.state) == Some(BgpState::Established) {
                self.handle_peer_established(peer_ip).await;
            }
        } else {
            // Close incoming, keep outgoing
            if let Some(tx) = &inc.peer_tx {
                let _ = tx.send(PeerOp::CollisionLost);
            }
            peer.incoming = None;
            info!(%peer_ip, "collision: incoming closed, outgoing wins");

            // If outgoing was already Established, handle it now
            if peer.outgoing.as_ref().map(|c| c.state) == Some(BgpState::Established) {
                self.handle_peer_established(peer_ip).await;
            }
        }
    }

    async fn handle_peer_disconnected(
        &mut self,
        peer_ip: IpAddr,
        reason: PeerDownReason,
        gr_afi_safis: Vec<AfiSafi>,
        conn_type: ConnectionType,
    ) {
        let Some(peer) = self.peers.get_mut(&peer_ip) else {
            return;
        };

        // Check if the disconnect is from the correct slot
        let slot_exists = peer.slot(conn_type).is_some();
        if !slot_exists {
            // Stale disconnect from old connection
            debug!(%peer_ip, ?conn_type, "ignoring stale disconnect");
            return;
        }

        // Extract info before modifying slot
        let was_established = peer
            .slot(conn_type)
            .map(|c| c.state == BgpState::Established)
            .unwrap_or(false);

        let bmp_peer_info = peer.slot(conn_type).and_then(|c| match (c.asn, c.bgp_id) {
            (Some(asn), Some(bgp_id)) => Some((asn, bgp_id, peer.supports_4byte_asn())),
            _ => None,
        });

        // Check if there's another connection in the other slot
        let other_slot_active = match conn_type {
            ConnectionType::Outgoing => peer.incoming.is_some(),
            ConnectionType::Incoming => peer.outgoing.is_some(),
        };

        if other_slot_active {
            // Other connection exists - just clear this slot
            *peer.slot_mut(conn_type) = None;
            debug!(%peer_ip, ?conn_type, "connection slot cleared, other connection active");
            return;
        }

        // Keep the slot but reset to Idle state (preserve peer_tx for reconnect)
        if let Some(conn) = peer.slot_mut(conn_type).as_mut() {
            conn.state = BgpState::Idle;
            conn.conn_info = None;
            conn.asn = None;
            conn.bgp_id = None;
        }
        peer.adj_rib_out.clear();
        peer.rr_stale_timers.cancel_all();
        // For non-GR disconnect, clear adj-rib-in and disabled AFI/SAFIs;
        // GR keeps adj-rib-in (routes are stale but retained)
        if gr_afi_safis.is_empty() {
            peer.adj_rib_in.clear();
            peer.disabled_afi_safi.clear();
        }
        info!(%peer_ip, "peer session ended");

        // RFC 4724: Handle routes based on Graceful Restart state
        if !gr_afi_safis.is_empty() {
            info!(%peer_ip, ?gr_afi_safis,
                  "peer disconnected with Graceful Restart - marking routes as stale (Receiving Speaker mode)");

            // Mark routes stale for each GR-enabled AFI/SAFI
            for afi_safi in gr_afi_safis {
                let count = self.loc_rib.mark_peer_routes_stale(peer_ip, afi_safi);
                debug!(%peer_ip, %afi_safi, count, "marked routes as stale");
            }
            // No withdrawals are propagated (RFC 4724 Section 4.1)
        } else if was_established {
            // Only propagate withdrawals if the disconnected connection was Established
            let delta = self.loc_rib.remove_routes_from_peer(peer_ip);
            self.propagate_routes(delta, Some(peer_ip)).await;
        }

        // BMP: Peer Down notification (only if session reached ESTABLISHED)
        if let Some((peer_as, peer_bgp_id, use_4byte_asn)) = bmp_peer_info {
            self.broadcast_bmp(BmpOp::PeerDown {
                peer_ip,
                peer_as,
                peer_bgp_id,
                reason,
                use_4byte_asn,
            });
        }
    }

    /// Handle peer reaching Established state - BMP PeerUp, route propagation, GR stale handling
    async fn handle_peer_established(&mut self, peer_ip: IpAddr) {
        let Some(peer) = self.peers.get(&peer_ip) else {
            return;
        };

        // Get the established connection
        let Some(conn) = peer.established_conn() else {
            return;
        };

        // Send BMP PeerUp
        if let (Some(asn), Some(bgp_id), Some(conn_info)) = (conn.asn, conn.bgp_id, &conn.conn_info)
        {
            let use_4byte_asn = peer.supports_4byte_asn();
            self.broadcast_bmp(BmpOp::PeerUp {
                peer_ip,
                peer_as: asn,
                peer_bgp_id: bgp_id,
                local_address: conn_info.local_address,
                local_port: conn_info.local_port,
                remote_port: conn_info.remote_port,
                sent_open: conn_info.sent_open.clone(),
                received_open: conn_info.received_open.clone(),
                use_4byte_asn,
            });
        }

        // Extract capabilities and peer_tx before propagate_routes.
        // Capabilities are always present for an established connection.
        let Some(capabilities) = conn.capabilities.clone() else {
            return;
        };
        let peer_tx = conn.peer_tx.clone();

        // RFC 7947: Warn if route-server client doesn't have ADD-PATH enabled
        if let Some(cfg) = self.config.find_peer(peer_ip) {
            if cfg.rs_client && matches!(cfg.add_path_send, AddPathSend::Disabled) {
                warn!(
                    %peer_ip,
                    "Route server could hide paths without add-path. Enable add-path send."
                );
            }
        }

        self.sweep_stale(peer_ip, &capabilities).await;

        // Send full loc-rib to the newly established peer
        let negotiated_afi_safis = capabilities.afi_safis();
        for afi_safi in &negotiated_afi_safis {
            self.resend_routes_to_peer(peer_ip, afi_safi.afi, afi_safi.safi);
        }

        // Signal that loc-rib has been sent for all negotiated AFI/SAFIs
        if let Some(peer_tx) = peer_tx {
            for afi_safi in &negotiated_afi_safis {
                let _ = peer_tx.send(PeerOp::LocalRibSent {
                    afi_safi: *afi_safi,
                });
            }
        }
    }

    /// GR timer expired: sweep non-LLGR stale routes, transition LLGR-capable ones.
    async fn handle_gr_timer_expired(
        &mut self,
        peer_ip: IpAddr,
        llgr_afi_safis: Vec<(AfiSafi, u32)>,
    ) {
        info!(%peer_ip, "Graceful Restart timer expired");

        let stale_afi_safis = self.loc_rib.stale_afi_safis(peer_ip);

        // RFC 9494 Section 4.2: LLST=0 means no LLGR phase for that AFI/SAFI.
        let llgr_map: HashMap<AfiSafi, u32> = llgr_afi_safis
            .into_iter()
            .filter(|(afi_safi, llst)| {
                if *llst == 0 {
                    info!(
                        "Peer {}: LLGR disabled for {:?} (LLST=0)",
                        peer_ip, afi_safi
                    );
                    return false;
                }
                true
            })
            .collect();

        let (llgr, gr): (Vec<_>, Vec<_>) = stale_afi_safis
            .iter()
            .partition(|afi_safi| llgr_map.contains_key(afi_safi));

        // GR-only: sweep stale routes immediately. LLGR: transition and schedule expiry.
        let mut delta = self.loc_rib.remove_peer_routes_stale(peer_ip, &gr);
        delta.extend(self.loc_rib.apply_llgr(peer_ip, &llgr));

        if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
            for (afi_safi, llst) in llgr_map {
                peer_info.llgr_timers.run(
                    afi_safi,
                    llst as u64,
                    ServerOp::LlgrTimerExpired { peer_ip, afi_safi },
                    self.op_tx.clone(),
                );
            }
        }
        self.propagate_routes(delta, Some(peer_ip)).await;
    }

    /// Cancel LLGR timer (if any) and sweep remaining stale routes for this AFI/SAFI.
    async fn clear_stale_afi_safi(&mut self, peer_ip: IpAddr, afi_safi: AfiSafi) {
        if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
            peer_info.llgr_timers.cancel(&afi_safi);
        }

        let delta = self.loc_rib.remove_peer_routes_stale(peer_ip, &[afi_safi]);
        self.propagate_routes(delta, Some(peer_ip)).await;
    }

    /// Sweep stale routes on reconnect (GR + LLGR) and propagate.
    async fn sweep_stale(&mut self, peer_ip: IpAddr, capabilities: &PeerCapabilities) {
        let mut delta = self.sweep_gr_stale(peer_ip, capabilities);
        delta.extend(self.sweep_llgr_stale(peer_ip, capabilities));
        self.propagate_routes(delta, Some(peer_ip)).await;
    }

    /// RFC 4724 Section 4.2: Sweep stale routes where F-bit=0,
    /// AFI/SAFI is absent from GR cap, or no GR cap at all.
    fn sweep_gr_stale(&mut self, peer_ip: IpAddr, capabilities: &PeerCapabilities) -> RouteDelta {
        let stale = self.loc_rib.stale_afi_safis(peer_ip);
        let to_clear: Vec<AfiSafi> = match &capabilities.graceful_restart {
            Some(cap) => cap.filter_stale(stale),
            None => stale.into_iter().collect(),
        };
        self.loc_rib.remove_peer_routes_stale(peer_ip, &to_clear)
    }

    /// RFC 9494 Section 4.2: Abort LLGR timers and sweep stale routes where
    /// F-bit=0, AFI/SAFI is absent from LLGR cap, or no LLGR cap at all.
    fn sweep_llgr_stale(&mut self, peer_ip: IpAddr, capabilities: &PeerCapabilities) -> RouteDelta {
        let Some(peer_info) = self.peers.get_mut(&peer_ip) else {
            return RouteDelta::new();
        };
        let stale: HashSet<AfiSafi> = peer_info.llgr_timers.keys().into_iter().collect();
        let to_clear: Vec<AfiSafi> = match &capabilities.llgr {
            Some(cap) => cap.filter_stale(stale),
            None => stale.into_iter().collect(),
        };
        for afi_safi in &to_clear {
            peer_info.llgr_timers.cancel(afi_safi);
        }
        self.loc_rib.remove_peer_routes_stale(peer_ip, &to_clear)
    }

    /// Server-initiated session teardown for max-prefix exceeded.
    /// Server owns all state; peer just sends the NOTIFICATION and closes TCP.
    async fn handle_max_prefix_terminate(&mut self, peer_ip: IpAddr) {
        let Some(peer) = self.peers.get_mut(&peer_ip) else {
            return;
        };

        // Extract peer_tx and BMP info before mutating
        let peer_tx = peer.established_conn().and_then(|c| c.peer_tx.clone());
        let bmp_info = peer
            .established_conn()
            .and_then(|c| match (c.asn, c.bgp_id) {
                (Some(asn), Some(bgp_id)) => Some((asn, bgp_id, peer.supports_4byte_asn())),
                _ => None,
            });

        // Server handles all state cleanup
        peer.admin_state = AdminState::PrefixLimitReached;
        peer.adj_rib_in.clear();
        peer.disabled_afi_safi.clear();
        peer.adj_rib_out.clear();

        // Reset established connection slot to Idle
        if let Some(conn) = peer.established_conn_mut() {
            conn.state = BgpState::Idle;
            conn.conn_info = None;
            conn.asn = None;
            conn.bgp_id = None;
        }

        // Tell peer to send NOTIFICATION and close TCP
        if let Some(tx) = peer_tx {
            let _ = tx.send(PeerOp::Shutdown(CeaseSubcode::MaxPrefixesReached));
        }

        // Remove routes from loc-rib and propagate withdrawals
        let delta = self.loc_rib.remove_routes_from_peer(peer_ip);
        self.propagate_routes(delta, Some(peer_ip)).await;

        // BMP PeerDown
        if let Some((peer_as, peer_bgp_id, use_4byte_asn)) = bmp_info {
            self.broadcast_bmp(BmpOp::PeerDown {
                peer_ip,
                peer_as,
                peer_bgp_id,
                reason: PeerDownReason::LocalNotification(NotificationMessage::new(
                    BgpError::Cease(CeaseSubcode::MaxPrefixesReached),
                    vec![],
                )),
                use_4byte_asn,
            });
        }

        info!(%peer_ip, "max prefix terminate: session torn down");
    }

    async fn handle_route_refresh(&mut self, peer_ip: IpAddr, afi: Afi, safi: Safi) {
        info!(%peer_ip, ?afi, ?safi, "processing ROUTE_REFRESH");

        let enhanced = self
            .peers
            .get(&peer_ip)
            .and_then(|p| p.established_conn())
            .is_some_and(|c| c.has_enhanced_route_refresh());

        if enhanced {
            self.send_enhanced_route_refresh(peer_ip, afi, safi);
        } else {
            self.resend_routes_to_peer(peer_ip, afi, safi);
        }
    }

    /// RFC 7313: Wrap route resend with BoRR/EoRR demarcation.
    fn send_enhanced_route_refresh(&mut self, peer_ip: IpAddr, afi: Afi, safi: Safi) {
        let peer_tx = self
            .peers
            .get(&peer_ip)
            .and_then(|p| p.established_conn())
            .and_then(|c| c.peer_tx.clone());

        let Some(peer_tx) = peer_tx else { return };

        let _ = peer_tx.send(PeerOp::SendRouteRefresh {
            afi,
            safi,
            subtype: RouteRefreshSubtype::BoRR,
        });
        self.resend_routes_to_peer(peer_ip, afi, safi);
        let _ = peer_tx.send(PeerOp::SendRouteRefresh {
            afi,
            safi,
            subtype: RouteRefreshSubtype::EoRR,
        });
    }

    /// RFC 7313: Mark all routes from peer as stale for the given AFI/SAFI.
    async fn handle_route_refresh_borr(&mut self, peer_ip: IpAddr, afi: Afi, safi: Safi) {
        let afi_safi = AfiSafi::new(afi, safi);
        let count = self.loc_rib.mark_peer_routes_stale(peer_ip, afi_safi);
        info!(%peer_ip, ?afi, ?safi, count, "BoRR: marked routes stale (RFC 7313)");

        if let Some(ttl) = self.config.enhanced_rr_stale_ttl {
            if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
                peer_info.rr_stale_timers.run(
                    afi_safi,
                    ttl,
                    ServerOp::EnhancedRrStaleTimerExpired { peer_ip, afi_safi },
                    self.op_tx.clone(),
                );
            }
        }
    }

    /// RFC 7313: Sweep remaining stale routes from peer for the given AFI/SAFI.
    async fn handle_route_refresh_eorr(&mut self, peer_ip: IpAddr, afi: Afi, safi: Safi) {
        let afi_safi = AfiSafi::new(afi, safi);
        if let Some(peer_info) = self.peers.get_mut(&peer_ip) {
            peer_info.rr_stale_timers.cancel(&afi_safi);
        }
        let delta = self.loc_rib.remove_peer_routes_stale(peer_ip, &[afi_safi]);
        let removed = delta.changed.len();
        if removed > 0 {
            info!(%peer_ip, ?afi, ?safi, removed, "EoRR: purged stale routes (RFC 7313)");
        } else {
            info!(%peer_ip, ?afi, ?safi, "EoRR: no stale routes to purge (RFC 7313)");
        }
        self.propagate_routes(delta, Some(peer_ip)).await;
    }

    /// RFC 7313: Stale TTL expired without receiving EoRR. Sweep remaining stale routes.
    async fn handle_enhanced_rr_stale_expired(&mut self, peer_ip: IpAddr, afi_safi: AfiSafi) {
        info!(%peer_ip, %afi_safi, "enhanced RR stale TTL expired (RFC 7313)");
        let delta = self.loc_rib.remove_peer_routes_stale(peer_ip, &[afi_safi]);
        self.propagate_routes(delta, Some(peer_ip)).await;
    }

    /// Process a peer UPDATE on the server: store in adj-rib-in, validate,
    /// apply import policy, update loc-rib, propagate, and send BMP.
    async fn handle_peer_update(&mut self, peer_ip: IpAddr, mut routes: Vec<PendingRoute>) {
        let Some(peer) = self.peers.get_mut(&peer_ip) else {
            return;
        };

        // Extract connection info needed for validation
        let Some(conn) = peer.established_conn() else {
            return;
        };
        let Some(peer_asn) = conn.asn else {
            return;
        };
        let negotiated_afi_safis = conn
            .capabilities
            .as_ref()
            .map(|c| c.multiprotocol.clone())
            .unwrap_or_default();
        let local_address = conn.conn_info.as_ref().map(|ci| ci.local_address);

        let local_asn = self.config.asn;
        let is_ebgp = peer_asn != local_asn;
        let peer_cfg = self.config.find_peer(peer_ip).cloned().unwrap_or_default();
        let max_prefix_for_family: HashMap<AfiSafi, MaxPrefixSetting> = routes
            .iter()
            .map(|route| route.route_key().afi_safi())
            .collect::<HashSet<_>>()
            .into_iter()
            .filter_map(|af| peer_cfg.effective_max_prefix(&af).map(|s| (af, s)))
            .collect();
        let local_bgp_id = self.config.router_id;
        let cluster_id = self.config.cluster_id();

        // Extract announced/withdrawn for adj-rib-in and validation checks
        let (announced, withdrawn) = PendingRoute::split(&routes);

        // Store ALL routes in adj-rib-in first (RFC 4271 3.2: "unprocessed")
        for (key, path_id) in &withdrawn {
            peer.adj_rib_in.remove_route(key, *path_id);
        }
        for route_path in &announced {
            peer.adj_rib_in
                .add_route(route_path.key.clone(), Arc::clone(&route_path.path));
        }

        // AFI/SAFI validation (RFC 4760 Section 7)
        if !announced.is_empty() && !validate_afi_safi(peer, &announced, &negotiated_afi_safis) {
            return;
        }

        // Treat-as-withdraw: if any check fails, all announcements
        // in the batch are rejected (BGP UPDATE shares attrs across all NLRI)
        if let Some(first_path) = announced.first().map(|prefix_path| &*prefix_path.path) {
            if (is_ebgp
                && peer_cfg.enforce_first_as
                && !check_first_as(first_path, peer_asn, peer_ip))
                || is_next_hop_local(first_path, local_address)
                || has_as_path_loop(first_path, local_asn)
                || (!is_ebgp && has_route_reflector_loop(first_path, local_bgp_id, cluster_id))
            {
                reject_announcements(&mut routes);
            }
        }

        // eBGP attribute scrubbing (applied directly to routes)
        if is_ebgp {
            scrub_ebgp_pending_routes(&mut routes);
        }

        // Per-family max-prefix check: each family uses its own override or falls back
        // to the peer-level max_prefix setting.
        let families_in_update: HashSet<AfiSafi> =
            routes.iter().map(|r| r.route_key().afi_safi()).collect();
        let mut discard_families: HashSet<AfiSafi> = HashSet::new();
        for family in &families_in_update {
            if let Some(setting) = max_prefix_for_family.get(family) {
                let current = peer.adj_rib_in.family_count(family);
                if current > setting.limit as usize {
                    match setting.action {
                        MaxPrefixAction::Terminate => {
                            warn!(%peer_ip, %family, limit = setting.limit, current,
                                  "max prefix limit exceeded");
                            if peer_cfg.allow_automatic_stop {
                                self.handle_max_prefix_terminate(peer_ip).await;
                            } else {
                                warn!(%peer_ip, "allow_automatic_stop=false, discarding update");
                            }
                            return;
                        }
                        MaxPrefixAction::Discard => {
                            warn!(%peer_ip, %family, limit = setting.limit, current,
                                  "max prefix limit reached, discarding new prefixes");
                            discard_families.insert(*family);
                        }
                    }
                }
            }
        }
        if !discard_families.is_empty() {
            routes.retain(|r| match r {
                PendingRoute::Announce(rp) => !discard_families.contains(&rp.key.afi_safi()),
                PendingRoute::Withdraw(_) => true,
            });
        }

        // Import policy + loc-rib update (routes processed in arrival order)
        let Some(peer) = self.peers.get_mut(&peer_ip) else {
            return;
        };
        let import_policies = peer.import_policies.clone();
        let (bmp_peer_asn, bmp_peer_bgp_id) = peer
            .established_conn()
            .map(|c| (c.asn, c.bgp_id))
            .unwrap_or((None, None));

        let vrp_table = &self.vrp_table;
        let delta = self
            .loc_rib
            .apply_peer_update(peer_ip, &routes, |prefix, path| {
                apply_import(vrp_table, local_asn, &import_policies, prefix, path)
            });

        info!(%peer_ip, "UPDATE processing complete");

        self.propagate_routes(delta, Some(peer_ip)).await;

        // BMP route monitoring (uses validated routes, not pre-validation snapshot)
        if let (Some(asn), Some(bgp_id)) = (bmp_peer_asn, bmp_peer_bgp_id) {
            let (bmp_announced, bmp_withdrawn) = PendingRoute::split(&routes);
            self.send_bmp_route_monitoring(peer_ip, asn, bgp_id, &bmp_withdrawn, &bmp_announced);
        }
    }

    /// Handle VRP table update from RtrManager. Apply diff to VrpTable, find
    /// affected routes via rib trie, re-evaluate from adj-rib-in using the
    /// same apply_peer_update path as normal route handling.
    async fn handle_vrp_update(&mut self, added: Vec<Vrp>, removed: Vec<Vrp>) {
        info!(
            added = added.len(),
            removed = removed.len(),
            "applying VRP update"
        );

        self.vrp_table.add(&added);
        self.vrp_table.remove(&removed);

        let affected = self.loc_rib.affected_prefixes(&added, &removed);
        if affected.is_empty() {
            return;
        }

        info!(
            affected_prefixes = affected.len(),
            "re-evaluating routes after VRP change"
        );

        let delta = self.reevaluate_routes(self.affected_routes(&affected));
        if delta.has_changes() {
            self.propagate_routes(delta, None).await;
        }
    }

    /// Re-run import policy on routes already in adj-rib-in (e.g. after VRP change).
    fn reevaluate_routes(&mut self, routes: Vec<(IpAddr, Vec<RoutePath>)>) -> RouteDelta {
        let local_asn = self.config.asn;
        let mut delta = RouteDelta::new();
        for (peer_ip, peer_routes) in routes {
            let import_policies = match self.peers.get(&peer_ip) {
                Some(peer) => peer.import_policies.clone(),
                None => continue,
            };
            let vrp_table = &self.vrp_table;
            let routes: Vec<PendingRoute> = peer_routes
                .into_iter()
                .map(PendingRoute::Announce)
                .collect();
            let peer_delta = self
                .loc_rib
                .apply_peer_update(peer_ip, &routes, |route_key, path| {
                    apply_import(vrp_table, local_asn, &import_policies, route_key, path)
                });
            delta.extend(peer_delta);
        }
        delta
    }

    /// Collect adj-rib-in routes for the given prefixes from all peers.
    /// Returns (peer_ip, routes) pairs. Collected upfront so loc_rib can be
    /// mutated separately (borrow splitting).
    fn affected_routes(&self, prefixes: &HashSet<IpNetwork>) -> Vec<(IpAddr, Vec<RoutePath>)> {
        let mut result = Vec::new();
        for (&peer_ip, peer_info) in &self.peers {
            let mut routes = Vec::new();
            for &prefix in prefixes {
                if let Some(route) = peer_info.adj_rib_in.get_route(&RouteKey::Prefix(prefix)) {
                    for path in &route.paths {
                        routes.push(RoutePath {
                            key: RouteKey::Prefix(prefix),
                            path: Arc::clone(path),
                        });
                    }
                }
            }
            if !routes.is_empty() {
                result.push((peer_ip, routes));
            }
        }
        result
    }
}

/// Validate AFI/SAFI for announced routes against negotiated capabilities.
/// Returns false if UPDATE should be ignored entirely.
fn validate_afi_safi(
    peer: &mut PeerInfo,
    announced: &[RoutePath],
    negotiated: &HashSet<AfiSafi>,
) -> bool {
    for pp in announced {
        let afi_safi = pp.key.afi_safi();

        if peer.disabled_afi_safi.contains(&afi_safi) {
            return false;
        }

        if !negotiated.is_empty() && !negotiated.contains(&afi_safi) {
            warn!(
                %afi_safi,
                "received UPDATE for non-negotiated AFI/SAFI, disabling"
            );
            let drained = peer.adj_rib_in.drain_afi_safi(afi_safi);
            if !drained.is_empty() {
                warn!(%afi_safi, deleted_count = drained.len(),
                      "cleared adj-rib-in for non-negotiated AFI/SAFI");
            }
            peer.disabled_afi_safi.insert(afi_safi);
            return false;
        }
    }
    true
}

/// RFC 4271 6.3: Check first AS in path matches peer ASN.
/// When leftmost AS is AS_TRANS (RFC 6793), skip the check -- the peer is an
/// OLD speaker and AS4_PATH resolution already happened during Path building.
fn check_first_as(path: &Path, peer_asn: u32, peer_ip: IpAddr) -> bool {
    let Some(first_segment) = path.as_path().first() else {
        return true;
    };
    let Some(&leftmost_as) = first_segment.asn_list.first() else {
        return true;
    };
    if leftmost_as == AS_TRANS as u32 {
        return true;
    }
    if leftmost_as != peer_asn {
        warn!(
            %peer_ip,
            leftmost_as,
            peer_asn,
            "AS_PATH first AS does not match peer AS, treat-as-withdraw per RFC 7606"
        );
        return false;
    }
    true
}

/// Convert all Announce entries to Withdraw in-place (treat-as-withdraw).
fn reject_announcements(routes: &mut [PendingRoute]) {
    for route in routes.iter_mut() {
        if let PendingRoute::Announce(route_path) = route {
            *route =
                PendingRoute::Withdraw((route_path.key.clone(), route_path.path.remote_path_id));
        }
    }
}

/// RFC 4456/8097/8326: Scrub non-transitive attrs and apply GRACEFUL_SHUTDOWN.
fn scrub_ebgp_pending_routes(routes: &mut [PendingRoute]) {
    for route in routes {
        if let PendingRoute::Announce(route_path) = route {
            let path = Arc::make_mut(&mut route_path.path);
            let attrs = path.attrs_mut();
            attrs.originator_id = None;
            attrs.cluster_list.clear();
            attrs
                .extended_communities
                .retain(|ec| !is_rpki_state_community(*ec));
            if attrs.communities.contains(&community::GRACEFUL_SHUTDOWN) {
                attrs.local_pref = Some(0);
            }
        }
    }
}

/// RFC 4271 5.1.3a: NEXT_HOP must not be local address.
fn is_next_hop_local(path: &Path, local_address: Option<IpAddr>) -> bool {
    let Some(local_ip) = local_address else {
        return false;
    };
    match (&path.attrs.next_hop, local_ip) {
        (NextHopAddr::Ipv4(nh), IpAddr::V4(local)) => nh == &local,
        (NextHopAddr::Ipv6(nh), IpAddr::V6(local)) => nh == &local,
        _ => false,
    }
}

/// RFC 4271 9.1.2: AS_PATH must not contain local ASN.
fn has_as_path_loop(path: &Path, local_asn: u32) -> bool {
    path.as_path()
        .iter()
        .any(|seg| seg.asn_list.contains(&local_asn))
}

/// RFC 4456 Section 8: Check for route reflector loop.
fn has_route_reflector_loop(path: &Path, local_bgp_id: Ipv4Addr, cluster_id: Ipv4Addr) -> bool {
    if path.originator_id() == Some(local_bgp_id) {
        return true;
    }
    path.cluster_list().contains(&cluster_id)
}

/// Shared import policy evaluation: stamp RPKI validation state, set default
/// LOCAL_PREF, then run the import policies for the route's AFI/SAFI.
fn apply_import(
    vrp_table: &VrpTable,
    local_asn: u32,
    import_policies: &AfiSafiPolicies,
    route_key: &RouteKey,
    path: &mut Path,
) -> bool {
    if let RouteKey::Prefix(prefix) = route_key {
        let origin = path.origin_as().unwrap_or(local_asn);
        path.rpki_state = vrp_table.validate(*prefix, origin);
    }
    if path.attrs.local_pref.is_none() {
        path.attrs_mut().local_pref = Some(100);
    }
    let policies = import_policies
        .get(&route_key.afi_safi())
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    for policy in policies {
        match policy.evaluate(route_key, path) {
            PolicyResult::Accept => return true,
            PolicyResult::Reject => return false,
            PolicyResult::Continue => continue,
        }
    }
    false
}
