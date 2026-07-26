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

use super::fsm::FsmEvent;
use super::{BgpOpenParams, PeerCapabilities, PendingRoute};
use crate::bgp::msg::{BgpMessage, Message};
use crate::bgp::msg_keepalive::KeepaliveMessage;
use crate::bgp::msg_notification::{BgpError, NotificationMessage, OpenMessageError};
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::msg_open_types::LlgrEntry;
use crate::bgp::msg_open_types::{
    AddPathCapability, AddPathMode, BgpCapabiltyCode, Capability, OptionalParam,
};
use crate::bgp::msg_route_refresh::RouteRefreshSubtype;
use crate::bgp::msg_update_types::MAX_2BYTE_ASN;
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::log::{debug, info, warn};
use crate::metrics;
use crate::server::ops::ServerOp;
use conf::bgp::LlgrConfig;
use std::collections::HashSet;
use std::io;
use std::net::Ipv4Addr;
use telemetry::{metric, Unit};
use tokio::io::AsyncWriteExt;

use conf::bgp::{AddPathSend, PeerConfig};

use super::{Peer, RouteChanges, SessionType};

/// Convert LLGR config to capability entries for OPEN message building.
fn llgr_to_entries(config: &LlgrConfig) -> Vec<LlgrEntry> {
    let stale_time = config.stale_time.unwrap_or(0);
    let afi_safis = config.afi_safis.as_deref().unwrap_or(&[]);
    afi_safis
        .iter()
        .map(|afi_safi| LlgrEntry {
            afi_safi: *afi_safi,
            forwarding_preserved: false,
            stale_time,
        })
        .collect()
}

/// Negotiate multiprotocol capabilities (intersection of local and peer)
fn negotiate_multiprotocol(local: &[AfiSafi], peer: &HashSet<AfiSafi>) -> HashSet<AfiSafi> {
    let local_set: HashSet<_> = local.iter().copied().collect();
    local_set.intersection(peer).copied().collect()
}

/// AFI/SAFIs to advertise in our OPEN. Configured families if any are
/// listed, otherwise IPv4 Unicast as the implicit default.
fn advertised_afi_safis(config: &PeerConfig) -> Vec<AfiSafi> {
    let configured = config.afi_safi_list();
    if configured.is_empty() {
        vec![AfiSafi::new(Afi::Ipv4, Safi::Unicast)]
    } else {
        configured
    }
}

/// Build optional parameters for OPEN message.
fn build_optional_params(
    asn: u32,
    config: &PeerConfig,
    llgr: &Option<LlgrConfig>,
) -> Vec<OptionalParam> {
    let afi_safis = advertised_afi_safis(config);
    let mut caps = Vec::new();

    // Multiprotocol capabilities (RFC 4760)
    for afi_safi in &afi_safis {
        caps.push(Capability::new_multiprotocol(afi_safi));
    }

    // Route Refresh (RFC 2918)
    caps.push(Capability::new_route_refresh());

    // Enhanced Route Refresh (RFC 7313)
    caps.push(Capability::new_enhanced_route_refresh());

    // Graceful Restart (RFC 4724) if enabled
    if config.graceful_restart.enabled {
        // Receiving Speaker mode: R bit = false (we don't preserve forwarding state)
        // F bit = false for all AFI/SAFIs (no forwarding state preservation)
        let afi_safi_list: Vec<_> = afi_safis
            .iter()
            .map(|afi_safi| (*afi_safi, false))
            .collect();
        caps.push(Capability::new_graceful_restart(
            config.graceful_restart.restart_time,
            false,
            afi_safi_list,
        ));
    }

    // Four-Octet ASN (RFC 6793) - always advertised
    caps.push(Capability::new_four_octet_asn(asn));

    // RFC 9494: LLGR from resolved config
    let llgr_entries = llgr.as_ref().map(llgr_to_entries).unwrap_or_default();
    if !llgr_entries.is_empty() {
        caps.push(Capability::new_llgr(&llgr_entries));
    }

    // ADD-PATH (RFC 7911) if configured
    let add_path_send = !matches!(config.add_path_send, AddPathSend::Disabled);
    if let Some(mode) = AddPathMode::from_flags(add_path_send, config.add_path_receive) {
        let entries: Vec<_> = afi_safis.iter().map(|afi_safi| (*afi_safi, mode)).collect();
        caps.push(Capability::new_add_path(&entries));
    }

    vec![OptionalParam::from_capabilities(caps)]
}

/// Extract capabilities from OPEN message (RFC 4271, RFC 2918, RFC 4760, RFC 6793, RFC 4724).
///
/// RFC 5492: capabilities may arrive packed in one Optional Parameter or
/// split across multiple. Both forms must be processed identically.
fn extract_capabilities(open_msg: &OpenMessage) -> PeerCapabilities {
    let mut capabilities = PeerCapabilities::default();

    for cap in open_msg
        .optional_params
        .iter()
        .flat_map(|p| p.capabilities())
    {
        match cap.code {
            BgpCapabiltyCode::Multiprotocol => {
                if let Ok(afi_safi) =
                    crate::bgp::multiprotocol::afi_safi_from_capability_bytes(&cap.val)
                {
                    capabilities.multiprotocol.insert(afi_safi);
                }
            }
            BgpCapabiltyCode::RouteRefresh => {
                capabilities.route_refresh = true;
            }
            BgpCapabiltyCode::FourOctetAsn if cap.val.len() == 4 => {
                // RFC 6793: 4-byte ASN value
                let asn = u32::from_be_bytes([cap.val[0], cap.val[1], cap.val[2], cap.val[3]]);
                capabilities.four_octet_asn = Some(asn);
            }
            BgpCapabiltyCode::GracefulRestart => {
                // RFC 4724: Parse Graceful Restart capability
                capabilities.graceful_restart = cap.as_graceful_restart();
            }
            BgpCapabiltyCode::AddPath => {
                // RFC 7911: Parse ADD-PATH capability
                capabilities.add_path = cap.as_add_path();
            }
            BgpCapabiltyCode::EnhancedRouteRefresh => {
                capabilities.enhanced_route_refresh = true;
            }
            BgpCapabiltyCode::Llgr => {
                // RFC 9494: Parse LLGR capability
                capabilities.llgr = cap.as_llgr();
            }
            _ => {}
        }
    }

    // RFC 9494 Section 4.5: LLGR without GR MUST be ignored
    if capabilities.llgr.is_some() && capabilities.graceful_restart.is_none() {
        warn!("ignoring LLGR capability: GR capability not present (RFC 9494 Section 4.5)");
        capabilities.llgr = None;
    }

    capabilities
}

/// Create an OPEN message with all capabilities
fn create_open_message(
    asn: u32,
    hold_time: u16,
    router_id: Ipv4Addr,
    config: &PeerConfig,
    llgr: &Option<LlgrConfig>,
) -> OpenMessage {
    let optional_params = build_optional_params(asn, config, llgr);

    // Calculate total optional params length
    let optional_params_len = optional_params
        .iter()
        .map(|p| 2 + p.param_len as usize) // type(1) + len(1) + value
        .sum::<usize>() as u8;

    OpenMessage {
        version: 4,
        asn,
        hold_time,
        bgp_identifier: u32::from(router_id),
        optional_params_len,
        optional_params,
    }
}

impl Peer {
    /// RFC 4271 6.8 / RFC 6286 2.3: true if the connection we initiated wins
    /// the collision. Higher BGP Identifier wins; on equal IDs, higher AS wins.
    pub(super) fn local_wins_collision(&self, open: &OpenMessage) -> bool {
        let local_id = u32::from(self.local_config.bgp_id);
        let remote_id = open.bgp_identifier;
        if local_id != remote_id {
            return local_id > remote_id;
        }
        let remote_asn = extract_capabilities(open)
            .four_octet_asn
            .unwrap_or(open.asn);
        self.local_config.asn > remote_asn
    }

    fn build_open_message(&self) -> OpenMessage {
        if self.capabilities_suppressed {
            // RFC 5492: peer rejected capabilities, send bare OPEN.
            OpenMessage::new(
                self.local_config.asn,
                self.local_config.hold_time,
                u32::from(self.local_config.bgp_id),
            )
        } else {
            create_open_message(
                self.local_config.asn,
                self.local_config.hold_time,
                self.local_config.bgp_id,
                &self.config,
                &self.local_config.llgr,
            )
        }
    }

    /// Send OPEN message to peer.
    pub(super) async fn send_open(&mut self) -> Result<(), io::Error> {
        let open_msg = self.build_open_message();
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no TCP connection"))?;
        conn.tx.write_all(&open_msg.serialize()).await?;
        self.sent_open = Some(open_msg);
        self.statistics.open_sent += 1;
        info!(peer_ip = %self.addr, capabilities_suppressed = self.capabilities_suppressed, "sent OPEN message");
        Ok(())
    }

    /// Handle entering OpenConfirm state - negotiate timers, send KEEPALIVE, notify server
    pub(super) async fn enter_open_confirm(
        &mut self,
        peer_asn: u32,
        peer_hold_time: u16,
        local_asn: u32,
        local_hold_time: u16,
        peer_capabilities: PeerCapabilities,
    ) -> Result<(), io::Error> {
        // Validate peer ASN if configured
        if let Some(expected_asn) = self.config.asn {
            if peer_asn != expected_asn {
                warn!(peer_ip = %self.addr,
                      expected_asn = expected_asn,
                      received_asn = peer_asn,
                      "rejecting session: peer ASN mismatch");

                let notif = NotificationMessage::new(
                    BgpError::OpenMessageError(OpenMessageError::BadPeerAs),
                    vec![],
                );
                self.send_notification(notif).await?;

                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "remote ASN mismatch: expected {}, received {}",
                        expected_asn, peer_asn
                    ),
                ));
            }
        }

        // Set peer ASN and determine session type
        self.asn = Some(peer_asn);
        self.session_type = Some(if peer_asn == local_asn {
            SessionType::Ibgp
        } else {
            SessionType::Ebgp
        });

        // Negotiate multiprotocol capabilities (intersection of local and peer)
        let local_afi_safis = advertised_afi_safis(&self.config);
        let negotiated_afi_safis =
            negotiate_multiprotocol(&local_afi_safis, &peer_capabilities.multiprotocol);

        // RFC 5492 Section 5: reject if peer advertised multiprotocol but
        // none overlap with ours. Skip the check when peer sent no multiprotocol
        // caps — base BGP-4 (RFC 4271) carries IPv4 Unicast without capabilities.
        if negotiated_afi_safis.is_empty() && !peer_capabilities.multiprotocol.is_empty() {
            warn!(peer_ip = %self.addr, "no common AFI/SAFI with peer");
            let data: Vec<u8> = local_afi_safis
                .iter()
                .flat_map(|afi_safi| Capability::new_multiprotocol(afi_safi).to_bytes())
                .collect();
            let notif = NotificationMessage::new(
                BgpError::OpenMessageError(OpenMessageError::UnsupportedCapability),
                data,
            );
            self.send_notification(notif).await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "no common AFI/SAFI",
            ));
        }

        // Negotiate Four-Octet ASN capability (RFC 6793)
        // Both must advertise for it to be negotiated
        let negotiated_four_octet_asn = peer_capabilities.four_octet_asn;

        // Negotiate ADD-PATH capability (RFC 7911)
        // Send is negotiated when local advertised send AND peer advertised receive
        // Receive is negotiated when local advertised receive AND peer advertised send
        let negotiated_add_path = self.negotiate_add_path(&peer_capabilities);

        self.capabilities = PeerCapabilities {
            multiprotocol: negotiated_afi_safis,
            route_refresh: peer_capabilities.route_refresh,
            enhanced_route_refresh: peer_capabilities.enhanced_route_refresh,
            four_octet_asn: negotiated_four_octet_asn,
            graceful_restart: peer_capabilities.graceful_restart,
            add_path: negotiated_add_path,
            llgr: peer_capabilities.llgr,
        };

        // RFC 4724: Update FSM with GR status
        // GR is active if peer advertised it (received, not what we sent)
        let gr_active = self.capabilities.graceful_restart.is_some();
        self.fsm.set_graceful_restart_negotiated(gr_active);

        // RFC 6793 Section 4.2.1: Peering between NEW and OLD speakers is only
        // possible if the NEW speaker has a two-octet AS number
        let local_asn = self.local_config.asn;
        if local_asn > MAX_2BYTE_ASN && negotiated_four_octet_asn.is_none() {
            // We have a large ASN but peer doesn't support 4-byte ASNs
            // This violates RFC 6793 - the session cannot function correctly
            warn!(local_asn = local_asn,
                  peer_ip = %self.addr,
                  "rejecting session: peer does not support 4-byte ASNs but local ASN exceeds 65535");

            let notif = NotificationMessage::new(
                BgpError::OpenMessageError(OpenMessageError::UnsupportedOptionalParameter),
                vec![],
            );
            self.send_notification(notif).await?;

            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer does not support 4-byte ASNs (RFC 6793)",
            ));
        }

        info!(multiprotocol = ?self.capabilities.multiprotocol,
              route_refresh = self.capabilities.route_refresh,
              four_octet_asn = ?self.capabilities.four_octet_asn,
              graceful_restart = ?self.capabilities.graceful_restart,
              add_path = ?self.capabilities.add_path,
              llgr = ?self.capabilities.llgr,
              peer_ip = %self.addr,
              "peer capabilities");

        // Negotiate hold time: use minimum (RFC 4271).
        let hold_time = local_hold_time.min(peer_hold_time);
        self.fsm.timers.set_negotiated_hold_time(hold_time);

        // Send KEEPALIVE message
        self.send_keepalive().await?;

        // RFC 4271 8.2.2: If negotiated hold time is non-zero, start timers.
        // If zero, timers are not started (connection stays up without heartbeats).
        if hold_time != 0 {
            self.fsm.timers.reset_hold_timer();
        } else {
            // Hold time is zero - ensure timers are stopped
            self.fsm.timers.stop_keepalive_timer();
            self.fsm.timers.stop_hold_timer();
        }

        info!(peer_ip = %self.addr, hold_time = hold_time, "timers initialized");

        // Notify server that handshake is complete
        let _ = self.server_tx.send(ServerOp::PeerHandshakeComplete {
            peer_ip: self.addr,
            asn: peer_asn,
        });

        Ok(())
    }

    /// Send KEEPALIVE message and restart keepalive timer
    pub(super) async fn send_keepalive(&mut self) -> Result<(), io::Error> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no TCP connection"))?;
        let keepalive_msg = KeepaliveMessage {};
        conn.tx.write_all(&keepalive_msg.serialize()).await?;
        self.statistics.keepalive_sent += 1;
        debug!(peer_ip = %self.addr, "sent KEEPALIVE message");
        // RFC 4271: Restart KeepaliveTimer unless negotiated HoldTime is zero
        if self.fsm.timers.hold_time.as_secs() > 0 {
            self.fsm.timers.start_keepalive_timer();
        }
        Ok(())
    }

    /// Send NOTIFICATION message (RFC 4271 Section 6.1)
    ///
    /// RFC 4271 8.2.1.5: SendNOTIFICATIONwithoutOPEN controls whether NOTIFICATION
    /// can be sent before OPEN. If disabled (default), NOTIFICATION is only sent
    /// after OPEN has been sent.
    pub(super) async fn send_notification(
        &mut self,
        notif_msg: NotificationMessage,
    ) -> Result<(), io::Error> {
        if !self.can_send_notification() {
            warn!(peer_ip = %self.addr, error = ?notif_msg.error(), "skipping NOTIFICATION");
            return Ok(());
        }
        // Safe: can_send_notification checks conn.is_some()
        let conn = self.conn.as_mut().unwrap();
        conn.tx.write_all(&notif_msg.serialize()).await?;
        self.statistics.notification_sent += 1;
        metric(
            metrics::NOTIFICATION_SENT_COUNT,
            1,
            Unit::Count,
            &[
                ("Peer", &self.addr),
                ("Code", &notif_msg.error().error_code()),
            ],
            &[&["Peer"], &["Code"], &["Peer", "Code"]],
            &[("Subcode", &notif_msg.error().error_subcode())],
        );
        warn!(peer_ip = %self.addr, error = ?notif_msg.error(), "sent NOTIFICATION");
        Ok(())
    }

    /// Process a received BGP message from the TCP stream
    /// Returns Err if should disconnect (notification or processing error)
    pub(super) async fn handle_received_message(
        &mut self,
        message: BgpMessage,
    ) -> Result<(), io::Error> {
        match &message {
            BgpMessage::Notification(_) => {
                let _ = self.handle_message(message).await;
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "notification received",
                ))
            }
            BgpMessage::Update(_) => {
                let delta = self.handle_message(message).await?;
                // RFC 4271: Reset HoldTimer if negotiated HoldTime is non-zero
                if self.fsm.timers.hold_time.as_secs() > 0 {
                    self.fsm.timers.reset_hold_timer();
                }

                // Accumulate into ordered event list; the established loop
                // flushes periodically so multiple UPDATEs coalesce into
                // a single ServerOp::PeerUpdate preserving temporal order.
                if let Some((announced, withdrawn)) = delta {
                    self.pending_routes
                        .extend(withdrawn.into_iter().map(PendingRoute::Withdraw));
                    self.pending_routes
                        .extend(announced.into_iter().map(PendingRoute::Announce));
                }
                Ok(())
            }
            BgpMessage::Keepalive(_) => {
                let _ = self.handle_message(message).await;
                // RFC 4271: Reset HoldTimer if negotiated HoldTime is non-zero
                if self.fsm.timers.hold_time.as_secs() > 0 {
                    self.fsm.timers.reset_hold_timer();
                }
                Ok(())
            }
            BgpMessage::Open(_) => {
                self.handle_message(message).await?;
                Ok(())
            }
            BgpMessage::RouteRefresh(_) => {
                let _ = self.handle_message(message).await;
                Ok(())
            }
        }
    }

    /// Track statistics for received BGP messages
    pub(super) fn track_received_message(&mut self, message: &BgpMessage) {
        match message {
            BgpMessage::Open(open_msg) => {
                self.statistics.open_received += 1;
                info!(peer_ip = %self.addr, asn = open_msg.asn, hold_time = open_msg.hold_time, "received OPEN from peer");
            }
            BgpMessage::Update(_) => {
                self.statistics.update_received += 1;
                info!(peer_ip = %self.addr, "received UPDATE");
            }
            BgpMessage::Keepalive(_) => {
                self.statistics.keepalive_received += 1;
                debug!(peer_ip = %self.addr, "received KEEPALIVE");
            }
            BgpMessage::Notification(notif) => {
                self.statistics.notification_received += 1;
                warn!(peer_ip = %self.addr, notification = ?notif, "received NOTIFICATION");
                metric(
                    metrics::NOTIFICATION_RECEIVED_COUNT,
                    1,
                    Unit::Count,
                    &[("Peer", &self.addr), ("Code", &notif.error().error_code())],
                    &[&["Peer"], &["Code"], &["Peer", "Code"]],
                    &[("Subcode", &notif.error().error_subcode())],
                );
                // RFC 5492: if peer doesn't understand capabilities, suppress them on retry.
                if matches!(
                    notif.error(),
                    BgpError::OpenMessageError(OpenMessageError::UnsupportedOptionalParameter)
                ) {
                    info!(peer_ip = %self.addr, "peer does not support capabilities, suppressing on retry");
                    self.capabilities_suppressed = true;
                }
            }
            BgpMessage::RouteRefresh(msg) => {
                self.statistics.route_refresh_received += 1;
                info!(peer_ip = %self.addr, afi = ?msg.afi, safi = ?msg.safi, "received ROUTE_REFRESH");
            }
        }
    }

    /// Process a BGP message and return route changes for Loc-RIB update if applicable
    /// Returns RouteChanges (announced, withdrawn) or None if not an UPDATE
    pub(super) async fn handle_message(
        &mut self,
        message: BgpMessage,
    ) -> Result<Option<RouteChanges>, io::Error> {
        self.track_received_message(&message);

        // Process FSM event
        match &message {
            BgpMessage::Open(open_msg) => {
                // Store received OPEN for BMP PeerUp
                self.received_open = Some(open_msg.clone());
                // Store peer's BGP Router ID
                self.bgp_id = Some(std::net::Ipv4Addr::from(
                    open_msg.bgp_identifier.to_be_bytes(),
                ));

                // Extract capabilities from OPEN message
                let peer_capabilities = extract_capabilities(open_msg);

                self.process_event(&FsmEvent::BgpOpenReceived(BgpOpenParams {
                    peer_asn: open_msg.asn,
                    peer_hold_time: open_msg.hold_time,
                    peer_bgp_id: open_msg.bgp_identifier,
                    local_asn: self.local_config.asn,
                    local_hold_time: self.local_config.hold_time,
                    peer_capabilities,
                }))
                .await?;
            }
            BgpMessage::Update(_) => {
                self.process_event(&FsmEvent::BgpUpdateReceived).await?;
            }
            BgpMessage::Keepalive(_) => {
                self.process_event(&FsmEvent::BgpKeepaliveReceived).await?;
            }
            BgpMessage::Notification(notif) => {
                self.handle_notification_received(notif).await;
                return Ok(None);
            }
            BgpMessage::RouteRefresh(msg) => {
                self.handle_route_refresh(msg.afi, msg.safi, msg.subtype)
                    .await;
                return Ok(None);
            }
        }

        // Process UPDATE message content
        let BgpMessage::Update(update_msg) = message else {
            return Ok(None);
        };

        // RFC 4724: Check for End-of-RIB marker
        if let Some(afi_safi) = update_msg.eor_afi_safi() {
            info!(peer_ip = %self.addr, %afi_safi, "received End-of-RIB marker");
            self.handle_eor_received(afi_safi).await;
            return Ok(None);
        }

        Ok(Some(self.handle_update(update_msg)))
    }

    /// Handle received ROUTE_REFRESH message
    async fn handle_route_refresh(&mut self, afi: Afi, safi: Safi, subtype: RouteRefreshSubtype) {
        // RFC 2918: ROUTE_REFRESH capability must be negotiated
        if !self.capabilities.route_refresh {
            warn!(peer_ip = %self.addr,
                  "ROUTE_REFRESH received but capability not negotiated");
            return;
        }

        // Validate against negotiated multiprotocol capabilities
        let requested = AfiSafi::new(afi, safi);
        if !self.capabilities.multiprotocol.contains(&requested) {
            warn!(peer_ip = %self.addr,
                  afi = ?afi,
                  safi = ?safi,
                  "ROUTE_REFRESH for non-negotiated AFI/SAFI");
            return;
        }

        match subtype {
            RouteRefreshSubtype::Normal => {
                let _ = self.server_tx.send(ServerOp::RouteRefresh {
                    peer_ip: self.addr,
                    afi,
                    safi,
                });
            }
            RouteRefreshSubtype::BoRR => {
                if !self.capabilities.enhanced_route_refresh {
                    warn!(peer_ip = %self.addr, "BoRR received but enhanced route refresh not negotiated");
                    return;
                }
                // RFC 7313 Section 4: If GR is negotiated, ignore BoRR before EoR
                let eor_received = self
                    .gr_state
                    .as_ref()
                    .is_none_or(|state| state.eor_received.contains(&requested));
                if self.capabilities.graceful_restart.is_some() && !eor_received {
                    warn!(peer_ip = %self.addr, ?afi, ?safi,
                          "ignoring BoRR received before EoR (RFC 7313)");
                    return;
                }
                let _ = self.server_tx.send(ServerOp::RouteRefreshBoRR {
                    peer_ip: self.addr,
                    afi,
                    safi,
                });
            }
            RouteRefreshSubtype::EoRR => {
                if !self.capabilities.enhanced_route_refresh {
                    warn!(peer_ip = %self.addr, "EoRR received but enhanced route refresh not negotiated");
                    return;
                }
                // Flush pending routes so the server processes them
                // before the stale sweep triggered by EoRR.
                self.flush_pending_routes();
                let _ = self.server_tx.send(ServerOp::RouteRefreshEoRR {
                    peer_ip: self.addr,
                    afi,
                    safi,
                });
            }
            RouteRefreshSubtype::Unknown(val) => {
                // RFC 7313 Section 5: unknown subtypes silently ignored
                debug!(peer_ip = %self.addr, subtype = val, "ignoring ROUTE_REFRESH with unknown subtype");
            }
        }
    }

    /// Negotiate ADD-PATH capability (RFC 7911)
    /// Local send is negotiated when local config has send enabled AND peer advertised receive.
    /// Local receive is negotiated when local config has receive enabled AND peer advertised send.
    fn negotiate_add_path(&self, peer_caps: &PeerCapabilities) -> Option<AddPathCapability> {
        let local_send = !matches!(self.config.add_path_send, AddPathSend::Disabled);
        let local_receive = self.config.add_path_receive;

        let peer_add_path = peer_caps.add_path.as_ref()?;

        if !local_send && !local_receive {
            return None;
        }

        let mut entries = Vec::new();
        for (afi_safi, peer_mode) in &peer_add_path.entries {
            let can_send = local_send && peer_mode.can_receive();
            let can_recv = local_receive && peer_mode.can_send();

            let mode = AddPathMode::from_flags(can_send, can_recv);

            if let Some(mode) = mode {
                entries.push((*afi_safi, mode));
            }
        }

        if entries.is_empty() {
            None
        } else {
            Some(AddPathCapability { entries })
        }
    }

    /// Send UPDATE message bytes and reset keepalive timer (RFC 4271 requirement)
    pub(super) async fn send_update(&mut self, update_bytes: Vec<u8>) -> Result<(), io::Error> {
        let conn = self
            .conn
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no TCP connection"))?;
        conn.tx.write_all(&update_bytes).await?;
        self.statistics.update_sent += 1;
        // RFC 4271: "Each time the local system sends a KEEPALIVE or UPDATE message,
        // it restarts its KeepaliveTimer, unless the negotiated HoldTime value is zero"
        if self.fsm.timers.hold_time.as_secs() > 0 {
            self.fsm.timers.reset_keepalive_timer();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_notification::CeaseSubcode;
    use crate::bgp::msg_open_types::{BgpCapabiltyCode, Capability, LlgrEntry, OptionalParam};
    use crate::bgp::msg_update::{
        AsPathSegment, AsPathSegmentType, NextHopAddr, Origin, UpdateMessage,
    };
    use crate::bgp::DEFAULT_FORMAT;
    use crate::peer::fsm::BgpState;
    use crate::peer::states::tests::create_test_peer_with_state;
    use crate::rib::{Path, PathAttrs, RouteSource};
    use crate::rpki::vrp::RpkiValidation;
    use conf::bgp::{AfiSafiConfig, LlgrConfig};
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn test_path() -> Path {
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

    #[test]
    fn test_extract_capabilities() {
        let config = PeerConfig {
            afi_safis: vec![
                AfiSafiConfig::new(Afi::Ipv4, Safi::Unicast),
                AfiSafiConfig::new(Afi::Ipv6, Safi::Unicast),
            ],
            ..PeerConfig::default()
        };
        let open_msg = create_open_message(65001, 180, Ipv4Addr::new(1, 1, 1, 1), &config, &None);
        let capabilities = extract_capabilities(&open_msg);

        // Check multiprotocol capabilities
        assert_eq!(capabilities.multiprotocol.len(), 2);
        assert!(capabilities
            .multiprotocol
            .contains(&AfiSafi::new(Afi::Ipv4, Safi::Unicast)));
        assert!(capabilities
            .multiprotocol
            .contains(&AfiSafi::new(Afi::Ipv6, Safi::Unicast)));

        // Check route refresh capability
        assert!(capabilities.route_refresh);

        // Check four-octet ASN capability
        assert_eq!(capabilities.four_octet_asn, Some(65001));

        // Check graceful restart capability (enabled by default)
        assert!(capabilities.graceful_restart.is_some());

        // Check add_path capability (disabled by default)
        assert!(capabilities.add_path.is_none());
    }

    #[test]
    fn test_extract_capabilities_add_path() {
        let ipv4_uni = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        let ipv6_uni = AfiSafi::new(Afi::Ipv6, Safi::Unicast);

        let test_cases = vec![
            ("send", AddPathSend::All, false, AddPathMode::Send),
            ("receive", AddPathSend::Disabled, true, AddPathMode::Receive),
            ("both", AddPathSend::All, true, AddPathMode::Both),
        ];

        for (name, send, receive, expected_mode) in test_cases {
            let config = PeerConfig {
                add_path_send: send,
                add_path_receive: receive,
                afi_safis: vec![
                    AfiSafiConfig::new(Afi::Ipv4, Safi::Unicast),
                    AfiSafiConfig::new(Afi::Ipv6, Safi::Unicast),
                ],
                ..PeerConfig::default()
            };
            let open_msg =
                create_open_message(65001, 180, Ipv4Addr::new(1, 1, 1, 1), &config, &None);
            let caps = extract_capabilities(&open_msg);
            let add_path = caps
                .add_path
                .unwrap_or_else(|| panic!("expected add_path for {}", name));
            assert_eq!(add_path.entries.len(), 2, "{}", name);
            assert!(
                add_path.entries.contains(&(ipv4_uni, expected_mode)),
                "{}",
                name
            );
            assert!(
                add_path.entries.contains(&(ipv6_uni, expected_mode)),
                "{}",
                name
            );
        }
    }

    #[tokio::test]
    async fn test_capability_negotiation_intersection() {
        use std::collections::HashSet;

        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        let ipv4_multicast = AfiSafi::new(Afi::Ipv4, Safi::Multicast);
        let ipv6_unicast = AfiSafi::new(Afi::Ipv6, Safi::Unicast);

        // (local_caps, peer_caps, expected_negotiated)
        let cases = vec![
            (vec![ipv4_unicast], vec![ipv4_unicast], vec![ipv4_unicast]),
            (
                vec![ipv4_unicast],
                vec![ipv4_unicast, ipv4_multicast],
                vec![ipv4_unicast],
            ),
            (vec![ipv4_unicast], vec![ipv6_unicast], vec![]),
            (
                vec![ipv4_unicast, ipv6_unicast],
                vec![ipv4_unicast, ipv6_unicast],
                vec![ipv4_unicast, ipv6_unicast],
            ),
            (
                vec![ipv4_unicast, ipv6_unicast],
                vec![ipv4_unicast],
                vec![ipv4_unicast],
            ),
        ];

        for (local_caps, peer_caps, expected) in cases {
            let local_set: HashSet<_> = local_caps.iter().copied().collect();
            let peer_set: HashSet<_> = peer_caps.iter().copied().collect();
            let negotiated: HashSet<_> = local_set.intersection(&peer_set).copied().collect();
            let expected_set: HashSet<_> = expected.iter().copied().collect();

            assert_eq!(
                negotiated, expected_set,
                "local={:?} peer={:?}",
                local_caps, peer_caps
            );
        }
    }

    #[tokio::test]
    async fn test_local_wins_collision() {
        // Local: bgp_id 1.1.1.1, asn 65000 (from create_test_peer_with_state)
        // (name, remote_bgp_id, remote_asn, local_wins)
        let cases = vec![
            ("higher remote id", Ipv4Addr::new(2, 2, 2, 2), 65001, false),
            ("lower remote id", Ipv4Addr::new(0, 0, 0, 1), 65001, true),
            // RFC 6286: equal IDs tie-break on AS
            (
                "equal id, higher remote asn",
                Ipv4Addr::new(1, 1, 1, 1),
                65001,
                false,
            ),
            (
                "equal id, lower remote asn",
                Ipv4Addr::new(1, 1, 1, 1),
                64999,
                true,
            ),
            (
                "equal id, equal asn",
                Ipv4Addr::new(1, 1, 1, 1),
                65000,
                false,
            ),
        ];

        for (name, remote_id, remote_asn, expected) in cases {
            let peer = create_test_peer_with_state(BgpState::OpenSent).await;
            let open = OpenMessage::new(remote_asn, 180, u32::from(remote_id));
            assert_eq!(peer.local_wins_collision(&open), expected, "{}", name);
        }
    }

    #[test]
    fn test_admin_shutdown_notification() {
        let notif = NotificationMessage::new(
            BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
            Vec::new(),
        );
        let bytes = notif.to_bytes();
        assert_eq!(bytes[0], 6); // Cease error code
        assert_eq!(bytes[1], 2); // AdministrativeShutdown subcode
        assert_eq!(bytes.len(), 2); // No data
    }

    #[tokio::test]
    async fn test_update_rejected_in_non_established_states() {
        // RFC 4271 Section 9: "An UPDATE message may be received only in the Established state.
        // Receiving an UPDATE message in any other state is an error."

        let non_established_states = vec![
            BgpState::Connect,
            BgpState::Active,
            BgpState::OpenSent,
            BgpState::OpenConfirm,
        ];

        for state in non_established_states {
            let mut peer = create_test_peer_with_state(state).await;
            peer.config.send_notification_without_open = true;

            let path = test_path();
            let update = UpdateMessage::new(&path, vec![], DEFAULT_FORMAT);

            let result = peer.handle_message(BgpMessage::Update(update)).await;

            assert!(
                result.is_err(),
                "UPDATE should cause error in {:?} state",
                state
            );
            assert_eq!(
                peer.state(),
                BgpState::Idle,
                "Peer should transition to Idle after UPDATE in {:?}",
                state
            );
            assert_eq!(
                peer.statistics.notification_sent, 1,
                "FSM error NOTIFICATION should be sent in {:?}",
                state
            );
        }
    }

    #[tokio::test]
    async fn test_update_accepted_in_established() {
        // RFC 4271 Section 9: UPDATE is processed normally in Established state

        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.timers.start_hold_timer();

        let path = test_path();
        let update = UpdateMessage::new(&path, vec![], DEFAULT_FORMAT);

        let result = peer.handle_message(BgpMessage::Update(update)).await;

        assert!(
            result.is_ok(),
            "UPDATE should be accepted in Established state"
        );
        assert_eq!(
            peer.state(),
            BgpState::Established,
            "Peer should remain in Established state"
        );
        assert_eq!(
            peer.statistics.notification_sent, 0,
            "No NOTIFICATION should be sent for valid UPDATE"
        );
    }

    #[test]
    fn test_llgr_capability_advertised() {
        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);

        let llgr = Some(LlgrConfig {
            enabled: true,
            stale_time: Some(3600),
            afi_safis: Some(vec![ipv4_unicast]),
        });

        let config = PeerConfig::default();
        // GR is enabled by default
        assert!(config.graceful_restart.enabled);

        let open_msg = create_open_message(65001, 180, Ipv4Addr::new(1, 1, 1, 1), &config, &llgr);

        // Find LLGR capability (code 71) in OPEN
        let has_llgr = open_msg
            .optional_params
            .iter()
            .flat_map(|p| p.capabilities())
            .any(|cap| matches!(cap.code, BgpCapabiltyCode::Llgr));
        assert!(has_llgr, "OPEN should contain LLGR capability (code 71)");

        // Verify it round-trips through extract_capabilities
        let caps = extract_capabilities(&open_msg);
        let llgr = caps.llgr.expect("should have LLGR capability");
        assert_eq!(llgr.entries.len(), 1);
        assert_eq!(llgr.entries[0].afi_safi, ipv4_unicast);
        assert!(!llgr.entries[0].forwarding_preserved);
        assert_eq!(llgr.entries[0].stale_time, 3600);
    }

    /// OPEN message roundtrip: encode -> decode -> extract_capabilities.
    #[test]
    fn test_open_message_roundtrip() {
        let config = PeerConfig {
            afi_safis: vec![
                AfiSafiConfig::new(Afi::Ipv4, Safi::Unicast),
                AfiSafiConfig::new(Afi::Ipv6, Safi::Unicast),
            ],
            ..PeerConfig::default()
        };
        let open_msg =
            create_open_message(4242423930, 180, Ipv4Addr::new(1, 1, 1, 1), &config, &None);

        // Serialize and reparse.
        let bytes = open_msg.to_bytes();
        let parsed = OpenMessage::from_bytes(bytes).expect("encoded OPEN must reparse");

        assert_eq!(parsed.asn, 4242423930, "AS4 must survive roundtrip");
        assert_eq!(parsed.hold_time, open_msg.hold_time);
        assert_eq!(parsed.bgp_identifier, open_msg.bgp_identifier);
        assert_eq!(parsed.optional_params, open_msg.optional_params);

        // Capabilities must survive the roundtrip.
        let caps = extract_capabilities(&parsed);
        assert!(caps
            .multiprotocol
            .contains(&AfiSafi::new(Afi::Ipv4, Safi::Unicast)));
        assert!(caps
            .multiprotocol
            .contains(&AfiSafi::new(Afi::Ipv6, Safi::Unicast)));
        assert!(caps.route_refresh);
        assert!(caps.enhanced_route_refresh);
        assert!(caps.graceful_restart.is_some());
        assert_eq!(caps.four_octet_asn, Some(4242423930));
    }

    /// RFC 5492: "a BGP speaker MUST be prepared to receive an OPEN message
    /// that contains multiple Capabilities Optional Parameters"
    #[test]
    fn test_extract_capabilities_split_params() {
        let open_msg = OpenMessage {
            version: 4,
            asn: 65001,
            hold_time: 180,
            bgp_identifier: u32::from(Ipv4Addr::new(1, 1, 1, 1)),
            optional_params_len: 0,
            optional_params: vec![
                OptionalParam::from_capabilities(vec![Capability::new_multiprotocol(
                    &AfiSafi::new(Afi::Ipv4, Safi::Unicast),
                )]),
                OptionalParam::from_capabilities(vec![Capability::new_route_refresh()]),
                OptionalParam::from_capabilities(vec![Capability::new_four_octet_asn(65001)]),
            ],
        };

        let caps = extract_capabilities(&open_msg);
        assert!(caps
            .multiprotocol
            .contains(&AfiSafi::new(Afi::Ipv4, Safi::Unicast)));
        assert!(caps.route_refresh);
        assert_eq!(caps.four_octet_asn, Some(65001));
    }

    #[test]
    fn test_extract_capabilities_llgr_ignored_without_gr() {
        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);

        // Build an OPEN with LLGR but no GR capability
        let llgr_cap = Capability::new_llgr(&[LlgrEntry {
            afi_safi: ipv4_unicast,
            forwarding_preserved: false,
            stale_time: 3600,
        }]);
        let open_msg = OpenMessage {
            version: 4,
            asn: 65002,
            hold_time: 180,
            bgp_identifier: u32::from(Ipv4Addr::new(2, 2, 2, 2)),
            optional_params_len: 0,
            optional_params: vec![OptionalParam::from_capabilities(vec![llgr_cap])],
        };

        let caps = extract_capabilities(&open_msg);
        assert!(caps.llgr.is_none(), "LLGR should be ignored without GR");
    }

    #[test]
    fn test_extract_capabilities_afi_safis() {
        let ls = AfiSafi::new(Afi::LinkState, Safi::LinkState);
        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        let ipv6_unicast = AfiSafi::new(Afi::Ipv6, Safi::Unicast);

        // Empty afi_safis: implicit IPv4 Unicast default only.
        let config = PeerConfig::default();
        assert!(config.afi_safis.is_empty());
        let open_msg = create_open_message(65001, 180, Ipv4Addr::new(1, 1, 1, 1), &config, &None);
        let caps = extract_capabilities(&open_msg);
        assert_eq!(caps.multiprotocol.len(), 1);
        assert!(caps.multiprotocol.contains(&ipv4_unicast));

        // Explicit list: only configured families are advertised, no implicit defaults.
        let config = PeerConfig {
            afi_safis: vec![
                AfiSafiConfig::new(Afi::Ipv4, Safi::Unicast),
                AfiSafiConfig::new(Afi::Ipv6, Safi::Unicast),
                AfiSafiConfig::new(Afi::LinkState, Safi::LinkState),
            ],
            ..PeerConfig::default()
        };
        let open_msg = create_open_message(65001, 180, Ipv4Addr::new(1, 1, 1, 1), &config, &None);
        let caps = extract_capabilities(&open_msg);
        assert_eq!(caps.multiprotocol.len(), 3);
        assert!(caps.multiprotocol.contains(&ipv4_unicast));
        assert!(caps.multiprotocol.contains(&ipv6_unicast));
        assert!(caps.multiprotocol.contains(&ls));
    }
}
