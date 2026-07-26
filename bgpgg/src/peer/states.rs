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

use super::fsm::{BgpState, FsmEvent};
use super::PeerCapabilities;
use super::{Peer, PeerError, PeerOp, TcpConnection};
use crate::bgp::msg::{BgpMessage, Message, PRE_OPEN_FORMAT};
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
use crate::bgp::msg_open::OpenMessage;
use crate::bgp::utils::ParserError;
use crate::log::{debug, error, info};
use crate::metrics;
use crate::server::ops::ServerOp;
use crate::server::AdminState;
use crate::types::PeerDownReason;
use std::time::Duration;
use telemetry::{metric, Unit};
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

impl Peer {
    /// Handle OpenSent and OpenConfirm states
    /// Returns true if shutdown requested.
    pub(super) async fn handle_open_states(&mut self) -> bool {
        let peer_ip = self.addr;

        // Timer interval for hold/keepalive checks
        let mut timer_interval = tokio::time::interval(Duration::from_millis(500));

        loop {
            let conn = match self.conn.as_mut() {
                Some(c) => c,
                None => {
                    // Connection lost, transition back to Idle
                    self.try_process_event(&FsmEvent::TcpConnectionFails).await;
                    return false;
                }
            };
            let pending_rx = self.conn_pending.as_mut().map(|p| &mut p.msg_rx);

            tokio::select! {
                result = conn.msg_rx.recv() => {
                    match result {
                        Some(Ok(bytes)) => {
                            let format = self.capabilities.receive_format(self.session_type);
                            let message_type = bytes[18]; // Type is in header byte 18
                            let body = bytes[19..].to_vec(); // Body starts after header

                            match BgpMessage::from_bytes(message_type, body, &bytes, format) {
                                Ok(message) => {
                                    if self.conn_pending.is_some() {
                                        if let BgpMessage::Open(open) = &message {
                                            // RFC 4271 6.8: resolve the collision on the
                                            // first OPEN from the peer.
                                            if self.local_wins_collision(open) {
                                                info!(peer_ip = %peer_ip, "collision: dialed connection wins, dropping accepted connection");
                                                self.conn_pending = None;
                                            } else {
                                                // The OPEN arrived on the losing connection; discard it.
                                                self.adopt_pending_after_collision_loss(None).await;
                                                continue;
                                            }
                                        } else if matches!(&message, BgpMessage::Notification(_)) {
                                            // Peer closed the connection we dialed (e.g. its
                                            // side of the collision); promote the accepted one.
                                            self.track_received_message(&message);
                                            self.promote_pending_after_conn_loss().await;
                                            continue;
                                        }
                                    }
                                    if let Err(e) = self.handle_received_message(message).await {
                                        error!(peer_ip = %peer_ip, error = %e, "error processing message");
                                        self.disconnect(true, PeerDownReason::RemoteNoNotification);
                                        return false;
                                    }
                                }
                                Err(e) => {
                                    // Parse error - convert to NOTIFICATION if possible
                                    error!(peer_ip = %peer_ip, error = ?e, "error parsing message");
                                    if let Some(notif) = NotificationMessage::from_parser_error(&e) {
                                        let _ = self.send_notification(notif.clone()).await;
                                        self.disconnect(true, PeerDownReason::LocalNotification(notif));
                                    } else {
                                        self.disconnect(true, PeerDownReason::RemoteNoNotification);
                                    }
                                    return false;
                                }
                            }
                        }
                        Some(Err(_)) | None if self.conn_pending.is_some() => {
                            self.promote_pending_after_conn_loss().await;
                        }
                        Some(Err(e)) => {
                            // Header validation error from read task
                            error!(peer_ip = %peer_ip, error = ?e, "error reading message");
                            if let Some(notif) = NotificationMessage::from_parser_error(&e) {
                                let _ = self.send_notification(notif.clone()).await;
                                self.disconnect(true, PeerDownReason::LocalNotification(notif));
                            } else {
                                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                            }
                            return false;
                        }
                        None => {
                            // Read task exited without error - connection failure
                            error!(peer_ip = %peer_ip, "read task exited unexpectedly");
                            self.disconnect(true, PeerDownReason::RemoteNoNotification);
                            return false;
                        }
                    }
                }

                result = async { match pending_rx { Some(rx) => rx.recv().await, None => std::future::pending().await } } => {
                    self.handle_conn_pending_msg(result).await;
                }

                Some(msg) = self.peer_rx.recv() => {
                    match msg {
                        PeerOp::SendUpdate(_) => {
                            // RFC violation: UPDATEs not allowed in OpenSent/OpenConfirm
                            // Drop silently
                        }
                        PeerOp::SendRouteRefresh { .. } => {
                            // ROUTE_REFRESH only allowed in Established state
                            // Drop silently
                        }
                        PeerOp::LocalRibSent { .. } => {
                            // Only relevant in Established state
                            // Drop silently
                        }
                        PeerOp::GetNegotiatedCapabilities(response) => {
                            // Return empty capabilities if not in Established state
                            let _ = response.send(PeerCapabilities::default());
                        }
                        PeerOp::GetStatistics(response) => {
                            let _ = response.send(self.statistics.clone());
                        }
                        PeerOp::HardReset => {
                            info!(peer_ip = %peer_ip, "hard reset requested");

                            // Send CEASE/ADMINISTRATIVE_RESET notification
                            let notif = NotificationMessage::new(
                                BgpError::Cease(CeaseSubcode::AdministrativeReset),
                                Vec::new()
                            );

                            if let Some(conn) = &mut self.conn {
                                if let Err(e) = conn.tx.write_all(&notif.serialize()).await {
                                    error!(peer_ip = %peer_ip, error = %e,
                                          "failed to send hard reset notification");
                                } else {
                                    self.statistics.notification_sent += 1;
                                }
                            }

                            // Close connection and transition to Idle (FSM handles this)
                            self.try_process_event(&FsmEvent::NotifMsgVerErr(notif)).await;

                            // Do NOT return true - keep task alive for reconnection
                            return false;
                        }
                        PeerOp::Shutdown(subcode) => {
                            info!(peer_ip = %peer_ip, "shutdown requested");
                            let notif = NotificationMessage::new(BgpError::Cease(subcode), Vec::new());
                            let _ = self.send_notification(notif).await;
                            return true;
                        }
                        PeerOp::ManualStop => {
                            info!(peer_ip = %peer_ip, "ManualStop received");
                            self.try_process_event(&FsmEvent::ManualStop).await;
                            return false;
                        }
                        PeerOp::ManualStart
                        | PeerOp::ManualStartPassive
                        | PeerOp::AutomaticStart
                        | PeerOp::AutomaticStartPassive => {
                            // Ignored when connected
                        }
                        PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx } => {
                            self.on_conn_accepted(tcp_tx, tcp_rx).await;
                        }
                    }
                }

                _ = timer_interval.tick() => {
                    // Hold timer check
                    if self.fsm.timers.hold_timer_expired() {
                        error!(peer_ip = %peer_ip, "hold timer expired");
                        self.try_process_event(&FsmEvent::HoldTimerExpires).await;
                        return false;
                    }

                    // Keepalive timer check
                    if self.fsm.timers.keepalive_timer_expired() {
                        if let Err(e) = self.process_event(&FsmEvent::KeepaliveTimerExpires).await {
                            error!(peer_ip = %peer_ip, error = %e, "failed to send keepalive");
                            self.disconnect(true, PeerDownReason::LocalNoNotification(FsmEvent::KeepaliveTimerExpires));
                            return false;
                        }
                    }
                }
            }

            // Check if we transitioned out of OpenSent/OpenConfirm
            match self.fsm.state() {
                BgpState::OpenSent | BgpState::OpenConfirm => {}
                _ => return false,
            }
        }
    }

    /// Handle received NOTIFICATION and generate appropriate event (Event 24 or 25).
    /// Bookkeeping (stats, metric, RFC 5492 suppression) is done by
    /// track_received_message; callers run that first.
    pub(super) async fn handle_notification_received(&mut self, notif: &NotificationMessage) {
        let event = if notif.is_version_error() {
            debug!(peer_ip = %self.addr, "NOTIFICATION with version error received");
            FsmEvent::NotifMsgVerErr(notif.clone())
        } else {
            debug!(peer_ip = %self.addr, "NOTIFICATION received");
            FsmEvent::NotifMsg(notif.clone())
        };
        self.try_process_event(&event).await;
    }

    /// An inbound connection was forwarded by the server. One policy for
    /// every FSM state; returns true if the state changed and the caller's
    /// state loop must re-enter the run loop.
    pub(super) async fn on_conn_accepted(
        &mut self,
        tcp_tx: OwnedWriteHalf,
        tcp_rx: OwnedReadHalf,
    ) -> bool {
        match self.fsm.state() {
            BgpState::Idle => {
                let auto_restart = self.get_idle_hold_time().is_some() && !self.manually_stopped;
                if !auto_restart {
                    // RFC 4271 8.2.2: refuse inbound while held down
                    // (admin down, manual stop, auto-start disabled)
                    debug!(peer_ip = %self.addr, "connection refused in Idle state");
                    return false;
                }
                // Deviation from RFC 4271 8.2.2 (refuse all inbound in
                // Idle): the peer's dial triggers the auto-restart early
                // instead of being refused for the rest of the idle hold.
                debug!(peer_ip = %self.addr, "accepting connection in Idle, restarting");
                self.conn = Some(TcpConnection::new(tcp_tx, tcp_rx));
                self.conn_dialed = false;
                let event = if self.config.passive_mode {
                    FsmEvent::AutomaticStartPassive
                } else {
                    FsmEvent::AutomaticStart
                };
                self.try_process_event(&event).await;
                true
            }
            BgpState::Connect | BgpState::Active if self.conn.is_none() => {
                debug!(peer_ip = %self.addr, "TcpConnectionAccepted");
                self.conn = Some(TcpConnection::new(tcp_tx, tcp_rx));
                self.conn_dialed = false;
                self.connection_ready().await;
                true
            }
            BgpState::Connect | BgpState::Active | BgpState::OpenSent
                if self.conn_dialed && self.conn_pending.is_none() =>
            {
                // RFC 4271 6.8: hold as the collision candidate; the peer's
                // first OPEN resolves it.
                debug!(peer_ip = %self.addr, "collision: holding accepted connection");
                self.conn_pending = Some(TcpConnection::new(tcp_tx, tcp_rx));
                false
            }
            BgpState::Connect | BgpState::Active | BgpState::OpenSent | BgpState::OpenConfirm => {
                // Candidate already held, primary is itself accepted, or past
                // the collision window (OpenConfirm)
                debug!(peer_ip = %self.addr, "dropping accepted connection");
                false
            }
            BgpState::Established => {
                let gr_negotiated = self
                    .capabilities
                    .graceful_restart
                    .as_ref()
                    .is_some_and(|gr| !gr.afi_safi_list.is_empty());
                if !gr_negotiated {
                    info!(peer_ip = %self.addr, "rejecting connection: session established without GR");
                    Self::reject_connection(tcp_tx, tcp_rx);
                    return false;
                }
                // RFC 4724: reconnect from a restarting peer. Drop the old
                // session without NOTIFICATION so routes are preserved,
                // adopt the new connection.
                info!(peer_ip = %self.addr, "GR reconnection: adopting new connection");
                self.disconnect(false, PeerDownReason::RemoteNoNotification);
                // Established + TcpConnectionConfirmed with GR -> Connect;
                // the attached connection goes straight to OPEN there.
                self.try_process_event(&FsmEvent::TcpConnectionConfirmed)
                    .await;
                self.conn = Some(TcpConnection::new(tcp_tx, tcp_rx));
                self.conn_dialed = false;
                true
            }
        }
    }

    /// Make the pending accepted connection the primary. Returns false if
    /// none is held.
    fn replace_conn_with_pending(&mut self) -> bool {
        let Some(pending) = self.conn_pending.take() else {
            return false;
        };
        self.conn = Some(pending);
        self.conn_dialed = false;
        true
    }

    /// The dialed connection died while an accepted connection is held:
    /// continue the handshake on the accepted connection. Returns false if
    /// none is held.
    pub(super) async fn promote_pending_after_conn_loss(&mut self) -> bool {
        if !self.replace_conn_with_pending() {
            return false;
        }
        info!(peer_ip = %self.addr, "dialed connection lost, promoting accepted connection");
        if self.fsm.timers.delay_open_timer_running() {
            self.fsm.timers.stop_delay_open_timer();
            self.connection_ready().await;
        } else if let Err(e) = self.send_open().await {
            error!(peer_ip = %self.addr, error = %e, "failed to send OPEN on promoted connection");
            self.disconnect(
                true,
                PeerDownReason::LocalNoNotification(FsmEvent::TcpConnectionFails),
            );
        }
        true
    }

    /// The accepted connection won the collision (RFC 4271 6.8): close the
    /// dialed connection and continue on the accepted one. `open` is the
    /// peer's OPEN when it arrived on the accepted connection (processed on
    /// it); None when it arrived on the losing dialed connection (discarded).
    pub(super) async fn adopt_pending_after_collision_loss(&mut self, open: Option<OpenMessage>) {
        info!(peer_ip = %self.addr, "collision: accepted connection wins, closing dialed connection");
        let delay_open = self.fsm.timers.delay_open_timer_running();
        if !delay_open {
            // An OPEN went out on the dialed connection; close it with Cease.
            // With DelayOpen no OPEN was sent, so it closes silently.
            let notif = NotificationMessage::new(
                BgpError::Cease(CeaseSubcode::ConnectionCollisionResolution),
                vec![],
            );
            let _ = self.send_notification(notif).await;
        }
        if !self.replace_conn_with_pending() {
            return;
        }
        if delay_open {
            match open {
                Some(open) => self.process_delay_open(open).await,
                None => {
                    self.fsm.timers.stop_delay_open_timer();
                    // Restarts DelayOpen on the adopted connection
                    self.connection_ready().await;
                }
            }
        } else {
            if let Err(e) = self.send_open().await {
                error!(peer_ip = %self.addr, error = %e, "failed to send OPEN on promoted connection");
                self.disconnect(
                    true,
                    PeerDownReason::LocalNoNotification(FsmEvent::TcpConnectionFails),
                );
                return;
            }
            if let Some(open) = open {
                if let Err(e) = self.handle_received_message(BgpMessage::Open(open)).await {
                    error!(peer_ip = %self.addr, error = %e, "error processing OPEN on promoted connection");
                    self.disconnect(true, PeerDownReason::RemoteNoNotification);
                }
            }
        }
    }

    /// Handle a message on the pending (accepted) connection. The peer's
    /// OPEN resolves the collision (RFC 4271 6.8); anything else drops the
    /// candidate.
    pub(super) async fn handle_conn_pending_msg(
        &mut self,
        result: Option<Result<Vec<u8>, ParserError>>,
    ) {
        match result {
            Some(Ok(bytes)) => match Self::parse_bgp_message(&bytes, PRE_OPEN_FORMAT) {
                Ok(BgpMessage::Open(open)) => {
                    if self.local_wins_collision(&open) {
                        info!(peer_ip = %self.addr, "collision: dialed connection wins, dropping accepted connection");
                        self.conn_pending = None;
                    } else {
                        self.adopt_pending_after_collision_loss(Some(open)).await;
                    }
                }
                Ok(_) | Err(_) => {
                    debug!(peer_ip = %self.addr, "dropping accepted connection: unexpected message before OPEN");
                    self.conn_pending = None;
                }
            },
            Some(Err(_)) | None => {
                debug!(peer_ip = %self.addr, "accepted connection closed");
                self.conn_pending = None;
            }
        }
    }

    /// Reject an accepted connection: send Cease/ConnectionRejected and close.
    /// Runs in a background task to avoid blocking the peer loop on the write.
    pub(super) fn reject_connection(mut tcp_tx: OwnedWriteHalf, tcp_rx: OwnedReadHalf) {
        tokio::spawn(async move {
            let notif =
                NotificationMessage::new(BgpError::Cease(CeaseSubcode::ConnectionRejected), vec![]);
            let _ = tcp_tx.write_all(&notif.serialize()).await;
            drop(tcp_rx);
        });
    }

    /// A TCP connection is in place (accepted, dialed, or attached at spawn):
    /// stop ConnectRetryTimer, then start DelayOpen or send OPEN.
    pub(super) async fn connection_ready(&mut self) {
        self.fsm.timers.stop_connect_retry();
        if self.config.delay_open_time_secs.is_some() {
            self.fsm.timers.start_delay_open_timer();
        } else if let Err(e) = self.process_event(&FsmEvent::TcpConnectionConfirmed).await {
            error!(peer_ip = %self.addr, error = %e, "failed to send OPEN");
            self.disconnect(
                true,
                PeerDownReason::LocalNoNotification(FsmEvent::TcpConnectionConfirmed),
            );
        }
    }

    /// Process FSM event, transition state, and execute associated actions.
    pub(super) async fn process_event(&mut self, event: &FsmEvent) -> Result<(), PeerError> {
        let old_state = self.fsm.state();
        let new_state = self.fsm.handle_event(event);

        // Dispatch to state-specific transition handlers
        match old_state {
            BgpState::Idle => self.handle_idle_transitions(new_state, event).await?,
            BgpState::Connect => self.handle_connect_transitions(new_state, event).await?,
            BgpState::Active => self.handle_active_transitions(new_state, event).await?,
            BgpState::OpenSent => self.handle_opensent_transitions(new_state, event).await?,
            BgpState::OpenConfirm => {
                self.handle_openconfirm_transitions(new_state, event)
                    .await?
            }
            BgpState::Established => {
                self.handle_established_transitions(new_state, event)
                    .await?
            }
        }

        // Notify server of state change after all actions complete
        if old_state != new_state {
            self.notify_state_change();
        }

        Ok(())
    }

    /// Process FSM event and log any errors.
    pub(super) async fn try_process_event(&mut self, event: &FsmEvent) {
        if let Err(e) = self.process_event(event).await {
            error!(peer_ip = %self.addr,
                event = ?event,
                error = %e,
                "failed to process event");
        }
    }

    /// Stop session timers (hold timer and keepalive timer)
    pub(super) fn stop_session_timers(&mut self) {
        self.fsm.timers.stop_hold_timer();
        self.fsm.timers.stop_keepalive_timer();
    }

    /// Transition to Idle on error - increments retry counter and stops all timers
    pub(super) fn transition_to_idle_on_error(&mut self, reason: PeerDownReason) {
        self.disconnect(true, reason);
        self.fsm.timers.stop_connect_retry();
        self.fsm.increment_connect_retry_counter();
        self.stop_session_timers();
    }

    /// Handle ManualStop event - sends admin shutdown notification and transitions to Idle
    pub(super) async fn handle_manual_stop(&mut self) -> Result<(), PeerError> {
        self.manually_stopped = true;
        let notif = NotificationMessage::new(
            BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
            Vec::new(),
        );
        let _ = self.send_notification(notif.clone()).await;
        self.disconnect(true, PeerDownReason::LocalNotification(notif));
        self.fsm.timers.stop_connect_retry();
        self.fsm.reset_connect_retry_counter();
        self.stop_session_timers();
        Ok(())
    }

    /// Handle AutomaticStop event - sends cease notification and transitions to Idle
    pub(super) async fn handle_automatic_stop(
        &mut self,
        subcode: &CeaseSubcode,
    ) -> Result<(), PeerError> {
        let notif = NotificationMessage::new(BgpError::Cease(subcode.clone()), Vec::new());
        let _ = self.send_notification(notif.clone()).await;
        self.disconnect(true, PeerDownReason::LocalNotification(notif));
        self.fsm.timers.stop_connect_retry();
        self.fsm.increment_connect_retry_counter();
        self.stop_session_timers();

        let admin_state = match subcode {
            CeaseSubcode::MaxPrefixesReached => AdminState::PrefixLimitReached,
            _ => AdminState::Down,
        };
        let _ = self.server_tx.send(ServerOp::SetAdminState {
            peer_ip: self.addr,
            state: admin_state,
        });
        Err(PeerError::AutomaticStop(subcode.clone()))
    }

    /// Handle HoldTimer expiration - sends hold timer expired notification and transitions to Idle
    pub(super) async fn handle_hold_timer_expires(&mut self) -> Result<(), PeerError> {
        metric(
            metrics::HOLD_TIMER_EXPIRED_COUNT,
            1,
            Unit::Count,
            &[("Peer", &self.addr)],
            &[&["Peer"]],
            &[],
        );
        let notif = NotificationMessage::new(BgpError::HoldTimerExpired, vec![]);
        let _ = self.send_notification(notif.clone()).await;
        self.disconnect(true, PeerDownReason::LocalNotification(notif));
        self.fsm.timers.stop_connect_retry();
        self.fsm.increment_connect_retry_counter();
        self.stop_session_timers();
        Ok(())
    }

    /// Handle BGP message error (header or open message) - sends notification and transitions to Idle
    pub(super) async fn handle_bgp_message_error(
        &mut self,
        notif: &NotificationMessage,
        in_session_state: bool,
    ) -> Result<(), PeerError> {
        let _ = self.send_notification(notif.clone()).await;
        self.disconnect(true, PeerDownReason::LocalNotification(notif.clone()));
        self.fsm.timers.stop_connect_retry();
        self.fsm.increment_connect_retry_counter();
        if in_session_state {
            self.stop_session_timers();
        }
        Ok(())
    }

    /// Handle FSM error - sends FSM error notification and transitions to Idle
    pub(super) async fn handle_fsm_error(&mut self, in_session: bool) -> Result<(), PeerError> {
        let notif = NotificationMessage::new(BgpError::FiniteStateMachineError, vec![]);
        let _ = self.send_notification(notif.clone()).await;
        self.disconnect(true, PeerDownReason::LocalNotification(notif));
        self.fsm.timers.stop_connect_retry();
        self.fsm.increment_connect_retry_counter();
        if in_session {
            self.stop_session_timers();
        }
        Err(PeerError::FsmError)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::bgp::msg_notification::{BgpError, CeaseSubcode, UpdateMessageError};
    use crate::peer::BgpOpenParams;
    use crate::peer::{BgpState, Fsm, LocalConfig, PeerStatistics, SessionType};
    use conf::bgp::PeerConfig;
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    pub(crate) async fn create_test_peer_with_state(state: BgpState) -> Peer {
        // Create a test TCP connection
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn task to accept connection and drain data
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (mut rx, _tx) = stream.into_split();
                let mut buf = vec![0u8; 4096];
                while rx.read(&mut buf).await.is_ok() {}
            }
        });

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (tcp_rx, tcp_tx) = client.into_split();

        // Create dummy channels for testing
        let (server_tx, _server_rx) = mpsc::unbounded_channel();
        let (_peer_tx, peer_rx) = mpsc::unbounded_channel();

        // Create peer directly for testing
        let local_ip = crate::net::ipv4(127, 0, 0, 1);
        let local_config = LocalConfig {
            asn: 65000,
            bgp_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
            hold_time: 180,
            addr: SocketAddr::new(local_ip, 0),
            cluster_id: std::net::Ipv4Addr::new(1, 1, 1, 1),
            llgr: None,
        };
        Peer {
            addr: addr.ip(),
            port: addr.port(),
            fsm: Fsm::with_state(state, false),
            convergence_reported: HashSet::new(),
            conn: Some(TcpConnection::new(tcp_tx, tcp_rx)),
            conn_pending: None,
            conn_dialed: false,
            asn: Some(65001),
            bgp_id: Some(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            session_type: Some(SessionType::Ebgp),
            statistics: PeerStatistics::default(),
            config: PeerConfig::default(),
            peer_rx,
            server_tx,
            local_config,
            connect_retry_secs: 120,
            consecutive_down_count: 0,
            capabilities_suppressed: false,
            manually_stopped: false,
            established_at: None,
            mrai_interval: Duration::from_secs(0),
            last_update_sent: None,
            pending_updates: Vec::new(),
            sent_open: None,
            received_open: None,
            capabilities: PeerCapabilities::default(),
            gr_state: None,
            pending_routes: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_state() {
        let peer = create_test_peer_with_state(BgpState::Idle).await;
        assert_eq!(peer.state(), BgpState::Idle);

        let peer = create_test_peer_with_state(BgpState::Connect).await;
        assert_eq!(peer.state(), BgpState::Connect);

        let peer = create_test_peer_with_state(BgpState::Established).await;
        assert_eq!(peer.state(), BgpState::Established);
    }

    #[tokio::test]
    async fn test_manual_stop_session_states() {
        let test_cases = vec![
            BgpState::OpenSent,
            BgpState::OpenConfirm,
            BgpState::Established,
        ];

        for state in test_cases {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.connect_retry_counter = 5;
            peer.fsm.timers.start_connect_retry();
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();

            peer.process_event(&FsmEvent::ManualStop).await.unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.manually_stopped);
            assert!(peer.conn.is_none());
            assert_eq!(
                peer.fsm.connect_retry_counter, 0,
                "ConnectRetryCounter should be reset to 0"
            );
            assert!(
                peer.fsm.timers.connect_retry_started.is_none(),
                "ConnectRetryTimer should be stopped"
            );
            assert!(peer.fsm.timers.hold_timer_started.is_none());
            assert!(peer.fsm.timers.keepalive_timer_started.is_none());
        }
    }

    #[tokio::test]
    async fn test_update_msg_err_in_session_states() {
        // RFC 4271 Event 28: UpdateMsgErr in session states should send NOTIFICATION
        for state in [
            BgpState::OpenSent,
            BgpState::OpenConfirm,
            BgpState::Established,
        ] {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            peer.config.send_notification_without_open = true;

            let notif = NotificationMessage::new(
                BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
                vec![],
            );

            // Process the event - should send NOTIFICATION and transition to Idle
            peer.process_event(&FsmEvent::BgpUpdateMsgErr(notif.clone()))
                .await
                .unwrap_err(); // Should return error

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.fsm.timers.hold_timer_started.is_none());
            assert!(peer.fsm.timers.keepalive_timer_started.is_none());
            assert!(peer.conn.is_none());
            // Verify notification was sent (check statistics)
            assert_eq!(peer.statistics.notification_sent, 1);
        }
    }

    #[tokio::test]
    async fn test_automatic_stop_in_session_states() {
        for state in [
            BgpState::OpenSent,
            BgpState::OpenConfirm,
            BgpState::Established,
        ] {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.connect_retry_counter = 2;
            peer.fsm.timers.start_connect_retry();
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            peer.statistics.open_sent = 1;

            let result = peer
                .process_event(&FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached))
                .await;
            assert!(result.is_err(), "AutomaticStop should return error");

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(
                peer.fsm.timers.connect_retry_started.is_none(),
                "ConnectRetryTimer should be set to zero"
            );
            assert_eq!(
                peer.fsm.connect_retry_counter, 3,
                "ConnectRetryCounter should be incremented"
            );
            assert!(peer.conn.is_none(), "TCP connection should be dropped");
            assert!(peer.fsm.timers.hold_timer_started.is_none());
            assert!(peer.fsm.timers.keepalive_timer_started.is_none());
            assert_eq!(
                peer.statistics.notification_sent, 1,
                "NOTIFICATION with Cease should be sent"
            );
        }
    }

    #[tokio::test]
    async fn test_hold_timer_expires_in_session_states() {
        for state in [
            BgpState::OpenSent,
            BgpState::OpenConfirm,
            BgpState::Established,
        ] {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.connect_retry_counter = 1;
            peer.fsm.timers.start_connect_retry();
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            peer.statistics.open_sent = 1;

            peer.process_event(&FsmEvent::HoldTimerExpires)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(
                peer.fsm.timers.connect_retry_started.is_none(),
                "ConnectRetryTimer should be set to zero"
            );
            assert_eq!(
                peer.fsm.connect_retry_counter, 2,
                "ConnectRetryCounter should be incremented"
            );
            assert!(peer.conn.is_none(), "TCP connection should be dropped");
            assert!(peer.fsm.timers.hold_timer_started.is_none());
            assert!(peer.fsm.timers.keepalive_timer_started.is_none());
            assert_eq!(
                peer.statistics.notification_sent, 1,
                "NOTIFICATION with HoldTimerExpired should be sent"
            );
        }
    }

    #[tokio::test]
    async fn test_open_received_hold_time_zero() {
        // RFC 4271 8.2.2: When hold time is zero, timers should not be started
        let mut peer = create_test_peer_with_state(BgpState::Connect).await;

        peer.process_event(&FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
            peer_asn: 65001,
            peer_hold_time: 0, // Peer wants no hold timer
            peer_bgp_id: 0x02020202,
            local_asn: 65000,
            local_hold_time: 180,
            peer_capabilities: PeerCapabilities::default(),
        }))
        .await
        .unwrap();

        // Verify state transition
        assert_eq!(peer.state(), BgpState::OpenConfirm);
        // Verify hold time negotiated to zero (min of 0 and 180)
        assert_eq!(peer.fsm.timers.hold_time.as_secs(), 0);
        assert_eq!(peer.fsm.timers.keepalive_time.as_secs(), 0);
        // Verify timers are NOT started when hold_time is zero
        assert!(peer.fsm.timers.hold_timer_started.is_none());
        assert!(peer.fsm.timers.keepalive_timer_started.is_none());
        // Verify KEEPALIVE was still sent (RFC requires it)
        assert_eq!(peer.statistics.keepalive_sent, 1);
    }
}
