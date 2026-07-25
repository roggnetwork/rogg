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
use super::{Peer, PeerError, PeerOp};
use crate::bgp::msg::Message;
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
use crate::bgp::msg_route_refresh::{RouteRefreshMessage, RouteRefreshSubtype};
use crate::bgp::multiprotocol::AfiSafi;
use crate::log::{debug, error, info, warn};
use crate::types::PeerDownReason;
use std::mem;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

/// Flush pending route buffer immediately when it reaches this size,
/// rather than waiting for the periodic flush timer.
const ROUTE_FLUSH_WATERMARK: usize = 1000;

impl Peer {
    /// Handle Established state transitions.
    pub(super) async fn handle_established_transitions(
        &mut self,
        new_state: BgpState,
        event: &FsmEvent,
    ) -> Result<(), PeerError> {
        match (new_state, event) {
            // RFC 4271 8.2.2: ManualStop in session states
            (BgpState::Idle, FsmEvent::ManualStop) => {
                self.handle_manual_stop().await?;
            }

            // RFC 4271 Event 8: AutomaticStop in session states
            (BgpState::Idle, FsmEvent::AutomaticStop(ref subcode)) => {
                return self.handle_automatic_stop(subcode).await;
            }

            // RFC 4271 Event 10: HoldTimer_Expires in session states
            (BgpState::Idle, FsmEvent::HoldTimerExpires) => {
                self.handle_hold_timer_expires().await?;
            }

            (BgpState::Idle, FsmEvent::BgpUpdateMsgErr(ref notif)) => {
                self.handle_bgp_message_error(notif, true).await?;
                return Err(PeerError::UpdateError);
            }

            // RFC 4271 8.2.2: TcpConnectionFails in Established -> Idle
            (BgpState::Idle, FsmEvent::TcpConnectionFails) => {
                self.transition_to_idle_on_error(PeerDownReason::RemoteNoNotification);
            }

            // RFC 4271 8.2.2: NotifMsg in Established -> Idle
            (BgpState::Idle, FsmEvent::NotifMsg(ref notif))
            | (BgpState::Idle, FsmEvent::NotifMsgVerErr(ref notif)) => {
                self.transition_to_idle_on_error(PeerDownReason::RemoteNotification(notif.clone()));
            }

            (BgpState::Established, FsmEvent::KeepaliveTimerExpires) => {
                self.send_keepalive().await?;
            }

            (BgpState::Established, FsmEvent::BgpKeepaliveReceived)
            | (BgpState::Established, FsmEvent::BgpUpdateReceived) => {
                // RFC 4271: Reset HoldTimer if negotiated HoldTime is non-zero
                if self.fsm.timers.hold_time.as_secs() > 0 {
                    self.fsm.timers.reset_hold_timer();
                }
                if let Some(established_at) = self.established_at {
                    let stability_threshold = self.fsm.timers.hold_time;
                    if established_at.elapsed() >= stability_threshold
                        && self.consecutive_down_count > 0
                    {
                        self.consecutive_down_count = 0;
                        debug!(peer_ip = %self.addr,
                            "reset damping counter after stable connection");
                    }
                }
            }

            // RFC 4271 8.2.2: FSM errors - Events 9, 12-13, 20-22 -> send FSM error NOTIFICATION
            (BgpState::Idle, FsmEvent::ConnectRetryTimerExpires)
            | (BgpState::Idle, FsmEvent::DelayOpenTimerExpires)
            | (BgpState::Idle, FsmEvent::IdleHoldTimerExpires)
            | (BgpState::Idle, FsmEvent::BgpOpenWithDelayOpenTimer(_))
            | (BgpState::Idle, FsmEvent::BgpHeaderErr(_))
            | (BgpState::Idle, FsmEvent::BgpOpenMsgErr(_)) => {
                return self.handle_fsm_error(true).await;
            }

            _ => {}
        }
        Ok(())
    }

    /// Handle Established state with MRAI rate limiting (RFC 4271 9.2.1.1)
    /// Returns true if shutdown requested.
    pub(super) async fn handle_established(&mut self) -> bool {
        let peer_ip = self.addr;

        // Timer interval for hold/keepalive checks
        let mut timer_interval = tokio::time::interval(Duration::from_millis(500));
        // Flush interval for coalescing route updates to the server
        let mut flush_interval = tokio::time::interval(Duration::from_millis(10));
        flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            let has_pending_routes = self.pending_route_count() > 0;
            let conn = match self.conn.as_mut() {
                Some(c) => c,
                None => {
                    // Connection lost, transition back to Idle
                    self.try_process_event(&FsmEvent::TcpConnectionFails).await;
                    return false;
                }
            };

            // Calculate next MRAI send time for pending updates
            let next_send_time = if !self.pending_updates.is_empty() {
                self.last_update_sent.map(|t| t + self.mrai_interval)
            } else {
                None
            };

            let sleep_future = match next_send_time {
                Some(instant) => tokio::time::sleep_until(instant.into()),
                None => tokio::time::sleep(Duration::from_secs(u64::MAX / 2)),
            };

            tokio::select! {
                result = conn.msg_rx.recv() => {
                    match result {
                        Some(Ok(bytes)) => {
                            let format = self.capabilities.receive_format(self.session_type);
                            match Self::parse_bgp_message(&bytes, format) {
                                Ok(message) => {
                                    if let Err(e) = self.handle_received_message(message).await {
                                        error!(peer_ip = %peer_ip, error = %e, "error processing message");
                                        self.disconnect(true, PeerDownReason::RemoteNoNotification);
                                        return false;
                                    }

                                    // Don't wait for the flush timer under heavy load
                                    if self.pending_route_count() >= ROUTE_FLUSH_WATERMARK {
                                        self.flush_pending_routes();
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

                Some(msg) = self.peer_rx.recv() => {
                    match msg {
                        PeerOp::SendUpdate(update_bytes) => {
                            // RFC 4271 9.2.1.1: MRAI rate limiting
                            let can_send = self.mrai_interval.is_zero() ||
                                self.last_update_sent.is_none_or(|t| t.elapsed() >= self.mrai_interval);

                            if can_send {
                                // Send immediately
                                if let Err(e) = self.send_update(update_bytes).await {
                                    error!(peer_ip = %peer_ip, error = %e, "failed to send UPDATE");
                                    self.disconnect(true, PeerDownReason::LocalNoNotification(FsmEvent::BgpUpdateReceived));
                                    return false;
                                }
                                self.last_update_sent = Some(Instant::now());
                            } else {
                                // Queue for later
                                self.pending_updates.push(update_bytes);
                            }
                        }
                        PeerOp::GetStatistics(response) => {
                            let _ = response.send(self.statistics.clone());
                        }
                        PeerOp::SendRouteRefresh { afi, safi, subtype } => {
                            // RFC 2918: Only send if capability was negotiated
                            if !self.capabilities.route_refresh {
                                warn!(peer_ip = %peer_ip,
                                      "cannot send ROUTE_REFRESH: capability not negotiated");
                                continue;
                            }

                            // Validate that the specific AFI/SAFI was negotiated
                            let afi_safi = AfiSafi::new(afi, safi);
                            if !self.capabilities.supports_afi_safi(&afi_safi) {
                                warn!(peer_ip = %peer_ip,
                                      afi = ?afi,
                                      safi = ?safi,
                                      "cannot send ROUTE_REFRESH: AFI/SAFI not negotiated");
                                continue;
                            }

                            // RFC 7313 Section 4: MUST NOT send BoRR before EoR
                            // when Graceful Restart is negotiated.
                            if matches!(subtype, RouteRefreshSubtype::BoRR | RouteRefreshSubtype::EoRR) {
                                let eor_sent = self.gr_state.as_ref()
                                    .is_none_or(|gs| gs.eor_sent.contains(&afi_safi));
                                if !eor_sent {
                                    warn!(peer_ip = %peer_ip, ?afi, ?safi, ?subtype,
                                          "suppressing BoRR/EoRR: EoR not yet sent (RFC 7313)");
                                    continue;
                                }
                            }

                            let refresh_msg = RouteRefreshMessage {
                                afi,
                                safi,
                                subtype,
                            };
                            if let Some(conn) = &mut self.conn {
                                if let Err(e) = conn.tx.write_all(&refresh_msg.serialize()).await {
                                    error!(peer_ip = %peer_ip,
                                           afi = ?afi,
                                           safi = ?safi,
                                           error = %e,
                                           "failed to send ROUTE_REFRESH");
                                } else {
                                    self.statistics.route_refresh_sent += 1;
                                    info!(peer_ip = %peer_ip,
                                          afi = ?afi,
                                          safi = ?safi,
                                          subtype = ?subtype,
                                          "sent ROUTE_REFRESH");
                                }
                            }
                        }
                        PeerOp::GetNegotiatedCapabilities(response) => {
                            let _ = response.send(self.capabilities.clone());
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
                        PeerOp::LocalRibSent { afi_safi } => {
                            debug!(peer_ip = %peer_ip, %afi_safi, "loc-rib sent");

                            if let Some(gr_state) = &mut self.gr_state {
                                gr_state.loc_rib_received.insert(afi_safi, true);

                                // Check if all negotiated AFI/SAFIs have received loc-rib
                                let all_complete = gr_state
                                    .afi_safis
                                    .iter()
                                    .all(|afi_safi| gr_state.loc_rib_received.get(afi_safi).copied().unwrap_or(false));

                                if all_complete {
                                    // Send EOR markers for all negotiated AFI/SAFIs
                                    let afi_safis: Vec<_> = gr_state.afi_safis.iter().copied().collect();
                                    if let Err(e) = self.send_eor_markers(&afi_safis).await {
                                        error!(peer_ip = %peer_ip, error = %e, "failed to send EOR markers");
                                    }
                                }
                            }
                        }
                        PeerOp::ManualStart
                        | PeerOp::ManualStartPassive
                        | PeerOp::AutomaticStart
                        | PeerOp::AutomaticStartPassive
                        | PeerOp::TcpConnectionAccepted { .. }
                        | PeerOp::CollisionLost => {
                            // Ignored when connected
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

                // Flush coalesced route updates to server
                _ = flush_interval.tick(), if has_pending_routes => {
                    self.flush_pending_routes();
                }

                // MRAI timer - send pending updates when timer expires
                _ = sleep_future, if next_send_time.is_some() => {
                    let updates = mem::take(&mut self.pending_updates);
                    for update in updates {
                        if let Err(e) = self.send_update(update).await {
                            error!(peer_ip = %peer_ip, error = %e, "failed to send queued UPDATE");
                            self.disconnect(true, PeerDownReason::LocalNoNotification(FsmEvent::BgpUpdateReceived));
                            return false;
                        }
                    }
                    self.last_update_sent = Some(Instant::now());
                }
            }

            // Check if we transitioned out of Established
            match self.fsm.state() {
                BgpState::Established => {}
                _ => return false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_notification::{
        CeaseSubcode, MessageHeaderError, OpenMessageError, UpdateMessageError,
    };
    use crate::peer::states::tests::create_test_peer_with_state;
    use crate::peer::BgpOpenParams;
    use crate::peer::PeerCapabilities;

    #[tokio::test]
    async fn test_established_ignores_start_events() {
        // RFC 4271 8.2.2: Events 1, 3-7 (Start events) are ignored in Established state
        let start_events = vec![
            FsmEvent::ManualStart,
            FsmEvent::AutomaticStart,
            FsmEvent::ManualStartPassive,
            FsmEvent::AutomaticStartPassive,
        ];

        for event in start_events {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            let initial_counter = peer.fsm.connect_retry_counter;

            peer.process_event(&event).await.unwrap();

            assert_eq!(
                peer.state(),
                BgpState::Established,
                "Start event {:?} should be ignored in Established state",
                event
            );
            assert!(peer.conn.is_some(), "TCP connection should remain");
            assert_eq!(peer.fsm.connect_retry_counter, initial_counter);
            assert!(peer.fsm.timers.hold_timer_started.is_some());
            assert!(peer.fsm.timers.keepalive_timer_started.is_some());
        }
    }

    #[tokio::test]
    async fn test_established_manual_stop() {
        // RFC 4271 8.2.2: ManualStop -> send NOTIFICATION with Cease, -> Idle
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.connect_retry_counter = 5;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        peer.process_event(&FsmEvent::ManualStop).await.unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert_eq!(
            peer.fsm.connect_retry_counter, 0,
            "ConnectRetryCounter should be set to zero"
        );
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
        assert_eq!(
            peer.statistics.notification_sent, 1,
            "NOTIFICATION with Cease should be sent"
        );
        assert!(peer.manually_stopped, "manually_stopped flag should be set");
    }

    #[tokio::test]
    async fn test_established_automatic_stop() {
        // RFC 4271 8.2.2: AutomaticStop -> send NOTIFICATION, -> Idle
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.connect_retry_counter = 2;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        let result = peer
            .process_event(&FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached))
            .await;

        assert!(result.is_err(), "AutomaticStop should return error");
        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 3,
            "ConnectRetryCounter should be incremented"
        );
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
        assert_eq!(
            peer.statistics.notification_sent, 1,
            "NOTIFICATION with Cease should be sent"
        );
    }

    #[tokio::test]
    async fn test_established_hold_timer_expires() {
        // RFC 4271 8.2.2: HoldTimer_Expires -> send NOTIFICATION, -> Idle
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.connect_retry_counter = 1;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        peer.process_event(&FsmEvent::HoldTimerExpires)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert_eq!(
            peer.statistics.notification_sent, 1,
            "NOTIFICATION with HoldTimerExpired should be sent"
        );
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 2,
            "ConnectRetryCounter should be incremented"
        );
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
    }

    #[tokio::test]
    async fn test_established_keepalive_timer_expires() {
        // RFC 4271 8.2.2: KeepaliveTimer_Expires -> send KEEPALIVE, stay Established
        let test_cases = vec![
            (180, true), // (hold_time, should_restart_timer)
            (0, false),  // hold_time=0 should not restart timer
        ];

        for (hold_time, should_restart) in test_cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.fsm.timers.set_negotiated_hold_time(hold_time);
            if hold_time > 0 {
                peer.fsm.timers.start_hold_timer();
                peer.fsm.timers.start_keepalive_timer();
            }
            let initial_keepalive_sent = peer.statistics.keepalive_sent;

            peer.process_event(&FsmEvent::KeepaliveTimerExpires)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Established);
            assert_eq!(
                peer.statistics.keepalive_sent,
                initial_keepalive_sent + 1,
                "KEEPALIVE message should be sent (hold_time={})",
                hold_time
            );
            assert!(peer.conn.is_some(), "TCP connection should remain");

            if should_restart {
                assert!(
                    peer.fsm.timers.keepalive_timer_started.is_some(),
                    "KeepaliveTimer should be restarted when hold_time > 0"
                );
            } else {
                assert!(
                    peer.fsm.timers.keepalive_timer_started.is_none(),
                    "KeepaliveTimer should NOT be restarted when hold_time is zero"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_established_keepalive_received() {
        // RFC 4271 8.2.2: KeepaliveMsg -> reset HoldTimer if non-zero, stay Established
        let test_cases = vec![
            (180, true), // (hold_time, should_reset_hold_timer)
            (0, false),  // hold_time=0 should not reset hold timer
        ];

        for (hold_time, should_reset) in test_cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.fsm.timers.set_negotiated_hold_time(hold_time);
            if hold_time > 0 {
                peer.fsm.timers.start_hold_timer();
                peer.fsm.timers.start_keepalive_timer();
            }
            peer.consecutive_down_count = 3;
            peer.config.damp_peer_oscillations = true;

            // Set established_at to simulate stable connection
            peer.established_at =
                Some(std::time::Instant::now() - std::time::Duration::from_secs(200));

            peer.process_event(&FsmEvent::BgpKeepaliveReceived)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Established);
            assert!(peer.conn.is_some(), "TCP connection should remain");

            if should_reset {
                assert!(
                    peer.fsm.timers.hold_timer_started.is_some(),
                    "Hold timer should be reset when hold_time > 0"
                );
            } else {
                assert!(
                    peer.fsm.timers.hold_timer_started.is_none(),
                    "Hold timer should NOT be reset when hold_time is zero"
                );
            }

            if hold_time > 0 {
                assert_eq!(
                    peer.consecutive_down_count, 0,
                    "Damping counter should be reset after stable connection"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_established_update_received() {
        // RFC 4271 8.2.2: UpdateMsg -> reset HoldTimer if non-zero, stay Established
        let test_cases = vec![
            (180, true), // (hold_time, should_reset_hold_timer)
            (0, false),  // hold_time=0 should not reset hold timer
        ];

        for (hold_time, should_reset) in test_cases {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.fsm.timers.set_negotiated_hold_time(hold_time);
            if hold_time > 0 {
                peer.fsm.timers.start_hold_timer();
                peer.fsm.timers.start_keepalive_timer();
            }

            peer.process_event(&FsmEvent::BgpUpdateReceived)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Established);
            assert!(peer.conn.is_some(), "TCP connection should remain");

            if should_reset {
                assert!(
                    peer.fsm.timers.hold_timer_started.is_some(),
                    "Hold timer should be reset when hold_time > 0"
                );
            } else {
                assert!(
                    peer.fsm.timers.hold_timer_started.is_none(),
                    "Hold timer should NOT be reset when hold_time is zero"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_established_update_msg_error() {
        // RFC 4271 8.2.2: UpdateMsgErr -> send NOTIFICATION, -> Idle
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.connect_retry_counter = 3;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        let notif = NotificationMessage::new(
            BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
            vec![],
        );

        let result = peer.process_event(&FsmEvent::BgpUpdateMsgErr(notif)).await;

        assert!(result.is_err(), "UpdateMsgErr should return error");
        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 4,
            "ConnectRetryCounter should be incremented"
        );
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
        assert_eq!(
            peer.statistics.notification_sent, 1,
            "NOTIFICATION should be sent"
        );
    }

    #[tokio::test]
    async fn test_established_tcp_connection_fails() {
        // RFC 4271 8.2.2: TcpConnectionFails -> Idle (no NOTIFICATION)
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.connect_retry_counter = 2;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();

        // Simulate TCP connection failure by dropping the connection
        peer.conn = None;

        peer.process_event(&FsmEvent::TcpConnectionFails)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 3,
            "ConnectRetryCounter should be incremented"
        );
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
        assert_eq!(
            peer.statistics.notification_sent, 0,
            "No NOTIFICATION should be sent on TCP failure"
        );
    }

    #[tokio::test]
    async fn test_established_notification_received() {
        use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};

        // RFC 4271 8.2.2: NotifMsg -> Idle
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.connect_retry_counter = 1;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();

        let notif = NotificationMessage::new(
            BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
            vec![],
        );
        peer.process_event(&FsmEvent::NotifMsg(notif))
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 2,
            "ConnectRetryCounter should be incremented"
        );
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
    }

    #[tokio::test]
    async fn test_established_fsm_error_connect_retry_timer() {
        // RFC 4271 6.6: Event 9 (ConnectRetryTimerExpires) in Established -> FSM Error
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.connect_retry_counter = 1;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        let result = peer
            .process_event(&FsmEvent::ConnectRetryTimerExpires)
            .await;

        assert!(result.is_err(), "FSM error should return error");
        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 2,
            "ConnectRetryCounter should be incremented"
        );
        assert!(
            peer.fsm.timers.hold_timer_started.is_none(),
            "Hold timer should be stopped"
        );
        assert!(
            peer.fsm.timers.keepalive_timer_started.is_none(),
            "Keepalive timer should be stopped"
        );
        assert_eq!(
            peer.statistics.notification_sent, 1,
            "NOTIFICATION should be sent"
        );
    }

    #[tokio::test]
    async fn test_established_damping_reset_after_stability() {
        // Test that consecutive_down_count is reset after stable connection
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.consecutive_down_count = 5;
        peer.config.damp_peer_oscillations = true;

        // Set established_at to simulate stable connection (longer than hold_time)
        let hold_time = peer.fsm.timers.hold_time;
        peer.established_at =
            Some(std::time::Instant::now() - hold_time - std::time::Duration::from_secs(1));

        peer.process_event(&FsmEvent::BgpKeepaliveReceived)
            .await
            .unwrap();

        assert_eq!(
            peer.consecutive_down_count, 0,
            "Damping counter should be reset after stable connection"
        );
    }

    #[tokio::test]
    async fn test_established_damping_not_reset_before_stability() {
        // Test that consecutive_down_count is NOT reset before stability threshold
        let mut peer = create_test_peer_with_state(BgpState::Established).await;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.consecutive_down_count = 3;
        peer.config.damp_peer_oscillations = true;

        // Set established_at to simulate recent connection (less than hold_time)
        peer.established_at = Some(std::time::Instant::now() - std::time::Duration::from_secs(10));

        peer.process_event(&FsmEvent::BgpKeepaliveReceived)
            .await
            .unwrap();

        assert_eq!(
            peer.consecutive_down_count, 3,
            "Damping counter should NOT be reset before stability threshold"
        );
    }

    #[tokio::test]
    async fn test_established_fsm_errors() {
        // RFC 4271: Events 12-13, 20-22 in Established -> FSM Error
        let events = vec![
            FsmEvent::DelayOpenTimerExpires,
            FsmEvent::IdleHoldTimerExpires,
            FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
                peer_asn: 65001,
                peer_hold_time: 180,
                peer_bgp_id: 0x02020202,
                local_asn: 65000,
                local_hold_time: 180,
                peer_capabilities: PeerCapabilities::default(),
            }),
            FsmEvent::BgpHeaderErr(NotificationMessage::new(
                BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
                vec![],
            )),
            FsmEvent::BgpOpenMsgErr(NotificationMessage::new(
                BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber),
                vec![],
            )),
        ];

        for event in events {
            let mut peer = create_test_peer_with_state(BgpState::Established).await;
            peer.fsm.connect_retry_counter = 3;
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            peer.config.send_notification_without_open = true;

            let result = peer.process_event(&event).await;

            assert!(result.is_err(), "FSM error should return error");
            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.conn.is_none(), "TCP connection should be dropped");
            assert!(
                peer.fsm.timers.connect_retry_started.is_none(),
                "ConnectRetryTimer should be set to zero"
            );
            assert_eq!(
                peer.fsm.connect_retry_counter, 4,
                "ConnectRetryCounter should be incremented"
            );
            assert!(
                peer.fsm.timers.hold_timer_started.is_none(),
                "Hold timer should be stopped"
            );
            assert!(
                peer.fsm.timers.keepalive_timer_started.is_none(),
                "Keepalive timer should be stopped"
            );
            assert_eq!(
                peer.statistics.notification_sent, 1,
                "NOTIFICATION should be sent"
            );
        }
    }
}
