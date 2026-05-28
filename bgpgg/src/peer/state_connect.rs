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
use super::{Peer, PeerError, PeerOp, TcpConnection};
use crate::bgp::msg_notification::{BgpError, NotificationMessage};
use crate::log::{debug, error, info};
use crate::net::create_and_bind_tcp_socket;
use crate::types::PeerDownReason;
use std::net::SocketAddr;
use std::time::Duration;

const INITIAL_HOLD_TIME: Duration = Duration::from_secs(240);

impl Peer {
    /// Handle Connect state - attempt TCP connection or wait for DelayOpen timer.
    pub(super) async fn handle_connect_state(&mut self) {
        if self.fsm.timers.delay_open_timer_running() {
            self.handle_connect_delay_open_wait().await;
        } else if self.conn.is_some() {
            // Have connection, start DelayOpen or transition to OpenSent
            if self.config.delay_open_time_secs.is_some() {
                self.fsm.timers.start_delay_open_timer();
            } else if let Err(e) = self.process_event(&FsmEvent::TcpConnectionConfirmed).await {
                error!(peer_ip = %self.addr, error = %e, "failed to send OPEN");
                self.disconnect(
                    true,
                    PeerDownReason::LocalNoNotification(FsmEvent::TcpConnectionConfirmed),
                );
            }
        } else {
            // No connection - first check if incoming connection is already queued
            if let Ok(op) = self.peer_rx.try_recv() {
                match op {
                    PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx } => {
                        // Accept incoming connection when no outgoing attempt yet
                        self.accept_connection(tcp_tx, tcp_rx).await;
                        return;
                    }
                    PeerOp::ManualStop => {
                        self.try_process_event(&FsmEvent::ManualStop).await;
                        return;
                    }
                    _ => {}
                }
            }

            // No queued incoming, attempt outgoing TCP connection
            let peer_addr = SocketAddr::new(self.addr, self.port);

            let md5_key = self.config.read_md5_key();
            let ttl_min = self.config.ttl_min;
            let if_index = match self
                .config
                .interface
                .as_ref()
                .map(|iface| crate::net::resolve_interface_index(iface))
            {
                Some(Ok(idx)) => Some(idx),
                Some(Err(err)) => {
                    error!(peer_ip = %self.addr, error = %err,
                        "failed to resolve interface index");
                    self.try_process_event(&FsmEvent::TcpConnectionFails).await;
                    return;
                }
                None => None,
            };
            tokio::select! {
                result = create_and_bind_tcp_socket(self.local_config.addr, peer_addr, md5_key.as_deref(), ttl_min, if_index) => {
                    match result {
                        Ok(stream) => {
                            info!(peer_ip = %self.addr, "TCP connection established");
                            let (rx, tx) = stream.into_split();
                            self.conn = Some(TcpConnection::new(tx, rx));
                            self.fsm.timers.stop_connect_retry();

                            if self.config.delay_open_time_secs.is_some() {
                                self.fsm.timers.start_delay_open_timer();
                            } else if let Err(e) = self.process_event(&FsmEvent::TcpConnectionConfirmed).await {
                                error!(peer_ip = %self.addr, error = %e, "failed to send OPEN");
                                self.disconnect(true, PeerDownReason::LocalNoNotification(FsmEvent::TcpConnectionConfirmed));
                            }
                        }
                        Err(e) => {
                            debug!(peer_ip = %self.addr, error = %e, "TCP connection failed");
                            self.try_process_event(&FsmEvent::TcpConnectionFails).await;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(self.connect_retry_secs)) => {
                    debug!(peer_ip = %self.addr, "ConnectRetryTimer expired");
                    self.try_process_event(&FsmEvent::ConnectRetryTimerExpires).await;
                }
                op = self.peer_rx.recv() => {
                    match op {
                        Some(PeerOp::ManualStop) => {
                            self.try_process_event(&FsmEvent::ManualStop).await;
                        }
                        Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                            // Drop - incoming connections handled by separate peer task
                            drop(tcp_tx);
                            drop(tcp_rx);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Wait for DelayOpen timer in Connect state (RFC 4271 8.2.2).
    /// Monitors both ConnectRetryTimer and DelayOpenTimer.
    async fn handle_connect_delay_open_wait(&mut self) {
        let conn = self.conn.as_mut().expect("connection should exist");
        let mut timer_interval = tokio::time::interval(Duration::from_millis(100));

        tokio::select! {
            result = conn.msg_rx.recv() => {
                self.handle_delay_open_message(result).await;
            }
            _ = timer_interval.tick() => {
                // RFC 4271 8.2.2: Check ConnectRetryTimer first (Event 9 in Connect state)
                if self.fsm.timers.connect_retry_expired() {
                    debug!(peer_ip = %self.addr, "ConnectRetryTimer expired in Connect while DelayOpen running");
                    self.try_process_event(&FsmEvent::ConnectRetryTimerExpires).await;
                } else if self.fsm.timers.delay_open_timer_expired() {
                    debug!(peer_ip = %self.addr, "DelayOpen timer expired");
                    if let Err(e) = self.process_event(&FsmEvent::DelayOpenTimerExpires).await {
                        error!(peer_ip = %self.addr, error = %e, "failed to send OPEN");
                        self.disconnect(true, PeerDownReason::LocalNoNotification(FsmEvent::DelayOpenTimerExpires));
                    }
                }
            }
            op = self.peer_rx.recv() => {
                match op {
                    Some(PeerOp::ManualStop) => {
                        self.try_process_event(&FsmEvent::ManualStop).await;
                    }
                    Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                        // This happens for collision candidates spawned by server
                        // In DelayOpen, we already have a connection, so drop this one
                        debug!(peer_ip = %self.addr, "dropping connection in Connect DelayOpen state");
                        drop(tcp_tx);
                        drop(tcp_rx);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Handle Connect state transitions.
    pub(super) async fn handle_connect_transitions(
        &mut self,
        new_state: BgpState,
        event: &FsmEvent,
    ) -> Result<(), PeerError> {
        match (new_state, event) {
            // RFC 4271 8.2.2: ConnectRetryTimer expires in Connect state
            (BgpState::Connect, FsmEvent::ConnectRetryTimerExpires) => {
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.timers.stop_delay_open_timer();
                self.fsm.timers.start_connect_retry();
            }

            // RFC 4271 8.2.2 Event 18: TcpConnectionFails with DelayOpenTimer running -> Active
            (BgpState::Active, FsmEvent::TcpConnectionFails) => {
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.timers.stop_delay_open_timer();
                self.fsm.timers.start_connect_retry();
            }

            // RFC 4271 8.2.2 Event 18: TcpConnectionFails without DelayOpenTimer -> Idle
            (BgpState::Idle, FsmEvent::TcpConnectionFails) => {
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.timers.stop_connect_retry();
                self.fsm.reset_connect_retry_counter();
            }

            // RFC 4271 Events 21, 22: BGP header/OPEN message errors -> Idle
            (BgpState::Idle, FsmEvent::BgpHeaderErr(ref notif))
            | (BgpState::Idle, FsmEvent::BgpOpenMsgErr(ref notif)) => {
                let _ = self.send_notification(notif.clone()).await;
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.increment_connect_retry_counter();
            }

            // RFC 4271 Event 24: NOTIFICATION with version error -> Idle
            (BgpState::Idle, FsmEvent::NotifMsgVerErr(ref notif)) => {
                self.fsm.timers.stop_connect_retry();
                let delay_open_was_running = self.fsm.timers.delay_open_timer_running();
                self.fsm.timers.stop_delay_open_timer();
                self.disconnect(
                    !delay_open_was_running,
                    PeerDownReason::RemoteNotification(notif.clone()),
                );
                if !delay_open_was_running {
                    self.fsm.increment_connect_retry_counter();
                }
            }

            // RFC 4271 Event 25: NOTIFICATION without version error -> Idle
            (BgpState::Idle, FsmEvent::NotifMsg(ref notif)) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.disconnect(true, PeerDownReason::RemoteNotification(notif.clone()));
                self.fsm.increment_connect_retry_counter();
            }

            // RFC 4271 8.2.2: ManualStop in Connect state
            (BgpState::Idle, FsmEvent::ManualStop) => {
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.manually_stopped = true;
                self.fsm.reset_connect_retry_counter();
                self.fsm.timers.stop_connect_retry();
            }

            // RFC 4271 8.2.2: Events 26-27 (Keepalive, Update) in Connect -> FSM Error
            (BgpState::Idle, FsmEvent::BgpKeepaliveReceived)
            | (BgpState::Idle, FsmEvent::BgpUpdateReceived) => {
                let _ = self
                    .send_notification(NotificationMessage::new(
                        BgpError::FiniteStateMachineError,
                        vec![],
                    ))
                    .await;
                if self.fsm.timers.connect_retry_started.is_some() {
                    self.fsm.timers.stop_connect_retry();
                }
                if self.fsm.timers.delay_open_timer_running() {
                    self.fsm.timers.stop_delay_open_timer();
                }
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.increment_connect_retry_counter();
                return Err(PeerError::FsmError);
            }

            // RFC 4271 8.2.2: Any other events (8, 10-11, 13, 19, 28) in Connect -> Idle
            (BgpState::Idle, FsmEvent::AutomaticStop(_))
            | (BgpState::Idle, FsmEvent::HoldTimerExpires)
            | (BgpState::Idle, FsmEvent::KeepaliveTimerExpires)
            | (BgpState::Idle, FsmEvent::IdleHoldTimerExpires)
            | (BgpState::Idle, FsmEvent::BgpOpenReceived(_))
            | (BgpState::Idle, FsmEvent::BgpUpdateMsgErr(_)) => {
                if self.fsm.timers.connect_retry_started.is_some() {
                    self.fsm.timers.stop_connect_retry();
                }
                if self.fsm.timers.delay_open_timer_running() {
                    self.fsm.timers.stop_delay_open_timer();
                }
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.increment_connect_retry_counter();
            }

            (BgpState::OpenSent, FsmEvent::DelayOpenTimerExpires) => {
                self.fsm.timers.stop_delay_open_timer();
                self.fsm.timers.set_initial_hold_time(INITIAL_HOLD_TIME);
                self.fsm.timers.start_hold_timer();
                self.send_open().await?;
            }

            // Entering OpenSent - send OPEN message
            (BgpState::OpenSent, FsmEvent::TcpConnectionConfirmed) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.set_initial_hold_time(INITIAL_HOLD_TIME);
                self.fsm.timers.start_hold_timer();
                self.send_open().await?;
            }

            // Received OPEN while in Connect with DelayOpen - send OPEN + KEEPALIVE (RFC 4271 Event 20)
            (BgpState::OpenConfirm, FsmEvent::BgpOpenWithDelayOpenTimer(params)) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.send_open().await?;
                self.enter_open_confirm(
                    params.peer_asn,
                    params.peer_hold_time,
                    params.local_asn,
                    params.local_hold_time,
                    params.peer_capabilities.clone(),
                )
                .await?;
            }

            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg_notification::{
        CeaseSubcode, MessageHeaderError, OpenMessageError, UpdateMessageError,
    };
    use crate::peer::states::tests::create_test_peer_with_state;
    use crate::peer::{BgpOpenParams, PeerCapabilities};

    #[tokio::test]
    async fn test_bgp_message_errors_in_connect_active() {
        let cases = vec![
            (
                BgpState::Connect,
                BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
                false,
                0,
            ),
            (
                BgpState::Connect,
                BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber),
                true,
                1,
            ),
        ];

        for (state, error, send_notif, expected_notif) in cases {
            let mut peer = create_test_peer_with_state(state).await;
            peer.fsm.timers.start_connect_retry();
            peer.config.send_notification_without_open = send_notif;
            peer.config.damp_peer_oscillations = true;
            let initial_down_count = peer.consecutive_down_count;
            let notif = NotificationMessage::new(error.clone(), vec![]);
            let event = match error {
                BgpError::MessageHeaderError(_) => FsmEvent::BgpHeaderErr(notif),
                BgpError::OpenMessageError(_) => FsmEvent::BgpOpenMsgErr(notif),
                _ => panic!("unexpected error type"),
            };

            peer.process_event(&event).await.unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.conn.is_none(), "TCP connection should be dropped");
            assert!(
                peer.fsm.timers.connect_retry_started.is_none(),
                "ConnectRetryTimer should be stopped (set to zero)"
            );
            assert!(
                !peer.fsm.timers.delay_open_timer_running(),
                "DelayOpenTimer should be stopped"
            );
            assert_eq!(
                peer.fsm.connect_retry_counter, 1,
                "ConnectRetryCounter should be incremented"
            );
            assert_eq!(peer.statistics.notification_sent, expected_notif);
            assert_eq!(
                peer.consecutive_down_count,
                initial_down_count + 1,
                "DampPeerOscillations should increment consecutive_down_count"
            );
        }
    }

    #[tokio::test]
    async fn test_notification_received_in_connect() {
        use crate::bgp::msg_notification::{
            BgpError, CeaseSubcode, NotificationMessage, OpenMessageError,
        };

        let notif_ver = NotificationMessage::new(
            BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber),
            vec![],
        );
        let notif = NotificationMessage::new(
            BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
            vec![],
        );

        let cases = vec![
            (FsmEvent::NotifMsgVerErr(notif_ver.clone()), true, 0, 0),
            (FsmEvent::NotifMsgVerErr(notif_ver.clone()), false, 1, 1),
            (FsmEvent::NotifMsg(notif.clone()), true, 1, 1),
            (FsmEvent::NotifMsg(notif.clone()), false, 1, 1),
        ];

        for (event, delay_open_running, expected_down_count, expected_counter) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Connect).await;
            peer.fsm.timers.start_connect_retry();
            if delay_open_running {
                peer.fsm.timers.start_delay_open_timer();
            }
            peer.config.damp_peer_oscillations = true;

            peer.process_event(&event).await.unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.conn.is_none());
            assert!(peer.fsm.timers.connect_retry_started.is_none());
            assert!(!peer.fsm.timers.delay_open_timer_running());
            assert_eq!(peer.consecutive_down_count, expected_down_count);
            assert_eq!(peer.fsm.connect_retry_counter, expected_counter);
        }
    }

    #[tokio::test]
    async fn test_connect_retry_expires_in_connect_resets_everything() {
        let mut peer = create_test_peer_with_state(BgpState::Connect).await;

        peer.fsm.timers.start_connect_retry();
        peer.fsm.timers.start_delay_open_timer();

        assert!(peer.conn.is_some(), "Test peer should have connection");
        assert!(peer.fsm.timers.delay_open_timer_running());
        assert!(peer.fsm.timers.connect_retry_started.is_some());

        peer.process_event(&FsmEvent::ConnectRetryTimerExpires)
            .await
            .unwrap();

        assert!(peer.conn.is_none(), "Connection should be dropped");
        assert!(
            !peer.fsm.timers.delay_open_timer_running(),
            "DelayOpenTimer should be stopped"
        );
        assert!(
            peer.fsm.timers.connect_retry_started.is_some(),
            "ConnectRetryTimer should be restarted"
        );
        assert_eq!(peer.state(), BgpState::Connect);
    }

    #[tokio::test]
    async fn test_manual_stop_connect() {
        let mut peer = create_test_peer_with_state(BgpState::Connect).await;
        peer.fsm.connect_retry_counter = 5;
        peer.fsm.timers.start_connect_retry();

        peer.process_event(&FsmEvent::ManualStop).await.unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.manually_stopped);
        assert_eq!(peer.fsm.connect_retry_counter, 0);
        assert!(peer.fsm.timers.connect_retry_started.is_none());
        assert!(peer.conn.is_none());
    }

    #[tokio::test]
    async fn test_tcp_connection_fails_connect() {
        {
            let mut peer = create_test_peer_with_state(BgpState::Connect).await;
            assert!(peer.conn.is_some());

            peer.process_event(&FsmEvent::TcpConnectionFails)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.conn.is_none());
            assert!(peer.fsm.timers.connect_retry_started.is_none());
            assert_eq!(peer.fsm.connect_retry_counter, 0);
        }

        {
            let mut peer = create_test_peer_with_state(BgpState::Connect).await;
            peer.fsm.timers.start_delay_open_timer();
            assert!(peer.conn.is_some());

            peer.process_event(&FsmEvent::TcpConnectionFails)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::Active);
            assert!(peer.conn.is_none());
            assert!(!peer.fsm.timers.delay_open_timer_running());
            assert!(peer.fsm.timers.connect_retry_started.is_some());
        }
    }

    #[tokio::test]
    async fn test_open_received_in_connect_stops_timers() {
        let mut peer = create_test_peer_with_state(BgpState::Connect).await;
        peer.fsm.timers.start_connect_retry();
        peer.fsm.timers.start_delay_open_timer();
        assert!(peer.fsm.timers.connect_retry_started.is_some());
        assert!(peer.fsm.timers.delay_open_timer_running());
        assert_eq!(peer.statistics.open_sent, 0);
        assert_eq!(peer.statistics.keepalive_sent, 0);

        peer.process_event(&FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
            peer_asn: 65001,
            peer_hold_time: 180,
            peer_bgp_id: 0x02020202,
            local_asn: 65000,
            local_hold_time: 180,
            peer_capabilities: PeerCapabilities::default(),
        }))
        .await
        .unwrap();

        assert_eq!(peer.state(), BgpState::OpenConfirm);
        assert!(peer.fsm.timers.connect_retry_started.is_none());
        assert!(!peer.fsm.timers.delay_open_timer_running());
        assert_eq!(peer.statistics.open_sent, 1);
        assert_eq!(peer.statistics.keepalive_sent, 1);
        assert!(peer.fsm.timers.hold_timer_started.is_some());
        assert!(peer.fsm.timers.keepalive_timer_started.is_some());
        assert_eq!(peer.fsm.timers.hold_time.as_secs(), 180);
        assert_eq!(peer.fsm.timers.keepalive_time.as_secs(), 60);
    }

    #[tokio::test]
    async fn test_delay_open_timer_expires_connect() {
        let mut peer = create_test_peer_with_state(BgpState::Connect).await;
        peer.fsm.timers.start_connect_retry();
        peer.fsm.timers.start_delay_open_timer();
        assert_eq!(peer.statistics.open_sent, 0);

        peer.process_event(&FsmEvent::DelayOpenTimerExpires)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::OpenSent);
        assert!(!peer.fsm.timers.delay_open_timer_running());
        assert!(
            peer.fsm.timers.connect_retry_started.is_some(),
            "RFC 4271: ConnectRetryTimer should NOT be stopped in Connect state"
        );
        assert!(peer.fsm.timers.hold_timer_started.is_some());
        assert_eq!(peer.statistics.open_sent, 1);
    }

    #[tokio::test]
    async fn test_tcp_connection_success_connect() {
        let cases = vec![(None, BgpState::OpenSent), (Some(5), BgpState::Connect)];

        for (delay_open, expected_state) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Connect).await;
            peer.fsm.timers.start_connect_retry();
            peer.config.delay_open_time_secs = delay_open;

            if delay_open.is_none() {
                peer.process_event(&FsmEvent::TcpConnectionConfirmed)
                    .await
                    .unwrap();

                assert_eq!(peer.state(), expected_state);
                assert!(peer.fsm.timers.connect_retry_started.is_none());
                assert!(peer.fsm.timers.hold_timer_started.is_some());
                assert_eq!(peer.statistics.open_sent, 1);
            } else {
                peer.fsm.timers.stop_connect_retry();
                peer.fsm.timers.start_delay_open_timer();

                assert_eq!(peer.state(), expected_state);
                assert!(peer.fsm.timers.connect_retry_started.is_none());
                assert!(peer.fsm.timers.delay_open_timer_running());
                assert_eq!(peer.statistics.open_sent, 0);
            }
        }
    }

    #[tokio::test]
    async fn test_connect_other_events() {
        // Events that transition to Idle without FSM error
        let events_no_error = vec![
            FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached),
            FsmEvent::HoldTimerExpires,
            FsmEvent::KeepaliveTimerExpires,
            FsmEvent::IdleHoldTimerExpires,
            FsmEvent::BgpOpenReceived(BgpOpenParams {
                peer_asn: 65001,
                peer_hold_time: 180,
                peer_bgp_id: 0x02020202,
                local_asn: 65000,
                local_hold_time: 180,
                peer_capabilities: PeerCapabilities::default(),
            }),
            FsmEvent::BgpUpdateMsgErr(NotificationMessage::new(
                BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
                vec![],
            )),
        ];

        // RFC 4271 Section 9: Events that cause FSM error (KEEPALIVE, UPDATE in Connect)
        let events_fsm_error = vec![FsmEvent::BgpKeepaliveReceived, FsmEvent::BgpUpdateReceived];

        let cases = vec![(true, true), (false, false)];

        for (start_connect_retry_timer, start_delay_open_timer) in cases {
            // Test events that don't cause FSM error
            for event in &events_no_error {
                let mut peer = create_test_peer_with_state(BgpState::Connect).await;
                if start_connect_retry_timer {
                    peer.fsm.timers.start_connect_retry();
                }
                if start_delay_open_timer {
                    peer.fsm.timers.start_delay_open_timer();
                }
                peer.config.damp_peer_oscillations = true;

                peer.process_event(event).await.unwrap();

                assert_eq!(peer.state(), BgpState::Idle);
                assert!(peer.fsm.timers.connect_retry_started.is_none());
                assert!(peer.fsm.timers.delay_open_timer_started.is_none());
                assert!(peer.conn.is_none());
                assert_eq!(peer.fsm.connect_retry_counter, 1);
                assert_eq!(peer.consecutive_down_count, 1);
            }

            // Test events that cause FSM error
            for event in &events_fsm_error {
                let mut peer = create_test_peer_with_state(BgpState::Connect).await;
                if start_connect_retry_timer {
                    peer.fsm.timers.start_connect_retry();
                }
                if start_delay_open_timer {
                    peer.fsm.timers.start_delay_open_timer();
                }
                peer.config.damp_peer_oscillations = true;
                peer.config.send_notification_without_open = true;

                let result = peer.process_event(event).await;
                assert!(result.is_err(), "FSM error expected for {:?}", event);

                assert_eq!(peer.state(), BgpState::Idle);
                assert!(peer.fsm.timers.connect_retry_started.is_none());
                assert!(peer.fsm.timers.delay_open_timer_started.is_none());
                assert!(peer.conn.is_none());
                assert_eq!(peer.fsm.connect_retry_counter, 1);
                assert_eq!(peer.consecutive_down_count, 1);
                assert_eq!(peer.statistics.notification_sent, 1);
            }
        }
    }
}
