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
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
use crate::log::{debug, error};
use crate::types::PeerDownReason;
use std::time::Duration;

const INITIAL_HOLD_TIME: Duration = Duration::from_secs(240);

impl Peer {
    /// Handle Active state - listen for incoming connections.
    pub(super) async fn handle_active_state(&mut self) {
        if self.fsm.timers.delay_open_timer_running() {
            self.handle_active_delay_open_wait().await;
        } else {
            let retry_time = Duration::from_secs(self.connect_retry_secs);

            tokio::select! {
                _ = tokio::time::sleep(retry_time) => {
                    debug!(peer_ip = %self.addr, "ConnectRetryTimer expired in Active");
                    self.try_process_event(&FsmEvent::ConnectRetryTimerExpires).await;
                }
                op = self.peer_rx.recv() => {
                    match op {
                        Some(PeerOp::ManualStop) => {
                            self.try_process_event(&FsmEvent::ManualStop).await;
                        }
                        Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                            self.accept_connection(tcp_tx, tcp_rx).await;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Wait for DelayOpen timer in Active state (RFC 4271 8.2.2).
    /// Does not monitor ConnectRetryTimer.
    async fn handle_active_delay_open_wait(&mut self) {
        let conn = self.conn.as_mut().expect("connection should exist");
        let mut timer_interval = tokio::time::interval(Duration::from_millis(100));

        tokio::select! {
            result = conn.msg_rx.recv() => {
                self.handle_delay_open_message(result).await;
            }
            _ = timer_interval.tick() => {
                if self.fsm.timers.delay_open_timer_expired() {
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
                        debug!(peer_ip = %self.addr, "closing duplicate incoming connection");
                        drop(tcp_tx);
                        drop(tcp_rx);
                    }
                    _ => {}
                }
            }
        }
    }

    /// Handle Active state transitions.
    pub(super) async fn handle_active_transitions(
        &mut self,
        new_state: BgpState,
        event: &FsmEvent,
    ) -> Result<(), PeerError> {
        match (new_state, event) {
            // RFC 4271 8.2.2: ConnectRetryTimer expires in Active state
            (BgpState::Connect, FsmEvent::ConnectRetryTimerExpires) => {
                self.fsm.timers.start_connect_retry();
            }

            // RFC 4271 8.2.2 Event 18: TcpConnectionFails in Active -> Idle
            (BgpState::Idle, FsmEvent::TcpConnectionFails) => {
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.timers.stop_delay_open_timer();
                self.fsm.timers.start_connect_retry();
                self.fsm.increment_connect_retry_counter();
            }

            // RFC 4271 Events 21, 22: BGP header/OPEN message errors -> Idle (shared with Connect)
            (BgpState::Idle, FsmEvent::BgpHeaderErr(ref notif))
            | (BgpState::Idle, FsmEvent::BgpOpenMsgErr(ref notif)) => {
                let _ = self.send_notification(notif.clone()).await;
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.increment_connect_retry_counter();
            }

            // RFC 4271 Event 24: NOTIFICATION with version error -> Idle (shared with Connect)
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

            // RFC 4271 Event 25: NOTIFICATION without version error -> Idle (shared with Connect)
            (BgpState::Idle, FsmEvent::NotifMsg(ref notif)) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.disconnect(true, PeerDownReason::RemoteNotification(notif.clone()));
                self.fsm.increment_connect_retry_counter();
            }

            // RFC 4271 8.2.2: Events 26-27 (Keepalive, Update) in Active -> FSM Error
            (BgpState::Idle, FsmEvent::BgpKeepaliveReceived)
            | (BgpState::Idle, FsmEvent::BgpUpdateReceived) => {
                let _ = self
                    .send_notification(NotificationMessage::new(
                        BgpError::FiniteStateMachineError,
                        vec![],
                    ))
                    .await;
                self.fsm.timers.stop_connect_retry();
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.increment_connect_retry_counter();
                return Err(PeerError::FsmError);
            }

            // RFC 4271 8.2.2: Any other events (8, 10-11, 13, 19, 28) in Active -> Idle
            (BgpState::Idle, FsmEvent::AutomaticStop(_))
            | (BgpState::Idle, FsmEvent::HoldTimerExpires)
            | (BgpState::Idle, FsmEvent::KeepaliveTimerExpires)
            | (BgpState::Idle, FsmEvent::IdleHoldTimerExpires)
            | (BgpState::Idle, FsmEvent::BgpOpenReceived(_))
            | (BgpState::Idle, FsmEvent::BgpUpdateMsgErr(_)) => {
                self.fsm.timers.stop_connect_retry();
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.increment_connect_retry_counter();
            }

            // RFC 4271 8.2.2: ManualStop in Active state
            (BgpState::Idle, FsmEvent::ManualStop) => {
                if self.fsm.timers.delay_open_timer_running()
                    && self.config.send_notification_without_open
                {
                    let notif = NotificationMessage::new(
                        BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
                        Vec::new(),
                    );
                    let _ = self.send_notification(notif).await;
                }
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.manually_stopped = true;
                self.fsm.reset_connect_retry_counter();
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
            }

            (BgpState::OpenSent, FsmEvent::DelayOpenTimerExpires) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.stop_delay_open_timer();
                self.fsm.timers.set_initial_hold_time(INITIAL_HOLD_TIME);
                self.fsm.timers.start_hold_timer();
                self.send_open().await?;
            }

            // Entering OpenSent - send OPEN message (shared with Connect)
            (BgpState::OpenSent, FsmEvent::TcpConnectionConfirmed) => {
                self.fsm.timers.stop_connect_retry();
                self.fsm.timers.set_initial_hold_time(INITIAL_HOLD_TIME);
                self.fsm.timers.start_hold_timer();
                self.send_open().await?;
            }

            // Received OPEN while in Active with DelayOpen - send OPEN + KEEPALIVE (RFC 4271 Event 20)
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
    use crate::peer::states::tests::create_test_peer_with_state;
    use crate::peer::{BgpOpenParams, PeerCapabilities};

    #[tokio::test]
    async fn test_manual_stop_active() {
        let cases = vec![
            (true, true, 1),
            (true, false, 0),
            (false, true, 0),
            (false, false, 0),
        ];

        for (delay_open_running, send_notif_config, expected_notif) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Active).await;
            peer.fsm.connect_retry_counter = 3;
            peer.fsm.timers.start_connect_retry();
            peer.config.send_notification_without_open = send_notif_config;

            if delay_open_running {
                peer.fsm.timers.start_delay_open_timer();
            }

            peer.process_event(&FsmEvent::ManualStop).await.unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.manually_stopped);
            assert_eq!(peer.fsm.connect_retry_counter, 0);
            assert!(peer.fsm.timers.connect_retry_started.is_none());
            assert!(peer.fsm.timers.delay_open_timer_started.is_none());
            assert!(peer.conn.is_none());
            assert_eq!(peer.statistics.notification_sent, expected_notif);
        }
    }

    #[tokio::test]
    async fn test_connect_retry_timer_expires_active() {
        let mut peer = create_test_peer_with_state(BgpState::Active).await;
        peer.fsm.timers.start_connect_retry();
        let timer_before = peer.fsm.timers.connect_retry_started;

        peer.process_event(&FsmEvent::ConnectRetryTimerExpires)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Connect);
        let timer_after = peer.fsm.timers.connect_retry_started;
        assert!(timer_after.is_some(), "ConnectRetryTimer should be running");
        assert_ne!(timer_before, timer_after);
    }

    #[tokio::test]
    async fn test_delay_open_timer_expires_active() {
        let mut peer = create_test_peer_with_state(BgpState::Active).await;
        peer.fsm.timers.start_connect_retry();
        peer.fsm.timers.start_delay_open_timer();
        assert_eq!(peer.statistics.open_sent, 0);

        peer.process_event(&FsmEvent::DelayOpenTimerExpires)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::OpenSent);
        assert!(!peer.fsm.timers.delay_open_timer_running());
        assert!(peer.fsm.timers.connect_retry_started.is_none());
        assert!(peer.fsm.timers.hold_timer_started.is_some());
        assert_eq!(peer.statistics.open_sent, 1);
    }

    #[tokio::test]
    async fn test_tcp_connection_fails_active() {
        let mut peer = create_test_peer_with_state(BgpState::Active).await;
        peer.fsm.timers.start_delay_open_timer();
        peer.config.damp_peer_oscillations = true;
        assert!(peer.conn.is_some());

        peer.process_event(&FsmEvent::TcpConnectionFails)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none());
        assert!(!peer.fsm.timers.delay_open_timer_running());
        assert!(peer.fsm.timers.connect_retry_started.is_some());
        assert_eq!(peer.fsm.connect_retry_counter, 1);
        assert_eq!(peer.consecutive_down_count, 1);
    }

    #[tokio::test]
    async fn test_open_received_in_active_stops_timers() {
        let mut peer = create_test_peer_with_state(BgpState::Active).await;
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
    async fn test_open_received_in_active_hold_time_zero() {
        let mut peer = create_test_peer_with_state(BgpState::Active).await;
        peer.fsm.timers.start_connect_retry();
        peer.fsm.timers.start_delay_open_timer();

        peer.process_event(&FsmEvent::BgpOpenWithDelayOpenTimer(BgpOpenParams {
            peer_asn: 65001,
            peer_hold_time: 0,
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
        assert_eq!(peer.fsm.timers.hold_time.as_secs(), 0);
        assert_eq!(peer.fsm.timers.keepalive_time.as_secs(), 0);
        assert!(peer.fsm.timers.hold_timer_started.is_none());
        assert!(peer.fsm.timers.keepalive_timer_started.is_none());
        assert_eq!(peer.statistics.keepalive_sent, 1);
    }

    #[tokio::test]
    async fn test_tcp_connection_success_active() {
        let cases = vec![(None, BgpState::OpenSent), (Some(5), BgpState::Active)];

        for (delay_open, expected_state) in cases {
            let mut peer = create_test_peer_with_state(BgpState::Active).await;
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
}
