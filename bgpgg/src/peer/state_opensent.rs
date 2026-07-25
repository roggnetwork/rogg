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
use super::{Peer, PeerError};
use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
use crate::server::ops::ServerOp;
use crate::server::AdminState;
use crate::types::PeerDownReason;

impl Peer {
    /// Handle OpenSent state transitions.
    pub(super) async fn handle_opensent_transitions(
        &mut self,
        new_state: BgpState,
        event: &FsmEvent,
    ) -> Result<(), PeerError> {
        match (new_state, event) {
            // RFC 4271 8.2.2: ManualStop in session states
            (BgpState::Idle, FsmEvent::ManualStop) => {
                self.manually_stopped = true;
                let notif = NotificationMessage::new(
                    BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
                    Vec::new(),
                );
                let _ = self.send_notification(notif).await;
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.timers.stop_connect_retry();
                self.fsm.reset_connect_retry_counter();
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
            }

            // RFC 4271 Event 8: AutomaticStop in session states
            (BgpState::Idle, FsmEvent::AutomaticStop(ref subcode)) => {
                let notif = NotificationMessage::new(BgpError::Cease(subcode.clone()), Vec::new());
                let _ = self.send_notification(notif).await;
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.timers.stop_connect_retry();
                self.fsm.increment_connect_retry_counter();
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();

                let admin_state = match subcode {
                    CeaseSubcode::MaxPrefixesReached => AdminState::PrefixLimitReached,
                    _ => AdminState::Down,
                };
                let _ = self.server_tx.send(ServerOp::SetAdminState {
                    peer_ip: self.addr,
                    state: admin_state,
                });
                return Err(PeerError::AutomaticStop(subcode.clone()));
            }

            // RFC 4271 Event 10: HoldTimer_Expires in session states
            (BgpState::Idle, FsmEvent::HoldTimerExpires) => {
                let notif = NotificationMessage::new(BgpError::HoldTimerExpired, vec![]);
                let _ = self.send_notification(notif).await;
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.timers.stop_connect_retry();
                self.fsm.increment_connect_retry_counter();
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
            }

            (BgpState::Active, FsmEvent::TcpConnectionFails) => {
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.timers.start_connect_retry();
            }

            (BgpState::Idle, FsmEvent::BgpHeaderErr(ref notif))
            | (BgpState::Idle, FsmEvent::BgpOpenMsgErr(ref notif)) => {
                let _ = self.send_notification(notif.clone()).await;
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.timers.stop_connect_retry();
                self.fsm.increment_connect_retry_counter();
            }

            (BgpState::Idle, FsmEvent::NotifMsgVerErr(ref notif)) => {
                self.fsm.timers.stop_connect_retry();
                self.disconnect(false, PeerDownReason::RemoteNotification(notif.clone()));
            }

            (BgpState::Idle, FsmEvent::NotifMsg(ref notif)) => {
                let _ = self
                    .send_notification(NotificationMessage::new(
                        BgpError::FiniteStateMachineError,
                        vec![],
                    ))
                    .await;
                self.fsm.timers.stop_connect_retry();
                self.disconnect(true, PeerDownReason::RemoteNotification(notif.clone()));
                self.fsm.increment_connect_retry_counter();
            }

            (BgpState::Idle, FsmEvent::ConnectRetryTimerExpires)
            | (BgpState::Idle, FsmEvent::KeepaliveTimerExpires)
            | (BgpState::Idle, FsmEvent::DelayOpenTimerExpires)
            | (BgpState::Idle, FsmEvent::IdleHoldTimerExpires)
            | (BgpState::Idle, FsmEvent::BgpKeepaliveReceived)
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

            (BgpState::Idle, FsmEvent::BgpUpdateMsgErr(ref notif)) => {
                let _ = self.send_notification(notif.clone()).await;
                self.disconnect(true, PeerDownReason::RemoteNoNotification);
                self.fsm.timers.stop_hold_timer();
                self.fsm.timers.stop_keepalive_timer();
                return Err(PeerError::UpdateError);
            }

            (BgpState::OpenConfirm, &FsmEvent::BgpOpenReceived(ref params))
            | (BgpState::OpenConfirm, &FsmEvent::BgpOpenWithDelayOpenTimer(ref params)) => {
                self.fsm.timers.stop_delay_open_timer();
                self.fsm.timers.stop_connect_retry();
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
    use crate::bgp::msg_notification::{MessageHeaderError, OpenMessageError};
    use crate::peer::states::tests::create_test_peer_with_state;
    use crate::peer::{BgpOpenParams, PeerCapabilities};

    #[tokio::test]
    async fn test_opensent_tcp_connection_fails() {
        let mut peer = create_test_peer_with_state(BgpState::OpenSent).await;
        peer.fsm.timers.start_hold_timer();
        assert!(peer.conn.is_some());
        assert!(peer.fsm.timers.connect_retry_started.is_none());

        peer.process_event(&FsmEvent::TcpConnectionFails)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Active);
        assert!(peer.conn.is_none());
        assert!(peer.fsm.timers.connect_retry_started.is_some());
    }

    #[tokio::test]
    async fn test_opensent_open_received_hold_time_negotiation() {
        let cases = vec![
            (180, 180, 180, 60),
            (180, 90, 90, 30),
            (90, 180, 90, 30),
            (240, 120, 120, 40),
            (180, 0, 0, 0),
            (0, 180, 0, 0),
        ];

        for (local_hold, peer_hold, expected_hold, expected_keepalive) in cases {
            let mut peer = create_test_peer_with_state(BgpState::OpenSent).await;
            peer.fsm.timers.start_connect_retry();
            peer.fsm.timers.start_delay_open_timer();

            peer.process_event(&FsmEvent::BgpOpenReceived(BgpOpenParams {
                peer_asn: 65001,
                peer_hold_time: peer_hold,
                peer_bgp_id: 0x02020202,
                local_asn: 65000,
                local_hold_time: local_hold,
                peer_capabilities: PeerCapabilities::default(),
            }))
            .await
            .unwrap();

            assert_eq!(peer.state(), BgpState::OpenConfirm);
            assert!(peer.fsm.timers.delay_open_timer_started.is_none());
            assert!(peer.fsm.timers.connect_retry_started.is_none());
            assert_eq!(peer.statistics.keepalive_sent, 1);
            assert_eq!(peer.fsm.timers.hold_time.as_secs(), expected_hold);
            assert_eq!(peer.fsm.timers.keepalive_time.as_secs(), expected_keepalive);

            if expected_hold == 0 {
                assert!(peer.fsm.timers.hold_timer_started.is_none());
                assert!(peer.fsm.timers.keepalive_timer_started.is_none());
            } else {
                assert!(peer.fsm.timers.hold_timer_started.is_some());
                assert!(peer.fsm.timers.keepalive_timer_started.is_some());
            }
        }
    }

    #[tokio::test]
    async fn test_opensent_bgp_message_errors() {
        let errors = vec![
            BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber),
        ];

        for error in errors {
            let mut peer = create_test_peer_with_state(BgpState::OpenSent).await;
            peer.fsm.connect_retry_counter = 2;
            peer.fsm.timers.start_connect_retry();
            peer.statistics.open_sent = 1;

            let notif = NotificationMessage::new(error, vec![]);
            let event = match notif.error() {
                BgpError::MessageHeaderError(_) => FsmEvent::BgpHeaderErr(notif),
                BgpError::OpenMessageError(_) => FsmEvent::BgpOpenMsgErr(notif),
                _ => panic!("unexpected error type"),
            };

            peer.process_event(&event).await.unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.fsm.timers.connect_retry_started.is_none());
            assert_eq!(peer.fsm.connect_retry_counter, 3);
            assert!(peer.conn.is_none());
            assert_eq!(peer.statistics.notification_sent, 1);
        }
    }

    #[tokio::test]
    async fn test_opensent_notification_received() {
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
            (FsmEvent::NotifMsgVerErr(notif_ver), 0, 0),
            (FsmEvent::NotifMsg(notif), 1, 1),
        ];

        for (event, expected_down_count, expected_counter) in cases {
            let mut peer = create_test_peer_with_state(BgpState::OpenSent).await;
            peer.fsm.timers.start_connect_retry();
            peer.config.damp_peer_oscillations = true;

            peer.process_event(&event).await.unwrap();

            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.conn.is_none());
            assert!(peer.fsm.timers.connect_retry_started.is_none());
            assert_eq!(peer.consecutive_down_count, expected_down_count);
            assert_eq!(peer.fsm.connect_retry_counter, expected_counter);
        }
    }

    #[tokio::test]
    async fn test_opensent_fsm_errors() {
        let events = vec![
            FsmEvent::ConnectRetryTimerExpires,
            FsmEvent::KeepaliveTimerExpires,
            FsmEvent::DelayOpenTimerExpires,
            FsmEvent::IdleHoldTimerExpires,
            FsmEvent::BgpKeepaliveReceived,
            FsmEvent::BgpUpdateReceived,
        ];

        for event in events {
            let mut peer = create_test_peer_with_state(BgpState::OpenSent).await;
            peer.fsm.timers.start_connect_retry();
            peer.config.damp_peer_oscillations = true;
            peer.statistics.open_sent = 1;

            let result = peer.process_event(&event).await;

            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), PeerError::FsmError));
            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.conn.is_none());
            assert!(peer.fsm.timers.connect_retry_started.is_none());
            assert_eq!(peer.fsm.connect_retry_counter, 1);
            assert_eq!(peer.consecutive_down_count, 1);
            assert_eq!(peer.statistics.notification_sent, 1);
        }
    }

    #[tokio::test]
    async fn test_opensent_ignores_start_events() {
        let start_events = vec![
            FsmEvent::ManualStart,
            FsmEvent::AutomaticStart,
            FsmEvent::ManualStartPassive,
            FsmEvent::AutomaticStartPassive,
        ];

        for event in start_events {
            let mut peer = create_test_peer_with_state(BgpState::OpenSent).await;
            let initial_counter = peer.fsm.connect_retry_counter;

            peer.process_event(&event).await.unwrap();

            assert_eq!(peer.state(), BgpState::OpenSent);
            assert_eq!(peer.fsm.connect_retry_counter, initial_counter);
            assert!(peer.conn.is_some());
        }
    }

    #[tokio::test]
    async fn test_opensent_automatic_stop_damping() {
        let mut peer = create_test_peer_with_state(BgpState::OpenSent).await;
        peer.config.damp_peer_oscillations = true;
        peer.consecutive_down_count = 0;
        peer.fsm.connect_retry_counter = 1;
        peer.config.send_notification_without_open = true;

        let result = peer
            .process_event(&FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached))
            .await;

        assert!(result.is_err());
        assert_eq!(peer.state(), BgpState::Idle);
        assert_eq!(peer.consecutive_down_count, 1);
        assert_eq!(peer.fsm.connect_retry_counter, 2);
    }
}
