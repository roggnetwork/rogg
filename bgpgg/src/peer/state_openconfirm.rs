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
use crate::server::ops::ServerOp;
use crate::types::PeerDownReason;
use std::time::Instant;

impl Peer {
    /// Handle OpenConfirm state transitions (RFC 4271 Section 8.2.2).
    pub(super) async fn handle_openconfirm_transitions(
        &mut self,
        new_state: BgpState,
        event: &FsmEvent,
    ) -> Result<(), PeerError> {
        match (new_state, event) {
            (BgpState::Idle, FsmEvent::ManualStop) => {
                self.handle_manual_stop().await?;
            }

            (BgpState::Idle, FsmEvent::AutomaticStop(ref subcode)) => {
                return self.handle_automatic_stop(subcode).await;
            }

            (BgpState::Idle, FsmEvent::HoldTimerExpires) => {
                self.handle_hold_timer_expires().await?;
            }

            (BgpState::Idle, FsmEvent::TcpConnectionFails) => {
                self.transition_to_idle_on_error(PeerDownReason::RemoteNoNotification);
            }

            (BgpState::Idle, FsmEvent::NotifMsgVerErr(ref notif)) => {
                self.disconnect(false, PeerDownReason::RemoteNotification(notif.clone()));
                self.fsm.timers.stop_connect_retry();
            }

            (BgpState::Idle, FsmEvent::NotifMsg(ref notif)) => {
                self.transition_to_idle_on_error(PeerDownReason::RemoteNotification(notif.clone()));
            }

            (BgpState::Idle, FsmEvent::BgpHeaderErr(ref notif))
            | (BgpState::Idle, FsmEvent::BgpOpenMsgErr(ref notif)) => {
                self.handle_bgp_message_error(notif, true).await?;
            }

            (BgpState::OpenConfirm, FsmEvent::KeepaliveTimerExpires) => {
                self.send_keepalive().await?;
            }

            (BgpState::Established, FsmEvent::BgpKeepaliveReceived) => {
                self.fsm.timers.reset_hold_timer();
                self.established_at = Some(Instant::now());

                // Send connection info to server for BMP
                if let (Some(sent_open), Some(received_open), Some(conn)) =
                    (&self.sent_open, &self.received_open, &self.conn)
                {
                    if let (Ok(local_addr), Ok(remote_addr)) =
                        (conn.tx.local_addr(), conn.tx.peer_addr())
                    {
                        let _ = self.server_tx.send(ServerOp::PeerConnectionInfo {
                            peer_ip: self.addr,
                            local_address: local_addr.ip(),
                            local_port: local_addr.port(),
                            remote_port: remote_addr.port(),
                            sent_open: sent_open.clone(),
                            received_open: received_open.clone(),
                            negotiated_capabilities: self.capabilities.clone(),
                            conn_type: self.conn_type,
                        });
                    }
                }
            }

            (BgpState::Idle, FsmEvent::ConnectRetryTimerExpires)
            | (BgpState::Idle, FsmEvent::DelayOpenTimerExpires)
            | (BgpState::Idle, FsmEvent::IdleHoldTimerExpires)
            | (BgpState::Idle, FsmEvent::BgpOpenWithDelayOpenTimer(_))
            | (BgpState::Idle, FsmEvent::BgpUpdateReceived)
            | (BgpState::Idle, FsmEvent::BgpUpdateMsgErr(_)) => {
                return self.handle_fsm_error(true).await;
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
        BgpError, CeaseSubcode, NotificationMessage, UpdateMessageError,
    };
    use crate::peer::states::tests::create_test_peer_with_state;
    use crate::peer::BgpOpenParams;
    use crate::peer::PeerCapabilities;

    #[tokio::test]
    async fn test_openconfirm_ignores_start_events() {
        let start_events = vec![
            FsmEvent::ManualStart,
            FsmEvent::AutomaticStart,
            FsmEvent::ManualStartPassive,
            FsmEvent::AutomaticStartPassive,
        ];

        for event in start_events {
            let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            let initial_counter = peer.fsm.connect_retry_counter;

            peer.process_event(&event).await.unwrap();

            assert_eq!(peer.state(), BgpState::OpenConfirm);
            assert!(peer.conn.is_some());
            assert_eq!(peer.fsm.connect_retry_counter, initial_counter);
            assert!(peer.fsm.timers.hold_timer_started.is_some());
            assert!(peer.fsm.timers.keepalive_timer_started.is_some());
        }
    }

    #[tokio::test]
    async fn test_openconfirm_manual_stop() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 5;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        peer.process_event(&FsmEvent::ManualStop).await.unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert_eq!(
            peer.fsm.connect_retry_counter, 0,
            "ConnectRetryCounter should be zero"
        );
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be zero"
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
    async fn test_openconfirm_automatic_stop() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
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
            "ConnectRetryTimer should be zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 3,
            "ConnectRetryCounter should be incremented by 1"
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
    async fn test_openconfirm_automatic_stop_with_damping() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 1;
        peer.config.damp_peer_oscillations = true;
        peer.consecutive_down_count = 0;
        peer.config.send_notification_without_open = true;

        let result = peer
            .process_event(&FsmEvent::AutomaticStop(CeaseSubcode::MaxPrefixesReached))
            .await;

        assert!(result.is_err());
        assert_eq!(peer.state(), BgpState::Idle);
        assert_eq!(
            peer.fsm.connect_retry_counter, 2,
            "ConnectRetryCounter should be incremented"
        );
        assert_eq!(
            peer.consecutive_down_count, 1,
            "Peer oscillation damping should increment consecutive_down_count"
        );
    }

    #[tokio::test]
    async fn test_openconfirm_keepalive_timer_expires() {
        let test_cases = vec![
            (180, true), // (hold_time, should_restart_timer)
            (0, false),  // hold_time=0 should not restart timer
        ];

        for (hold_time, should_restart) in test_cases {
            let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
            peer.fsm.timers.set_negotiated_hold_time(hold_time);
            if hold_time > 0 {
                peer.fsm.timers.start_hold_timer();
                peer.fsm.timers.start_keepalive_timer();
            }
            let initial_keepalive_sent = peer.statistics.keepalive_sent;

            peer.process_event(&FsmEvent::KeepaliveTimerExpires)
                .await
                .unwrap();

            assert_eq!(peer.state(), BgpState::OpenConfirm);
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
    async fn test_openconfirm_hold_timer_expires() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 3;
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
            peer.fsm.connect_retry_counter, 4,
            "ConnectRetryCounter should be incremented by 1"
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
    async fn test_openconfirm_tcp_connection_fails() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 2;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();

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
            "ConnectRetryCounter should be incremented by 1"
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
    async fn test_openconfirm_notification_received() {
        use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};

        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
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
            "ConnectRetryCounter should be incremented by 1"
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
    async fn test_openconfirm_notification_version_error() {
        use crate::bgp::msg_notification::{BgpError, NotificationMessage, OpenMessageError};

        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 5;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();

        let notif = NotificationMessage::new(
            BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber),
            vec![],
        );
        peer.process_event(&FsmEvent::NotifMsgVerErr(notif))
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 5,
            "ConnectRetryCounter should NOT be incremented for version error"
        );
    }

    #[tokio::test]
    async fn test_openconfirm_bgp_header_error() {
        use crate::bgp::msg_notification::MessageHeaderError;

        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 1;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        let notif = NotificationMessage::new(
            BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            vec![],
        );

        peer.process_event(&FsmEvent::BgpHeaderErr(notif))
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
            "ConnectRetryCounter should be incremented by 1"
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
    async fn test_openconfirm_bgp_open_msg_error() {
        use crate::bgp::msg_notification::OpenMessageError;

        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.connect_retry_counter = 3;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();
        peer.config.send_notification_without_open = true;

        let notif = NotificationMessage::new(
            BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber),
            vec![],
        );

        peer.process_event(&FsmEvent::BgpOpenMsgErr(notif))
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Idle);
        assert!(peer.conn.is_none(), "TCP connection should be dropped");
        assert!(
            peer.fsm.timers.connect_retry_started.is_none(),
            "ConnectRetryTimer should be set to zero"
        );
        assert_eq!(
            peer.fsm.connect_retry_counter, 4,
            "ConnectRetryCounter should be incremented by 1"
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
    async fn test_openconfirm_fsm_errors() {
        let events = vec![
            FsmEvent::ConnectRetryTimerExpires,
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
            FsmEvent::BgpUpdateReceived,
            FsmEvent::BgpUpdateMsgErr(NotificationMessage::new(
                BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList),
                vec![],
            )),
        ];

        for event in events {
            let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
            peer.fsm.connect_retry_counter = 2;
            peer.fsm.timers.start_hold_timer();
            peer.fsm.timers.start_keepalive_timer();
            peer.config.damp_peer_oscillations = true;
            peer.config.send_notification_without_open = true;

            let result = peer.process_event(&event).await;

            assert!(result.is_err(), "FSM error should return error");
            assert_eq!(peer.state(), BgpState::Idle);
            assert!(peer.conn.is_none(), "TCP connection should be dropped");
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

    #[tokio::test]
    async fn test_openconfirm_transition_to_established() {
        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.timers.start_hold_timer();
        peer.fsm.timers.start_keepalive_timer();

        peer.process_event(&FsmEvent::BgpKeepaliveReceived)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Established);
        assert!(peer.established_at.is_some());
    }

    #[tokio::test]
    async fn test_openconfirm_keepalive_received() {
        use std::time::Duration;

        let mut peer = create_test_peer_with_state(BgpState::OpenConfirm).await;
        peer.fsm.timers.start_hold_timer();
        let hold_start = peer.fsm.timers.hold_timer_started;

        tokio::time::sleep(Duration::from_millis(10)).await;

        peer.process_event(&FsmEvent::BgpKeepaliveReceived)
            .await
            .unwrap();

        assert_eq!(peer.state(), BgpState::Established);
        assert!(peer.fsm.timers.hold_timer_started > hold_start);
    }
}
