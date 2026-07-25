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
use crate::log::debug;
use std::time::Duration;
use tokio::time::Instant;

impl Peer {
    /// Handle Idle state - wait for ManualStart or AutomaticStart.
    /// Returns true if shutdown requested.
    pub(super) async fn handle_idle_state(&mut self) -> bool {
        if self.config.passive_mode {
            self.handle_idle_state_passive().await
        } else {
            self.handle_idle_state_active().await
        }
    }

    /// Passive mode: wait for start event or IdleHoldTimer to transition to Active.
    /// RFC 4271 8.1.2: Event 7 (AutomaticStart_with_DampPeerOscillations_and_PassiveTcpEstablishment)
    /// and Event 13 (IdleHoldTimer_Expires) apply to passive peers.
    async fn handle_idle_state_passive(&mut self) -> bool {
        let idle_hold_time = self.get_idle_hold_time();
        let auto_reconnect = idle_hold_time.is_some() && !self.manually_stopped;
        let idle_hold_deadline = if auto_reconnect {
            Instant::now() + idle_hold_time.unwrap()
        } else {
            Instant::now() + Duration::from_secs(86400 * 365) // Far future if not auto-reconnecting
        };

        loop {
            tokio::select! {
                op = self.peer_rx.recv() => {
                    match op {
                        Some(PeerOp::ManualStartPassive) => {
                            debug!(peer_ip = %self.addr, "ManualStartPassive received");
                            self.manually_stopped = false;
                            self.try_process_event(&FsmEvent::ManualStartPassive).await;
                            return false;
                        }
                        Some(PeerOp::AutomaticStartPassive) => {
                            debug!(peer_ip = %self.addr, "AutomaticStartPassive received");
                            self.try_process_event(&FsmEvent::AutomaticStartPassive).await;
                            return false;
                        }
                        Some(PeerOp::Shutdown(_)) => return true,
                        Some(PeerOp::GetStatistics(response)) => {
                            let _ = response.send(self.statistics.clone());
                        }
                        Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                            // RFC 4271 8.2.2: In Idle state, refuse incoming connections
                            debug!(peer_ip = %self.addr, "connection refused in Idle state");
                            drop(tcp_tx);
                            drop(tcp_rx);
                        }
                        Some(_) => {}
                        None => return true,
                    }
                }
                _ = tokio::time::sleep_until(idle_hold_deadline), if auto_reconnect => {
                    // RFC 4271 Event 13: IdleHoldTimer_Expires
                    debug!(peer_ip = %self.addr, "IdleHoldTimer expired");
                    self.try_process_event(&FsmEvent::IdleHoldTimerExpires).await;
                    return false;
                }
            }
        }
    }

    /// Non-passive mode: wait for ManualStart, AutomaticStart, or auto-reconnect timer.
    async fn handle_idle_state_active(&mut self) -> bool {
        let idle_hold_time = self.get_idle_hold_time();
        let auto_reconnect = idle_hold_time.is_some() && !self.manually_stopped;
        let idle_hold_deadline = if auto_reconnect {
            Instant::now() + idle_hold_time.unwrap()
        } else {
            Instant::now() + Duration::from_secs(86400 * 365) // Far future if not auto-reconnecting
        };

        loop {
            tokio::select! {
                op = self.peer_rx.recv() => {
                    match op {
                        Some(PeerOp::ManualStart) => {
                            debug!(peer_ip = %self.addr, "ManualStart received");
                            self.manually_stopped = false;
                            self.try_process_event(&FsmEvent::ManualStart).await;
                            return false;
                        }
                        Some(PeerOp::AutomaticStart) => {
                            debug!(peer_ip = %self.addr, "AutomaticStart received");
                            self.try_process_event(&FsmEvent::AutomaticStart).await;
                            return false;
                        }
                        Some(PeerOp::Shutdown(_)) => return true,
                        Some(PeerOp::GetStatistics(response)) => {
                            let _ = response.send(self.statistics.clone());
                        }
                        Some(PeerOp::TcpConnectionAccepted { tcp_tx, tcp_rx }) => {
                            // RFC 4271 8.2.2: In Idle state, refuse incoming connections
                            debug!(peer_ip = %self.addr, "connection refused in Idle state");
                            drop(tcp_tx);
                            drop(tcp_rx);
                        }
                        Some(_) => {}
                        None => return true,
                    }
                }
                _ = tokio::time::sleep_until(idle_hold_deadline), if auto_reconnect => {
                    // RFC 4271 Event 13: IdleHoldTimer_Expires
                    debug!(peer_ip = %self.addr, "IdleHoldTimer expired");
                    self.try_process_event(&FsmEvent::IdleHoldTimerExpires).await;
                    return false;
                }
            }
        }
    }

    /// Handle Idle state transitions.
    pub(super) async fn handle_idle_transitions(
        &mut self,
        new_state: BgpState,
        _event: &FsmEvent,
    ) -> Result<(), PeerError> {
        match new_state {
            // RFC 4271 8.2.2: Initialize resources and start ConnectRetryTimer when leaving Idle
            BgpState::Connect | BgpState::Active => {
                self.fsm.reset_connect_retry_counter();
                self.fsm.timers.start_connect_retry();
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

    #[tokio::test]
    async fn test_connect_retry_timer_started_on_idle_transition() {
        let test_cases = vec![
            (FsmEvent::ManualStart, BgpState::Connect),
            (FsmEvent::AutomaticStart, BgpState::Connect),
            (FsmEvent::ManualStartPassive, BgpState::Active),
            (FsmEvent::AutomaticStartPassive, BgpState::Active),
        ];

        for (event, expected_state) in test_cases {
            let mut peer = create_test_peer_with_state(BgpState::Idle).await;
            assert!(
                peer.fsm.timers.connect_retry_started.is_none(),
                "ConnectRetryTimer should not be started initially"
            );

            peer.process_event(&event).await.unwrap();

            assert_eq!(
                peer.state(),
                expected_state,
                "State should transition to {:?}",
                expected_state
            );
            assert_eq!(
                peer.fsm.connect_retry_counter, 0,
                "ConnectRetryCounter should be set to 0 after {:?}",
                event
            );
            assert!(
                peer.fsm.timers.connect_retry_started.is_some(),
                "ConnectRetryTimer should be started after {:?}",
                event
            );
        }
    }
}
