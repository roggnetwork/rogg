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

//! Shared types used across modules

use crate::bgp::msg_notification::NotificationMessage;
use crate::peer::FsmEvent;

// TODO: Add support for RFC 9069 reason 6 (Local system closed, TLV data follows)
// for Loc-RIB monitoring support
#[derive(Clone, Debug)]
pub enum PeerDownReason {
    LocalNotification(NotificationMessage), // reason 1: local sent NOTIFICATION (data = BGP NOTIFICATION PDU)
    LocalNoNotification(FsmEvent), // reason 2: local closed, no NOTIFICATION (data = 2-byte FSM event code)
    RemoteNotification(NotificationMessage), // reason 3: remote sent NOTIFICATION (data = BGP NOTIFICATION PDU)
    RemoteNoNotification,                    // reason 4: remote closed, no NOTIFICATION (no data)
    PeerDeConfigured,                        // reason 5: peer de-configured (no data)
}
