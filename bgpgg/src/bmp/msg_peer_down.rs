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

use super::msg::{Message, MessageType};
use super::utils::{PeerDistinguisher, PeerHeader};
use crate::bgp::msg::Message as BgpMessage;
use crate::types::PeerDownReason;
use std::net::IpAddr;
use std::time::SystemTime;

impl PeerDownReason {
    fn reason_code(&self) -> u8 {
        match self {
            PeerDownReason::LocalNotification(_) => 1,
            PeerDownReason::LocalNoNotification(_) => 2,
            PeerDownReason::RemoteNotification(_) => 3,
            PeerDownReason::RemoteNoNotification => 4,
            PeerDownReason::PeerDeConfigured => 5,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![self.reason_code()];
        match self {
            PeerDownReason::LocalNotification(notif)
            | PeerDownReason::RemoteNotification(notif) => {
                bytes.extend_from_slice(&notif.serialize());
            }
            PeerDownReason::LocalNoNotification(fsm_event) => {
                bytes.extend_from_slice(&fsm_event.to_event_code().to_be_bytes());
            }
            PeerDownReason::RemoteNoNotification | PeerDownReason::PeerDeConfigured => {
                // No data for reasons 4 and 5
            }
        }
        bytes
    }
}

#[derive(Clone, Debug)]
pub struct PeerDownMessage {
    pub peer_header: PeerHeader,
    pub reason: PeerDownReason,
}

impl PeerDownMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer_distinguisher: PeerDistinguisher,
        peer_address: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        post_policy: bool,
        use_4byte_asn: bool,
        timestamp: Option<SystemTime>,
        reason: PeerDownReason,
    ) -> Self {
        Self {
            peer_header: PeerHeader::new(
                peer_distinguisher,
                peer_address,
                peer_as,
                peer_bgp_id,
                post_policy,
                use_4byte_asn,
                timestamp,
            ),
            reason,
        }
    }
}

impl Message for PeerDownMessage {
    fn message_type(&self) -> MessageType {
        MessageType::PeerDownNotification
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Per-Peer Header (42 bytes)
        bytes.extend_from_slice(&self.peer_header.to_bytes());

        // Reason
        bytes.extend_from_slice(&self.reason.to_bytes());

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_peer_down_message_no_notification() {
        use crate::bmp::utils::PeerDistinguisher;
        use crate::peer::FsmEvent;

        let msg = PeerDownMessage::new(
            PeerDistinguisher::Global,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            false,
            true,
            Some(SystemTime::now()),
            PeerDownReason::LocalNoNotification(FsmEvent::HoldTimerExpires),
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::PeerDownNotification.as_u8());
    }

    #[test]
    fn test_peer_down_message_with_notification() {
        use crate::bgp::msg_notification::{BgpError, CeaseSubcode, NotificationMessage};
        use crate::bmp::utils::PeerDistinguisher;

        let notif =
            NotificationMessage::new(BgpError::Cease(CeaseSubcode::AdministrativeReset), vec![]);
        let msg = PeerDownMessage::new(
            PeerDistinguisher::Global,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            false,
            true,
            Some(SystemTime::now()),
            PeerDownReason::LocalNotification(notif),
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::PeerDownNotification.as_u8());
    }
}
