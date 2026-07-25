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
use crate::bgp::msg_update::UpdateMessage;
use std::net::IpAddr;
use std::time::SystemTime;

/// Route Monitoring message - carries BGP UPDATE messages (RFC 7854 Section 5)
#[derive(Clone, Debug)]
pub struct RouteMonitoringMessage {
    pub peer_header: PeerHeader,
    pub bgp_update: UpdateMessage,
}

impl RouteMonitoringMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer_distinguisher: PeerDistinguisher,
        peer_address: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        post_policy: bool,
        use_4byte_asn: bool,
        timestamp: Option<SystemTime>,
        bgp_update: UpdateMessage,
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
            bgp_update,
        }
    }

    pub fn peer_header(&self) -> &PeerHeader {
        &self.peer_header
    }

    pub fn bgp_update(&self) -> &UpdateMessage {
        &self.bgp_update
    }
}

impl Message for RouteMonitoringMessage {
    fn message_type(&self) -> MessageType {
        MessageType::RouteMonitoring
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Per-Peer Header (42 bytes)
        bytes.extend_from_slice(&self.peer_header.to_bytes());

        // BGP UPDATE Message (BMP uses 4-byte ASN encoding per RFC 7854)
        bytes.extend_from_slice(&self.bgp_update.serialize());

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg::{AddPathMask, MessageFormat};
    use std::net::IpAddr;

    #[test]
    fn test_route_monitoring_message() {
        use crate::bgp::msg_update::UpdateMessage;
        use crate::bgp::msg_update_types::Nlri;
        use crate::bgp::nlri_v4;
        use crate::bmp::utils::PeerDistinguisher;
        use std::net::Ipv4Addr;

        // Create a withdrawal UPDATE message
        let withdrawn: Vec<Nlri> = vec![nlri_v4(10, 0, 0, 0, 24, None)];
        let update = UpdateMessage::new_withdraw(
            withdrawn,
            MessageFormat {
                use_4byte_asn: true,
                add_path: AddPathMask::NONE,
                is_ebgp: false,
                enhanced_rr: false,
            },
        );

        let msg = RouteMonitoringMessage::new(
            PeerDistinguisher::Global,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            false,
            true,
            Some(SystemTime::now()),
            update,
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::RouteMonitoring.as_u8());
    }
}
