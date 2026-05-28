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
use crate::bgp::msg::BgpMessage;
use std::net::IpAddr;
use std::time::SystemTime;

/// What to mirror in a Route Mirroring message (RFC 7854 Section 4.7)
#[derive(Clone, Debug)]
pub enum MirroringContent {
    /// Normal verbatim mirror of a valid BGP message
    Normal(BgpMessage),
    /// Errored PDU with parsed message (semantic error, treated-as-withdraw per RFC 7606)
    ErroredMessage(BgpMessage),
    /// Errored PDU with unparseable bytes (malformed/corrupted message)
    ErroredRaw(Vec<u8>),
    /// One or more messages were lost (e.g., buffer overflow)
    MessagesLost,
}

impl MirroringContent {
    fn to_tlvs(&self) -> Vec<MirroringTlv> {
        match self {
            Self::Normal(msg) => vec![MirroringTlv::BgpMessage(msg.serialize())],
            Self::ErroredMessage(msg) => vec![
                MirroringTlv::ErroredPdu,
                MirroringTlv::BgpMessage(msg.serialize()),
            ],
            Self::ErroredRaw(pdu) => vec![
                MirroringTlv::ErroredPdu,
                MirroringTlv::BgpMessage(pdu.clone()),
            ],
            Self::MessagesLost => vec![MirroringTlv::MessagesLost],
        }
    }
}

/// Route Mirroring TLV (internal - RFC 7854 Section 4.7)
#[derive(Clone, Debug)]
enum MirroringTlv {
    /// Type 0: BGP Message - verbatim copy of received BGP PDU
    BgpMessage(Vec<u8>),
    /// Type 1, Code 0: Errored PDU (treated-as-withdraw per RFC 7606)
    ErroredPdu,
    /// Type 1, Code 1: Messages Lost (e.g., buffer overflow)
    MessagesLost,
}

impl MirroringTlv {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        match self {
            Self::BgpMessage(pdu) => {
                // Type 0: BGP Message
                bytes.extend_from_slice(&0u16.to_be_bytes());
                bytes.extend_from_slice(&(pdu.len() as u16).to_be_bytes());
                bytes.extend_from_slice(pdu);
            }
            Self::ErroredPdu => {
                // Type 1: Information, Code 0: Errored PDU
                bytes.extend_from_slice(&1u16.to_be_bytes());
                bytes.extend_from_slice(&2u16.to_be_bytes()); // Length = 2
                bytes.extend_from_slice(&0u16.to_be_bytes()); // Code 0
            }
            Self::MessagesLost => {
                // Type 1: Information, Code 1: Messages Lost
                bytes.extend_from_slice(&1u16.to_be_bytes());
                bytes.extend_from_slice(&2u16.to_be_bytes()); // Length = 2
                bytes.extend_from_slice(&1u16.to_be_bytes()); // Code 1
            }
        }

        bytes
    }
}

/// Route Mirroring message - for debugging/monitoring rejected or policy-filtered messages
#[derive(Clone, Debug)]
pub struct RouteMirroringMessage {
    peer_header: PeerHeader,
    content: MirroringContent,
}

impl RouteMirroringMessage {
    pub fn new(
        peer_distinguisher: PeerDistinguisher,
        peer_address: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        use_4byte_asn: bool,
        timestamp: Option<SystemTime>,
        content: MirroringContent,
    ) -> Self {
        Self {
            peer_header: PeerHeader::new(
                peer_distinguisher,
                peer_address,
                peer_as,
                peer_bgp_id,
                false,
                use_4byte_asn,
                timestamp,
            ),
            content,
        }
    }
}

impl Message for RouteMirroringMessage {
    fn message_type(&self) -> MessageType {
        MessageType::RouteMirroring
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Per-Peer Header (42 bytes)
        bytes.extend_from_slice(&self.peer_header.to_bytes());

        // Convert content to TLVs and serialize
        let tlvs = self.content.to_tlvs();
        for tlv in &tlvs {
            bytes.extend_from_slice(&tlv.to_bytes());
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_route_mirroring_normal() {
        use crate::bgp::msg_keepalive::KeepaliveMessage;
        use crate::bmp::utils::PeerDistinguisher;

        let keepalive = BgpMessage::Keepalive(KeepaliveMessage {});
        let msg = RouteMirroringMessage::new(
            PeerDistinguisher::Global,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            true,
            Some(SystemTime::now()),
            MirroringContent::Normal(keepalive),
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::RouteMirroring.as_u8());
    }

    #[test]
    fn test_route_mirroring_errored_message() {
        use crate::bgp::msg_keepalive::KeepaliveMessage;
        use crate::bmp::utils::PeerDistinguisher;

        // A parsed message that had semantic errors (treated-as-withdraw)
        let keepalive = BgpMessage::Keepalive(KeepaliveMessage {});
        let msg = RouteMirroringMessage::new(
            PeerDistinguisher::Global,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            true,
            Some(SystemTime::now()),
            MirroringContent::ErroredMessage(keepalive),
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::RouteMirroring.as_u8());
    }

    #[test]
    fn test_route_mirroring_errored_raw() {
        use crate::bmp::utils::PeerDistinguisher;

        // Unparseable/malformed PDU bytes
        let bad_pdu = vec![0xff; 23];
        let msg = RouteMirroringMessage::new(
            PeerDistinguisher::Global,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            true,
            Some(SystemTime::now()),
            MirroringContent::ErroredRaw(bad_pdu),
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::RouteMirroring.as_u8());
    }

    #[test]
    fn test_route_mirroring_messages_lost() {
        use crate::bmp::utils::PeerDistinguisher;

        let msg = RouteMirroringMessage::new(
            PeerDistinguisher::Global,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            true,
            Some(SystemTime::now()),
            MirroringContent::MessagesLost,
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::RouteMirroring.as_u8());
    }
}
