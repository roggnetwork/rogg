// Copyright 2026 bgpgg Authors
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
use super::msg_notification::{BgpError, MessageHeaderError, RouteRefreshMessageError};
use super::multiprotocol::{Afi, Safi};
use super::utils::ParserError;

/// RFC 7313: ROUTE-REFRESH message subtypes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteRefreshSubtype {
    /// Normal route refresh request (RFC 2918)
    Normal,
    /// Beginning of Route Refresh (RFC 7313)
    BoRR,
    /// End of Route Refresh (RFC 7313)
    EoRR,
    /// Unknown subtype (silently ignored per RFC 7313 Section 5)
    Unknown(u8),
}

impl From<u8> for RouteRefreshSubtype {
    fn from(value: u8) -> Self {
        match value {
            0 => RouteRefreshSubtype::Normal,
            1 => RouteRefreshSubtype::BoRR,
            2 => RouteRefreshSubtype::EoRR,
            val => RouteRefreshSubtype::Unknown(val),
        }
    }
}

impl RouteRefreshSubtype {
    pub fn as_u8(self) -> u8 {
        match self {
            RouteRefreshSubtype::Normal => 0,
            RouteRefreshSubtype::BoRR => 1,
            RouteRefreshSubtype::EoRR => 2,
            RouteRefreshSubtype::Unknown(val) => val,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRefreshMessage {
    pub afi: Afi,
    pub safi: Safi,
    pub subtype: RouteRefreshSubtype,
}

impl RouteRefreshMessage {
    pub fn new(afi: Afi, safi: Safi) -> Self {
        RouteRefreshMessage {
            afi,
            safi,
            subtype: RouteRefreshSubtype::Normal,
        }
    }

    pub fn new_borr(afi: Afi, safi: Safi) -> Self {
        RouteRefreshMessage {
            afi,
            safi,
            subtype: RouteRefreshSubtype::BoRR,
        }
    }

    pub fn new_eorr(afi: Afi, safi: Safi) -> Self {
        RouteRefreshMessage {
            afi,
            safi,
            subtype: RouteRefreshSubtype::EoRR,
        }
    }

    /// Parse a ROUTE-REFRESH message body.
    pub fn from_bytes(
        body: Vec<u8>,
        full_msg: &[u8],
        enhanced_rr: bool,
    ) -> Result<Self, ParserError> {
        if body.len() != 4 {
            let subtype = body.get(2).copied().map(RouteRefreshSubtype::from);
            let is_borr_or_eorr = matches!(
                subtype,
                Some(RouteRefreshSubtype::BoRR | RouteRefreshSubtype::EoRR)
            );

            // RFC 7313 Section 5: BoRR/EoRR with wrong length -> error code 7, subcode 1.
            // Data field must contain the complete ROUTE-REFRESH message.
            // Only applies when Enhanced Route Refresh was received from peer.
            if is_borr_or_eorr && enhanced_rr {
                return Err(ParserError::BgpError {
                    error: BgpError::RouteRefreshMessageError(
                        RouteRefreshMessageError::InvalidMessageLength,
                    ),
                    data: full_msg.to_vec(),
                });
            }

            return Err(ParserError::BgpError {
                error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
                data: (body.len() as u16).to_be_bytes().to_vec(),
            });
        }

        let afi_val = u16::from_be_bytes([body[0], body[1]]);
        let subtype = RouteRefreshSubtype::from(body[2]);
        let safi_val = body[3];

        let afi = Afi::try_from(afi_val)?;
        let safi = Safi::try_from(safi_val)?;

        Ok(RouteRefreshMessage { afi, safi, subtype })
    }
}

impl Message for RouteRefreshMessage {
    fn kind(&self) -> MessageType {
        MessageType::RouteRefresh
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.afi as u16).to_be_bytes());
        bytes.push(self.subtype.as_u8());
        bytes.push(self.safi as u8);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::msg::Message;
    use crate::bgp::multiprotocol::{Afi, Safi};

    #[test]
    fn test_route_refresh_serialize() {
        let msg = RouteRefreshMessage::new(Afi::Ipv4, Safi::Unicast);
        let serialized = msg.serialize();

        assert_eq!(&serialized[0..16], &[0xff; 16]); // Marker
        assert_eq!(serialized[16..18], [0x00, 0x17]); // Length: 23
        assert_eq!(serialized[18], 5); // Type: ROUTE_REFRESH
        assert_eq!(serialized[19..21], [0x00, 0x01]); // AFI: IPv4
        assert_eq!(serialized[21], 0x00); // Subtype: Normal
        assert_eq!(serialized[22], 0x01); // SAFI: Unicast
    }

    #[test]
    fn test_route_refresh_parse() {
        let cases = vec![
            (
                vec![0x00, 0x01, 0x00, 0x01],
                Afi::Ipv4,
                Safi::Unicast,
                RouteRefreshSubtype::Normal,
            ),
            (
                vec![0x00, 0x02, 0x00, 0x01],
                Afi::Ipv6,
                Safi::Unicast,
                RouteRefreshSubtype::Normal,
            ),
            (
                vec![0x00, 0x01, 0x00, 0x02],
                Afi::Ipv4,
                Safi::Multicast,
                RouteRefreshSubtype::Normal,
            ),
            (
                vec![0x00, 0x02, 0x00, 0x02],
                Afi::Ipv6,
                Safi::Multicast,
                RouteRefreshSubtype::Normal,
            ),
            (
                vec![0x00, 0x01, 0x00, 0x04],
                Afi::Ipv4,
                Safi::MplsLabel,
                RouteRefreshSubtype::Normal,
            ),
            // BoRR
            (
                vec![0x00, 0x01, 0x01, 0x01],
                Afi::Ipv4,
                Safi::Unicast,
                RouteRefreshSubtype::BoRR,
            ),
            // EoRR
            (
                vec![0x00, 0x02, 0x02, 0x01],
                Afi::Ipv6,
                Safi::Unicast,
                RouteRefreshSubtype::EoRR,
            ),
            // Unknown subtype
            (
                vec![0x00, 0x01, 0xFF, 0x01],
                Afi::Ipv4,
                Safi::Unicast,
                RouteRefreshSubtype::Unknown(0xFF),
            ),
        ];

        for (body, expected_afi, expected_safi, expected_subtype) in cases {
            let full_msg = build_rr_msg(&body);
            let msg = RouteRefreshMessage::from_bytes(body, &full_msg, false).unwrap();
            assert_eq!(msg.afi, expected_afi);
            assert_eq!(msg.safi, expected_safi);
            assert_eq!(msg.subtype, expected_subtype);
        }
    }

    #[test]
    fn test_route_refresh_round_trip() {
        let cases = vec![
            RouteRefreshMessage::new(Afi::Ipv6, Safi::Unicast),
            RouteRefreshMessage::new_borr(Afi::Ipv4, Safi::Unicast),
            RouteRefreshMessage::new_eorr(Afi::Ipv4, Safi::Unicast),
        ];

        for msg in cases {
            let body = msg.to_bytes();
            let full_msg = build_rr_msg(&body);
            let parsed = RouteRefreshMessage::from_bytes(body, &full_msg, false).unwrap();
            assert_eq!(parsed, msg);
        }
    }

    fn build_rr_msg(body: &[u8]) -> Vec<u8> {
        let mut msg = vec![0xff; 16];
        let length = (19 + body.len()) as u16;
        msg.extend_from_slice(&length.to_be_bytes());
        msg.push(MessageType::RouteRefresh.as_u8());
        msg.extend_from_slice(body);
        msg
    }

    #[test]
    fn test_route_refresh_invalid_length_error_codes() {
        // RFC 7313 Section 5: error code 7 only when enhanced RR is negotiated
        let cases = vec![
            // (body, enhanced_rr, expected_error)
            // Normal subtype -> always error code 1
            (
                vec![0x00, 0x01, 0x00],
                true,
                BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            ),
            (
                vec![0x00, 0x01, 0x00],
                false,
                BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            ),
            // BoRR with enhanced_rr=true -> error code 7
            (
                vec![0x00, 0x01, 0x01],
                true,
                BgpError::RouteRefreshMessageError(RouteRefreshMessageError::InvalidMessageLength),
            ),
            // BoRR with enhanced_rr=false -> falls back to error code 1
            (
                vec![0x00, 0x01, 0x01],
                false,
                BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            ),
            // EoRR with enhanced_rr=true -> error code 7
            (
                vec![0x00, 0x01, 0x02],
                true,
                BgpError::RouteRefreshMessageError(RouteRefreshMessageError::InvalidMessageLength),
            ),
            // EoRR with enhanced_rr=false -> falls back to error code 1
            (
                vec![0x00, 0x01, 0x02],
                false,
                BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            ),
            // Unknown subtype -> always error code 1
            (
                vec![0x00, 0x01, 0x63],
                true,
                BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            ),
        ];

        for (body, enhanced_rr, expected_error) in cases {
            let full_msg = build_rr_msg(&body);
            let err =
                RouteRefreshMessage::from_bytes(body.clone(), &full_msg, enhanced_rr).unwrap_err();
            match err {
                ParserError::BgpError { error, data } => {
                    assert_eq!(
                        error, expected_error,
                        "body: {:?}, enhanced_rr: {}",
                        body, enhanced_rr
                    );
                    if matches!(error, BgpError::RouteRefreshMessageError(_)) {
                        assert_eq!(data, full_msg, "data must be the complete message");
                    }
                }
                other => panic!("expected BgpError, got {:?}", other),
            }
        }
    }
}
