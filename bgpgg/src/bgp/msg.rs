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

use super::msg_keepalive::KeepaliveMessage;
use super::msg_notification::{BgpError, MessageHeaderError, NotificationMessage};
use super::msg_open::OpenMessage;
use super::msg_route_refresh::RouteRefreshMessage;
use super::msg_update::UpdateMessage;
use super::multiprotocol::{Afi, AfiSafi, Safi};
use super::utils::ParserError;
use tokio::io::AsyncReadExt;

pub const BGP_HEADER_SIZE_BYTES: usize = 19;
pub const MAX_MESSAGE_SIZE: u16 = 4096;

/// Per-AFI/SAFI ADD-PATH bitmask (RFC 7911).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddPathMask(u32);

impl AddPathMask {
    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self(u32::MAX);

    /// Return a new mask with the given AFI/SAFI added
    pub fn with(self, afi_safi: &AfiSafi) -> Self {
        Self(self.0 | Self::from_afi_safi(afi_safi))
    }

    /// Check if ADD-PATH is enabled for a specific AFI/SAFI
    pub fn contains(&self, afi_safi: &AfiSafi) -> bool {
        self.0 & Self::from_afi_safi(afi_safi) != 0
    }

    /// Returns true if no AFI/SAFI has ADD-PATH enabled
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    fn from_afi_safi(afi_safi: &AfiSafi) -> u32 {
        match (afi_safi.afi, afi_safi.safi) {
            (Afi::Ipv4, Safi::Unicast) => 1 << 0,
            (Afi::Ipv6, Safi::Unicast) => 1 << 1,
            (Afi::Ipv4, Safi::Multicast) => 1 << 2,
            (Afi::Ipv6, Safi::Multicast) => 1 << 3,
            (Afi::Ipv4, Safi::MplsLabel) => 1 << 4,
            (Afi::Ipv6, Safi::MplsLabel) => 1 << 5,
            (Afi::LinkState, Safi::LinkState) => 1 << 6,
            (Afi::LinkState, Safi::LinkStateVpn) => 1 << 7,
            _ => 0,
        }
    }
}

/// Message encoding format based on negotiated capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageFormat {
    /// Whether to use 4-byte ASN encoding (RFC 6793)
    pub use_4byte_asn: bool,
    /// Which AFI/SAFI combos use ADD-PATH encoding (RFC 7911)
    pub add_path: AddPathMask,
    /// Whether this is an eBGP session (RFC 7606 error handling, attribute stripping)
    pub is_ebgp: bool,
    /// Whether Enhanced Route Refresh (RFC 7313) was negotiated
    pub enhanced_rr: bool,
}

/// Format for parsing OPEN messages, before capabilities are negotiated.
/// OPEN always uses 2-byte ASN (RFC 6793) and no ADD-PATH.
pub const PRE_OPEN_FORMAT: MessageFormat = MessageFormat {
    use_4byte_asn: false,
    add_path: AddPathMask::NONE,
    is_ebgp: false,
    enhanced_rr: false,
};

// BGP header marker (16 bytes of 0xFF)
pub const BGP_MARKER: [u8; 16] = [0xff; 16];

#[repr(u8)]
#[derive(Clone, Copy)]
pub enum MessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5,
}

impl MessageType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Trait for BGP message types that can serialize themselves
pub trait Message {
    /// Returns the message type identifier
    fn kind(&self) -> MessageType;

    /// Serializes the message body (without BGP header)
    fn to_bytes(&self) -> Vec<u8>;

    /// Serializes the complete BGP message with header
    ///
    /// This method has a default implementation that uses to_bytes()
    /// and adds the BGP header automatically.
    fn serialize(&self) -> Vec<u8> {
        let body = self.to_bytes();
        let mut message = Vec::new();

        // BGP header marker (16 bytes of 0xFF)
        message.extend_from_slice(&BGP_MARKER);

        // Message length (header + body)
        let length = BGP_HEADER_SIZE_BYTES as u16 + body.len() as u16;
        message.extend_from_slice(&length.to_be_bytes());

        // Message type
        message.push(self.kind().as_u8());

        // Message body
        message.extend_from_slice(&body);

        message
    }
}

impl TryFrom<u8> for MessageType {
    type Error = ParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MessageType::Open),
            2 => Ok(MessageType::Update),
            3 => Ok(MessageType::Notification),
            4 => Ok(MessageType::Keepalive),
            5 => Ok(MessageType::RouteRefresh),
            _ => Err(ParserError::BgpError {
                error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageType),
                data: vec![value],
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub enum BgpMessage {
    Open(OpenMessage),
    Update(UpdateMessage),
    Keepalive(KeepaliveMessage),
    Notification(NotificationMessage),
    RouteRefresh(RouteRefreshMessage),
}

impl BgpMessage {
    /// Serialize the BGP message to bytes with BGP header
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Open(m) => m.serialize(),
            Self::Update(m) => m.serialize(),
            Self::Keepalive(m) => m.serialize(),
            Self::Notification(m) => m.serialize(),
            Self::RouteRefresh(m) => m.serialize(),
        }
    }

    pub fn from_bytes(
        msg_type: u8,
        body: Vec<u8>,
        full_msg: &[u8],
        format: MessageFormat,
    ) -> Result<Self, ParserError> {
        let message_type = MessageType::try_from(msg_type)?;

        match message_type {
            MessageType::Open => {
                let message = OpenMessage::from_bytes(body)?;
                Ok(BgpMessage::Open(message))
            }
            MessageType::Update => {
                let message = UpdateMessage::from_bytes(body, format)?;
                Ok(BgpMessage::Update(message))
            }
            MessageType::Keepalive => Ok(BgpMessage::Keepalive(KeepaliveMessage {})),
            MessageType::Notification => {
                let message = NotificationMessage::from_bytes(body);
                Ok(BgpMessage::Notification(message))
            }
            MessageType::RouteRefresh => {
                let message = RouteRefreshMessage::from_bytes(body, full_msg, format.enhanced_rr)?;
                Ok(BgpMessage::RouteRefresh(message))
            }
        }
    }
}

/// Read complete BGP message (header + body) as raw bytes without parsing.
/// Returns the complete message including the 19-byte header.
///
/// This function validates the header (marker, length, type) but does not
/// parse the message body. Header validation errors are returned as ParserError.
pub async fn read_bgp_message_bytes<R: AsyncReadExt + Unpin>(
    mut stream: R,
) -> Result<Vec<u8>, ParserError> {
    let mut header_buffer = [0u8; BGP_HEADER_SIZE_BYTES];

    stream
        .read_exact(&mut header_buffer)
        .await
        .map_err(|err| ParserError::IoError(err.to_string()))?;

    // Validate header fields (RFC 4271 Section 6.1)
    validate_marker(&header_buffer)?;

    let message_length = u16::from_be_bytes([header_buffer[16], header_buffer[17]]);
    let message_type = header_buffer[18];

    validate_length(message_length, message_type)?;
    validate_message_type(message_type)?;

    // Build complete message (header + body)
    let mut message = header_buffer.to_vec();
    let body_length = message_length - BGP_HEADER_SIZE_BYTES as u16;

    if body_length > 0 {
        let mut body_buffer = vec![0u8; body_length as usize];
        stream
            .read_exact(&mut body_buffer)
            .await
            .map_err(|err| ParserError::IoError(err.to_string()))?;
        message.extend_from_slice(&body_buffer);
    }

    Ok(message)
}

/// Read and parse a BGP message.
///
/// NOTE: This is a convenience wrapper for tests and utilities. Production code should use
/// `read_bgp_message_bytes()` and parse separately with negotiated capabilities.
pub async fn read_bgp_message<R: AsyncReadExt + Unpin>(
    stream: R,
    format: MessageFormat,
) -> Result<BgpMessage, ParserError> {
    let full_msg = read_bgp_message_bytes(stream).await?;
    let message_type = full_msg[18];
    let body = full_msg[BGP_HEADER_SIZE_BYTES..].to_vec();
    BgpMessage::from_bytes(message_type, body, &full_msg, format)
}

fn validate_marker(header: &[u8]) -> Result<(), ParserError> {
    if header[0..16] != BGP_MARKER {
        return Err(ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized),
            data: Vec::new(),
        });
    }
    Ok(())
}

fn validate_length(message_length: u16, message_type: u8) -> Result<(), ParserError> {
    if message_length < BGP_HEADER_SIZE_BYTES as u16 {
        return Err(ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            data: message_length.to_be_bytes().to_vec(),
        });
    }

    if message_length > MAX_MESSAGE_SIZE {
        return Err(ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            data: message_length.to_be_bytes().to_vec(),
        });
    }

    // Validate message-type-specific length
    if message_type == MessageType::Keepalive.as_u8()
        && message_length != BGP_HEADER_SIZE_BYTES as u16
    {
        return Err(ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            data: message_length.to_be_bytes().to_vec(),
        });
    }

    // NOTIFICATION minimum length is 21 (19 header + 2 for error code/subcode)
    if message_type == MessageType::Notification.as_u8() && message_length < 21 {
        return Err(ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            data: message_length.to_be_bytes().to_vec(),
        });
    }

    Ok(())
}

fn validate_message_type(message_type: u8) -> Result<(), ParserError> {
    MessageType::try_from(message_type)
        .map(|_| ())
        .map_err(|_| ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageType),
            data: vec![message_type],
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::DEFAULT_FORMAT;
    use std::io::Cursor;

    const MOCK_OPEN_MESSAGE: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x1d, // Message length (29 bytes)
        0x01, // Message type (Open)
        0x04, // Version
        0x04, 0xd2, // ASN
        0x00, 0x0a, // Hold time
        0x0a, 0x0a, 0x0a, 0x0a, // BGP identififer
        0x00, // Optional parameters length
    ];

    #[tokio::test]
    async fn test_read_open_message() {
        let stream = Cursor::new(MOCK_OPEN_MESSAGE);

        match read_bgp_message(stream, DEFAULT_FORMAT).await.unwrap() {
            BgpMessage::Open(open_message) => {
                assert_eq!(open_message.version, 4);
                assert_eq!(open_message.asn, 1234);
                assert_eq!(open_message.hold_time, 10);
                assert_eq!(open_message.bgp_identifier, 168430090);
                assert_eq!(open_message.optional_params_len, 0);
                assert_eq!(open_message.optional_params, vec![]);
            }
            _ => panic!("Expected BgpMessage::OPEN"),
        }
    }

    #[tokio::test]
    async fn test_read_message_invalid_marker() {
        let mut msg = MOCK_OPEN_MESSAGE.to_vec();
        msg[0] = 0x00;
        let stream = Cursor::new(msg);
        match read_bgp_message(stream, DEFAULT_FORMAT).await {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized)
                );
                assert_eq!(data, Vec::<u8>::new());
            }
            _ => panic!("Expected InvalidMarker error"),
        }
    }

    #[tokio::test]
    async fn test_read_message_length_too_small() {
        let mut msg = MOCK_OPEN_MESSAGE.to_vec();
        msg[16] = 0x00;
        msg[17] = 0x12; // 18
        let stream = Cursor::new(msg);
        match read_bgp_message(stream, DEFAULT_FORMAT).await {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength)
                );
                assert_eq!(data, vec![0x00, 0x12]); // Erroneous length field
            }
            _ => panic!("Expected BadMessageLength error"),
        }
    }

    #[tokio::test]
    async fn test_read_message_length_too_large() {
        let mut msg = MOCK_OPEN_MESSAGE.to_vec();
        msg[16] = 0x10;
        msg[17] = 0x01; // 4097
        let stream = Cursor::new(msg);
        match read_bgp_message(stream, DEFAULT_FORMAT).await {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength)
                );
                assert_eq!(data, vec![0x10, 0x01]); // Erroneous length field
            }
            _ => panic!("Expected BadMessageLength error"),
        }
    }

    #[tokio::test]
    async fn test_read_message_invalid_type() {
        let mut msg = MOCK_OPEN_MESSAGE.to_vec();
        msg[18] = 99;
        let stream = Cursor::new(msg);
        match read_bgp_message(stream, DEFAULT_FORMAT).await {
            Err(ParserError::BgpError { error, data }) => {
                assert_eq!(
                    error,
                    BgpError::MessageHeaderError(MessageHeaderError::BadMessageType)
                );
                assert_eq!(data, vec![99]); // Erroneous type field
            }
            _ => panic!("Expected BadMessageType error"),
        }
    }
}
