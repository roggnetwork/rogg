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

//! RTR (RPKI-to-Router) Protocol v1 codec (RFC 8210).
//!
//! Parse and serialize messages for communication with RPKI cache servers.
//! Protocol version 1 only -- v0 messages are rejected with Error Report
//! code 4 (Unsupported Protocol Version).

use crate::log::warn;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::AsyncReadExt;

/// RTR protocol version 1 (RFC 8210).
pub const PROTOCOL_VERSION: u8 = 1;

/// RTR message header size: version (1) + type (1) + session_id (2) + length (4) = 8 bytes.
pub const HEADER_SIZE: usize = 8;

/// Maximum message size. RFC 8210 doesn't set a hard max, but Error Report
/// contains variable-length text. Cap at 64KB to bound memory usage.
pub const MAX_MESSAGE_SIZE: u32 = 65536;

/// Default refresh interval in seconds (RFC 8210 Section 6).
pub const DEFAULT_REFRESH_INTERVAL: u64 = 3600;

/// Default retry interval in seconds (RFC 8210 Section 6).
pub const DEFAULT_RETRY_INTERVAL: u64 = 600;

/// Default expire interval in seconds (RFC 8210 Section 6).
pub const DEFAULT_EXPIRE_INTERVAL: u64 = 7200;

/// RTR serial number with RFC 1982 comparison semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Serial(pub u32);

impl PartialOrd for Serial {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Serial {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if self.0 == other.0 {
            std::cmp::Ordering::Equal
        } else if (other.0.wrapping_sub(self.0) as i32) > 0 {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    }
}

/// RTR message type codes (RFC 8210 Section 5).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    SerialNotify = 0,
    SerialQuery = 1,
    ResetQuery = 2,
    CacheResponse = 3,
    Ipv4Prefix = 4,
    Ipv6Prefix = 6,
    EndOfData = 7,
    CacheReset = 8,
    RouterKey = 9,
    ErrorReport = 10,
}

impl MessageType {
    fn from_u8(val: u8) -> Option<MessageType> {
        match val {
            0 => Some(MessageType::SerialNotify),
            1 => Some(MessageType::SerialQuery),
            2 => Some(MessageType::ResetQuery),
            3 => Some(MessageType::CacheResponse),
            4 => Some(MessageType::Ipv4Prefix),
            // 5 is IPv4 Prefix in v0, but in v1 it's reserved
            6 => Some(MessageType::Ipv6Prefix),
            7 => Some(MessageType::EndOfData),
            8 => Some(MessageType::CacheReset),
            9 => Some(MessageType::RouterKey),
            10 => Some(MessageType::ErrorReport),
            _ => None,
        }
    }
}

/// RTR Error Report codes (RFC 8210 Section 10).
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    CorruptData = 0,
    InternalError = 1,
    NoDataAvailable = 2,
    InvalidRequest = 3,
    UnsupportedProtocolVersion = 4,
    UnsupportedMessageType = 5,
    WithdrawalOfUnknownRecord = 6,
    DuplicateAnnouncementReceived = 7,
    UnexpectedProtocolVersion = 8,
}

impl ErrorCode {
    fn from_u16(val: u16) -> Option<ErrorCode> {
        match val {
            0 => Some(ErrorCode::CorruptData),
            1 => Some(ErrorCode::InternalError),
            2 => Some(ErrorCode::NoDataAvailable),
            3 => Some(ErrorCode::InvalidRequest),
            4 => Some(ErrorCode::UnsupportedProtocolVersion),
            5 => Some(ErrorCode::UnsupportedMessageType),
            6 => Some(ErrorCode::WithdrawalOfUnknownRecord),
            7 => Some(ErrorCode::DuplicateAnnouncementReceived),
            8 => Some(ErrorCode::UnexpectedProtocolVersion),
            _ => None,
        }
    }
}

/// Codec error for RTR message parsing.
#[derive(Debug)]
pub enum ParseError {
    /// Too short to contain the expected fields.
    TooShort { expected: usize, actual: usize },
    /// Length field doesn't match expected fixed size.
    InvalidLength {
        message_type: MessageType,
        length: u32,
    },
    /// Unknown message type code.
    UnknownMessageType(u8),
    /// Wrong protocol version (not v1).
    UnsupportedVersion(u8),
    /// Unknown error code in Error Report.
    UnknownErrorCode(u16),
    /// Error Report has inconsistent internal lengths.
    MalformedErrorReport,
    /// Error Report error text is not valid UTF-8.
    InvalidErrorText,
}

// -- Message structs --

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerialNotify {
    pub session_id: u16,
    pub serial: Serial,
}

impl SerialNotify {
    const TYPE_CODE: u8 = MessageType::SerialNotify as u8;

    fn to_bytes(&self) -> Vec<u8> {
        self.serial.0.to_be_bytes().to_vec()
    }

    fn parse(session_id: u16, length: u32, body: &[u8]) -> Result<Self, ParseError> {
        if length != 12 {
            return Err(ParseError::InvalidLength {
                message_type: MessageType::SerialNotify,
                length,
            });
        }
        let serial = Serial(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
        Ok(SerialNotify { session_id, serial })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SerialQuery {
    pub session_id: u16,
    pub serial: Serial,
}

impl SerialQuery {
    const TYPE_CODE: u8 = MessageType::SerialQuery as u8;

    fn to_bytes(&self) -> Vec<u8> {
        self.serial.0.to_be_bytes().to_vec()
    }

    fn parse(session_id: u16, length: u32, body: &[u8]) -> Result<Self, ParseError> {
        if length != 12 {
            return Err(ParseError::InvalidLength {
                message_type: MessageType::SerialQuery,
                length,
            });
        }
        let serial = Serial(u32::from_be_bytes([body[0], body[1], body[2], body[3]]));
        Ok(SerialQuery { session_id, serial })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResetQuery;

impl ResetQuery {
    const TYPE_CODE: u8 = MessageType::ResetQuery as u8;

    fn parse(length: u32) -> Result<Self, ParseError> {
        if length != 8 {
            return Err(ParseError::InvalidLength {
                message_type: MessageType::ResetQuery,
                length,
            });
        }
        Ok(ResetQuery)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheResponse {
    pub session_id: u16,
}

impl CacheResponse {
    const TYPE_CODE: u8 = MessageType::CacheResponse as u8;

    fn parse(session_id: u16, length: u32) -> Result<Self, ParseError> {
        if length != 8 {
            return Err(ParseError::InvalidLength {
                message_type: MessageType::CacheResponse,
                length,
            });
        }
        Ok(CacheResponse { session_id })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Prefix {
    pub flags: u8,
    pub prefix_length: u8,
    pub max_length: u8,
    pub prefix: Ipv4Addr,
    pub asn: u32,
}

impl Ipv4Prefix {
    const TYPE_CODE: u8 = MessageType::Ipv4Prefix as u8;

    pub fn is_announcement(&self) -> bool {
        self.flags & 0x01 != 0
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(12);
        body.push(self.flags);
        body.push(self.prefix_length);
        body.push(self.max_length);
        body.push(0);
        body.extend_from_slice(&self.prefix.octets());
        body.extend_from_slice(&self.asn.to_be_bytes());
        body
    }

    fn parse(length: u32, body: &[u8]) -> Result<Self, ParseError> {
        if length != 20 {
            return Err(ParseError::InvalidLength {
                message_type: MessageType::Ipv4Prefix,
                length,
            });
        }
        Ok(Ipv4Prefix {
            flags: body[0],
            prefix_length: body[1],
            max_length: body[2],
            prefix: Ipv4Addr::new(body[4], body[5], body[6], body[7]),
            asn: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Prefix {
    pub flags: u8,
    pub prefix_length: u8,
    pub max_length: u8,
    pub prefix: Ipv6Addr,
    pub asn: u32,
}

impl Ipv6Prefix {
    const TYPE_CODE: u8 = MessageType::Ipv6Prefix as u8;

    pub fn is_announcement(&self) -> bool {
        self.flags & 0x01 != 0
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(24);
        body.push(self.flags);
        body.push(self.prefix_length);
        body.push(self.max_length);
        body.push(0);
        body.extend_from_slice(&self.prefix.octets());
        body.extend_from_slice(&self.asn.to_be_bytes());
        body
    }

    fn parse(length: u32, body: &[u8]) -> Result<Self, ParseError> {
        if length != 32 {
            return Err(ParseError::InvalidLength {
                message_type: MessageType::Ipv6Prefix,
                length,
            });
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&body[4..20]);
        Ok(Ipv6Prefix {
            flags: body[0],
            prefix_length: body[1],
            max_length: body[2],
            prefix: Ipv6Addr::from(octets),
            asn: u32::from_be_bytes([body[20], body[21], body[22], body[23]]),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndOfData {
    pub session_id: u16,
    pub serial: Serial,
    pub refresh_interval: u32,
    pub retry_interval: u32,
    pub expire_interval: u32,
}

impl EndOfData {
    const TYPE_CODE: u8 = MessageType::EndOfData as u8;

    /// Return validated (refresh, retry, expire) intervals per RFC 8210 Section 6.
    /// Out-of-range values are clamped and logged.
    pub fn get_timers(&self) -> (u64, u64, u64) {
        let refresh = (self.refresh_interval as u64).clamp(1, 86400);
        if refresh != self.refresh_interval as u64 {
            warn!(
                raw = self.refresh_interval,
                clamped = refresh,
                "refresh interval out of range, clamped"
            );
        }

        let retry = (self.retry_interval as u64).clamp(1, 7200);
        if retry != self.retry_interval as u64 {
            warn!(
                raw = self.retry_interval,
                clamped = retry,
                "retry interval out of range, clamped"
            );
        }

        let mut expire = (self.expire_interval as u64).clamp(600, 172800);
        if expire != self.expire_interval as u64 {
            warn!(
                raw = self.expire_interval,
                clamped = expire,
                "expire interval out of range, clamped"
            );
        }

        // expire must be > max(refresh, retry)
        let min_expire = refresh.max(retry) + 1;
        if expire < min_expire {
            warn!(expire, min_expire, "expire interval too small, adjusted");
            expire = min_expire;
        }

        (refresh, retry, expire)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(16);
        body.extend_from_slice(&self.serial.0.to_be_bytes());
        body.extend_from_slice(&self.refresh_interval.to_be_bytes());
        body.extend_from_slice(&self.retry_interval.to_be_bytes());
        body.extend_from_slice(&self.expire_interval.to_be_bytes());
        body
    }

    fn parse(session_id: u16, length: u32, body: &[u8]) -> Result<Self, ParseError> {
        if length != 24 {
            return Err(ParseError::InvalidLength {
                message_type: MessageType::EndOfData,
                length,
            });
        }
        Ok(EndOfData {
            session_id,
            serial: Serial(u32::from_be_bytes([body[0], body[1], body[2], body[3]])),
            refresh_interval: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
            retry_interval: u32::from_be_bytes([body[8], body[9], body[10], body[11]]),
            expire_interval: u32::from_be_bytes([body[12], body[13], body[14], body[15]]),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheReset;

impl CacheReset {
    const TYPE_CODE: u8 = MessageType::CacheReset as u8;

    fn parse(length: u32) -> Result<Self, ParseError> {
        if length != 8 {
            return Err(ParseError::InvalidLength {
                message_type: MessageType::CacheReset,
                length,
            });
        }
        Ok(CacheReset)
    }
}

/// BGPsec router key. Parsed but not used -- bgpgg does not implement BGPsec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterKey {
    pub flags: u8,
    pub subject_key_identifier: [u8; 20],
    pub asn: u32,
    pub subject_public_key_info: Vec<u8>,
}

impl RouterKey {
    const TYPE_CODE: u8 = MessageType::RouterKey as u8;

    fn to_bytes(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(24 + self.subject_public_key_info.len());
        body.extend_from_slice(&self.subject_key_identifier);
        body.extend_from_slice(&self.asn.to_be_bytes());
        body.extend_from_slice(&self.subject_public_key_info);
        body
    }

    fn parse(flags: u8, length: u32, body: &[u8]) -> Result<Self, ParseError> {
        if length < 32 {
            return Err(ParseError::InvalidLength {
                message_type: MessageType::RouterKey,
                length,
            });
        }
        let mut ski = [0u8; 20];
        ski.copy_from_slice(&body[0..20]);
        Ok(RouterKey {
            flags,
            subject_key_identifier: ski,
            asn: u32::from_be_bytes([body[20], body[21], body[22], body[23]]),
            subject_public_key_info: body[24..].to_vec(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorReport {
    pub error_code: ErrorCode,
    pub erroneous_pdu: Option<Vec<u8>>,
    pub error_text: String,
}

impl ErrorReport {
    const TYPE_CODE: u8 = MessageType::ErrorReport as u8;

    fn to_bytes(&self) -> Vec<u8> {
        let erroneous_bytes = self.erroneous_pdu.as_deref().unwrap_or(&[]);
        let text_bytes = self.error_text.as_bytes();
        let mut body = Vec::with_capacity(4 + erroneous_bytes.len() + 4 + text_bytes.len());
        body.extend_from_slice(&(erroneous_bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(erroneous_bytes);
        body.extend_from_slice(&(text_bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(text_bytes);
        body
    }

    fn parse(error_code: ErrorCode, length: u32, body: &[u8]) -> Result<Self, ParseError> {
        if length < 16 {
            return Err(ParseError::InvalidLength {
                message_type: MessageType::ErrorReport,
                length,
            });
        }

        let body_len = body.len();
        if body_len < 8 {
            return Err(ParseError::MalformedErrorReport);
        }

        let erroneous_pdu_length =
            u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;

        if body_len < 4 + erroneous_pdu_length + 4 {
            return Err(ParseError::MalformedErrorReport);
        }

        let erroneous_pdu = if erroneous_pdu_length > 0 {
            Some(body[4..4 + erroneous_pdu_length].to_vec())
        } else {
            None
        };

        let text_offset = 4 + erroneous_pdu_length;
        let error_text_length = u32::from_be_bytes([
            body[text_offset],
            body[text_offset + 1],
            body[text_offset + 2],
            body[text_offset + 3],
        ]) as usize;

        let text_data_offset = text_offset + 4;
        if body_len < text_data_offset + error_text_length {
            return Err(ParseError::MalformedErrorReport);
        }

        let error_text = if error_text_length > 0 {
            std::str::from_utf8(&body[text_data_offset..text_data_offset + error_text_length])
                .map_err(|_| ParseError::InvalidErrorText)?
                .to_string()
        } else {
            String::new()
        };

        Ok(ErrorReport {
            error_code,
            erroneous_pdu,
            error_text,
        })
    }
}

// -- Message enum --

/// Parsed RTR message (RFC 8210).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    SerialNotify(SerialNotify),
    SerialQuery(SerialQuery),
    ResetQuery(ResetQuery),
    CacheResponse(CacheResponse),
    Ipv4Prefix(Ipv4Prefix),
    Ipv6Prefix(Ipv6Prefix),
    EndOfData(EndOfData),
    CacheReset(CacheReset),
    RouterKey(RouterKey),
    ErrorReport(ErrorReport),
}

impl Message {
    /// Parse an RTR message from a byte buffer.
    ///
    /// The buffer must contain a complete message including the 8-byte header.
    /// Returns the parsed message and the number of bytes consumed.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Message, usize), ParseError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ParseError::TooShort {
                expected: HEADER_SIZE,
                actual: bytes.len(),
            });
        }

        let version = bytes[0];
        if version != PROTOCOL_VERSION {
            return Err(ParseError::UnsupportedVersion(version));
        }

        let type_val = bytes[1];
        let session_id = u16::from_be_bytes([bytes[2], bytes[3]]);
        let length = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        if length < HEADER_SIZE as u32 || length > MAX_MESSAGE_SIZE {
            let message_type =
                MessageType::from_u8(type_val).ok_or(ParseError::UnknownMessageType(type_val))?;
            return Err(ParseError::InvalidLength {
                message_type,
                length,
            });
        }

        if bytes.len() < length as usize {
            return Err(ParseError::TooShort {
                expected: length as usize,
                actual: bytes.len(),
            });
        }

        let message_type =
            MessageType::from_u8(type_val).ok_or(ParseError::UnknownMessageType(type_val))?;
        let body = &bytes[HEADER_SIZE..length as usize];

        let msg = match message_type {
            MessageType::SerialNotify => {
                Message::SerialNotify(SerialNotify::parse(session_id, length, body)?)
            }
            MessageType::SerialQuery => {
                Message::SerialQuery(SerialQuery::parse(session_id, length, body)?)
            }
            MessageType::ResetQuery => Message::ResetQuery(ResetQuery::parse(length)?),
            MessageType::CacheResponse => {
                Message::CacheResponse(CacheResponse::parse(session_id, length)?)
            }
            MessageType::Ipv4Prefix => Message::Ipv4Prefix(Ipv4Prefix::parse(length, body)?),
            MessageType::Ipv6Prefix => Message::Ipv6Prefix(Ipv6Prefix::parse(length, body)?),
            MessageType::EndOfData => {
                Message::EndOfData(EndOfData::parse(session_id, length, body)?)
            }
            MessageType::CacheReset => Message::CacheReset(CacheReset::parse(length)?),
            MessageType::RouterKey => {
                let flags = bytes[2]; // high byte of session_id field
                Message::RouterKey(RouterKey::parse(flags, length, body)?)
            }
            MessageType::ErrorReport => {
                let error_code = ErrorCode::from_u16(session_id)
                    .ok_or(ParseError::UnknownErrorCode(session_id))?;
                Message::ErrorReport(ErrorReport::parse(error_code, length, body)?)
            }
        };

        Ok((msg, length as usize))
    }

    /// Serialize the complete message with the 8-byte header.
    pub fn serialize(&self) -> Vec<u8> {
        let (type_code, session_id, body) = match self {
            Message::SerialNotify(m) => (SerialNotify::TYPE_CODE, m.session_id, m.to_bytes()),
            Message::SerialQuery(m) => (SerialQuery::TYPE_CODE, m.session_id, m.to_bytes()),
            Message::ResetQuery(_) => (ResetQuery::TYPE_CODE, 0, Vec::new()),
            Message::CacheResponse(m) => (CacheResponse::TYPE_CODE, m.session_id, Vec::new()),
            Message::Ipv4Prefix(m) => (Ipv4Prefix::TYPE_CODE, 0, m.to_bytes()),
            Message::Ipv6Prefix(m) => (Ipv6Prefix::TYPE_CODE, 0, m.to_bytes()),
            Message::EndOfData(m) => (EndOfData::TYPE_CODE, m.session_id, m.to_bytes()),
            Message::CacheReset(_) => (CacheReset::TYPE_CODE, 0, Vec::new()),
            Message::RouterKey(m) => (RouterKey::TYPE_CODE, (m.flags as u16) << 8, m.to_bytes()),
            Message::ErrorReport(m) => (ErrorReport::TYPE_CODE, m.error_code as u16, m.to_bytes()),
        };
        let length = (HEADER_SIZE + body.len()) as u32;
        let mut buf = Vec::with_capacity(length as usize);
        buf.push(PROTOCOL_VERSION);
        buf.push(type_code);
        buf.extend_from_slice(&session_id.to_be_bytes());
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(&body);
        buf
    }
}

/// Read buffer size for RTR PDU ingestion.
const READ_BUF_SIZE: usize = 4096;

/// Errors from reading RTR messages off a stream.
#[derive(Debug)]
pub enum RtrReadError {
    /// Connection closed cleanly (EOF).
    Eof,
    /// IO error during read.
    Io(std::io::Error),
    /// RTR parse error on a complete PDU.
    Parse(ParseError),
    /// Message length field exceeds MAX_MESSAGE_SIZE.
    MessageTooLarge(usize),
}

/// Buffered reader that extracts complete RTR messages from a byte stream.
pub struct RtrReader<R> {
    reader: R,
    buf: Vec<u8>,
}

impl<R: AsyncReadExt + Unpin> RtrReader<R> {
    pub fn new(reader: R) -> Self {
        RtrReader {
            reader,
            buf: Vec::with_capacity(READ_BUF_SIZE),
        }
    }

    /// Read the next complete RTR message from the stream.
    pub async fn next_message(&mut self) -> Result<Message, RtrReadError> {
        loop {
            // Try to extract a complete message from the buffer
            if self.buf.len() >= HEADER_SIZE {
                let msg_len =
                    u32::from_be_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]])
                        as usize;
                if msg_len > MAX_MESSAGE_SIZE as usize {
                    return Err(RtrReadError::MessageTooLarge(msg_len));
                }
                if self.buf.len() >= msg_len {
                    let (msg, consumed) =
                        Message::from_bytes(&self.buf[..msg_len]).map_err(RtrReadError::Parse)?;
                    self.buf.drain(..consumed);
                    return Ok(msg);
                }
            }

            // Need more data
            let mut read_buf = [0u8; READ_BUF_SIZE];
            match self.reader.read(&mut read_buf).await {
                Ok(0) => return Err(RtrReadError::Eof),
                Ok(n) => self.buf.extend_from_slice(&read_buf[..n]),
                Err(err) => return Err(RtrReadError::Io(err)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_of_data_get_timers() {
        let make_eod = |refresh, retry, expire| EndOfData {
            session_id: 0,
            serial: Serial(0),
            refresh_interval: refresh,
            retry_interval: retry,
            expire_interval: expire,
        };
        let cases = vec![
            ("defaults", make_eod(3600, 600, 7200), (3600, 600, 7200)),
            (
                "clamp refresh too low",
                make_eod(0, 600, 7200),
                (1, 600, 7200),
            ),
            (
                "clamp refresh too high",
                make_eod(100000, 600, 7200),
                (86400, 600, 86401),
            ),
            (
                "clamp retry too low",
                make_eod(3600, 0, 7200),
                (3600, 1, 7200),
            ),
            (
                "clamp retry too high",
                make_eod(3600, 10000, 7200),
                (3600, 7200, 7201),
            ),
            (
                "clamp expire too low",
                make_eod(3600, 600, 100),
                (3600, 600, 3601),
            ),
            (
                "clamp expire too high",
                make_eod(3600, 600, 200000),
                (3600, 600, 172800),
            ),
            (
                "expire must exceed max(refresh, retry)",
                make_eod(3600, 600, 3600),
                (3600, 600, 3601),
            ),
        ];
        for (name, eod, expected) in cases {
            assert_eq!(eod.get_timers(), expected, "case: {}", name);
        }
    }

    #[test]
    fn test_serial_compare() {
        use std::cmp::Ordering;
        let cases = vec![
            ("equal", 100, 100, Ordering::Equal),
            ("simple less", 1, 2, Ordering::Less),
            ("simple greater", 2, 1, Ordering::Greater),
            ("wraparound less", u32::MAX, 0, Ordering::Less),
            ("wraparound greater", 0, u32::MAX, Ordering::Greater),
            ("large gap less", 1, u32::MAX / 2, Ordering::Less),
            // s1=2^31+1, s2=1: difference is exactly 2^31, undefined in RFC 1982
            ("large gap boundary", u32::MAX / 2 + 2, 1, Ordering::Greater),
            ("zero and one", 0, 1, Ordering::Less),
            ("max and max-1", u32::MAX, u32::MAX - 1, Ordering::Greater),
        ];
        for (name, s1, s2, expected) in cases {
            assert_eq!(
                Serial(s1).cmp(&Serial(s2)),
                expected,
                "case: {} (s1={}, s2={})",
                name,
                s1,
                s2
            );
        }
    }

    #[test]
    fn test_prefix_is_announcement() {
        let cases = vec![
            ("flags 0 is withdrawal", 0u8, false),
            ("flags 1 is announcement", 1, true),
            ("only low bit matters", 0xFE, false),
            ("low bit set with others", 0xFF, true),
        ];
        for (name, flags, expected) in cases {
            let v4 = Ipv4Prefix {
                flags,
                prefix_length: 24,
                max_length: 24,
                prefix: Ipv4Addr::LOCALHOST,
                asn: 0,
            };
            let v6 = Ipv6Prefix {
                flags,
                prefix_length: 48,
                max_length: 48,
                prefix: Ipv6Addr::LOCALHOST,
                asn: 0,
            };
            assert_eq!(v4.is_announcement(), expected, "v4 case: {}", name);
            assert_eq!(v6.is_announcement(), expected, "v6 case: {}", name);
        }
    }

    fn roundtrip(msg: &Message) -> Message {
        let bytes = msg.serialize();
        let (parsed, consumed) = Message::from_bytes(&bytes).expect("parse failed");
        assert_eq!(consumed, bytes.len());
        parsed
    }

    #[test]
    fn test_serial_notify_roundtrip() {
        let cases = vec![
            ("zero serial", 0u16, Serial(0)),
            ("typical", 1234, Serial(56789)),
            ("max values", u16::MAX, Serial(u32::MAX)),
        ];
        for (name, session_id, serial) in cases {
            let msg = Message::SerialNotify(SerialNotify { session_id, serial });
            let parsed = roundtrip(&msg);
            assert_eq!(msg, parsed, "case: {}", name);
        }
    }

    #[test]
    fn test_serial_query_roundtrip() {
        let cases = vec![
            ("zero", 0u16, Serial(0)),
            ("typical", 42, Serial(100)),
            ("max", u16::MAX, Serial(u32::MAX)),
        ];
        for (name, session_id, serial) in cases {
            let msg = Message::SerialQuery(SerialQuery { session_id, serial });
            let parsed = roundtrip(&msg);
            assert_eq!(msg, parsed, "case: {}", name);
        }
    }

    #[test]
    fn test_reset_query_roundtrip() {
        let msg = Message::ResetQuery(ResetQuery);
        let parsed = roundtrip(&msg);
        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_cache_response_roundtrip() {
        let cases = vec![("zero", 0u16), ("typical", 5555), ("max", u16::MAX)];
        for (name, session_id) in cases {
            let msg = Message::CacheResponse(CacheResponse { session_id });
            let parsed = roundtrip(&msg);
            assert_eq!(msg, parsed, "case: {}", name);
        }
    }

    #[test]
    fn test_ipv4_prefix_roundtrip() {
        let cases = vec![
            (
                "announce",
                1u8,
                24u8,
                24u8,
                Ipv4Addr::new(10, 0, 0, 0),
                65001u32,
            ),
            ("withdraw", 0, 16, 24, Ipv4Addr::new(192, 168, 0, 0), 65002),
            (
                "max prefix",
                1,
                32,
                32,
                Ipv4Addr::new(255, 255, 255, 255),
                u32::MAX,
            ),
            ("default route", 1, 0, 0, Ipv4Addr::new(0, 0, 0, 0), 0),
        ];
        for (name, flags, prefix_length, max_length, prefix, asn) in cases {
            let msg = Message::Ipv4Prefix(Ipv4Prefix {
                flags,
                prefix_length,
                max_length,
                prefix,
                asn,
            });
            let parsed = roundtrip(&msg);
            assert_eq!(msg, parsed, "case: {}", name);
        }
    }

    #[test]
    fn test_ipv6_prefix_roundtrip() {
        let cases = vec![
            (
                "announce",
                1u8,
                48u8,
                48u8,
                Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
                65001u32,
            ),
            (
                "withdraw",
                0,
                32,
                48,
                Ipv6Addr::new(0x2001, 0x0db8, 0xabcd, 0, 0, 0, 0, 0),
                65002,
            ),
            (
                "max prefix",
                1,
                128,
                128,
                Ipv6Addr::new(
                    0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                ),
                u32::MAX,
            ),
        ];
        for (name, flags, prefix_length, max_length, prefix, asn) in cases {
            let msg = Message::Ipv6Prefix(Ipv6Prefix {
                flags,
                prefix_length,
                max_length,
                prefix,
                asn,
            });
            let parsed = roundtrip(&msg);
            assert_eq!(msg, parsed, "case: {}", name);
        }
    }

    #[test]
    fn test_end_of_data_roundtrip() {
        let cases = vec![
            ("defaults", 1u16, Serial(1), 3600u32, 600u32, 7200u32),
            ("custom", 42, Serial(999), 1800, 300, 14400),
            (
                "max",
                u16::MAX,
                Serial(u32::MAX),
                u32::MAX,
                u32::MAX,
                u32::MAX,
            ),
        ];
        for (name, session_id, serial, refresh, retry, expire) in cases {
            let msg = Message::EndOfData(EndOfData {
                session_id,
                serial,
                refresh_interval: refresh,
                retry_interval: retry,
                expire_interval: expire,
            });
            let parsed = roundtrip(&msg);
            assert_eq!(msg, parsed, "case: {}", name);
        }
    }

    #[test]
    fn test_cache_reset_roundtrip() {
        let msg = Message::CacheReset(CacheReset);
        let parsed = roundtrip(&msg);
        assert_eq!(msg, parsed);
    }

    #[test]
    fn test_router_key_roundtrip() {
        let cases = vec![
            ("announce", 1u8, [0xAA; 20], 65001u32, vec![1, 2, 3, 4]),
            ("withdraw", 0, [0xBB; 20], 65002, vec![]),
            ("large spki", 1, [0xCC; 20], 12345, vec![0xFF; 256]),
        ];
        for (name, flags, ski, asn, spki) in cases {
            let msg = Message::RouterKey(RouterKey {
                flags,
                subject_key_identifier: ski,
                asn,
                subject_public_key_info: spki,
            });
            let parsed = roundtrip(&msg);
            assert_eq!(msg, parsed, "case: {}", name);
        }
    }

    #[test]
    fn test_error_report_roundtrip() {
        let cases = vec![
            (
                "with pdu and text",
                ErrorCode::CorruptData,
                Some(vec![1, 2, 3]),
                "something went wrong".to_string(),
            ),
            (
                "no pdu, no text",
                ErrorCode::NoDataAvailable,
                None,
                String::new(),
            ),
            (
                "text only",
                ErrorCode::UnsupportedProtocolVersion,
                None,
                "version 0 not supported".to_string(),
            ),
            (
                "pdu only",
                ErrorCode::DuplicateAnnouncementReceived,
                Some(vec![0xFF; 20]),
                String::new(),
            ),
            (
                "withdrawal of unknown",
                ErrorCode::WithdrawalOfUnknownRecord,
                Some(vec![1]),
                "unknown VRP".to_string(),
            ),
        ];
        for (name, error_code, erroneous_pdu, error_text) in cases {
            let msg = Message::ErrorReport(ErrorReport {
                error_code,
                erroneous_pdu,
                error_text,
            });
            let parsed = roundtrip(&msg);
            assert_eq!(msg, parsed, "case: {}", name);
        }
    }

    #[test]
    fn test_parse_too_short() {
        let bytes = [PROTOCOL_VERSION, 0, 0, 0]; // only 4 bytes, need 8
        let result = Message::from_bytes(&bytes);
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn test_parse_wrong_version() {
        let bytes = [0u8, 2, 0, 0, 0, 0, 0, 8];
        let result = Message::from_bytes(&bytes);
        assert!(matches!(result, Err(ParseError::UnsupportedVersion(0))));
    }

    #[test]
    fn test_parse_unknown_message_type() {
        // Type 5 is reserved in v1 (was IPv4 Prefix in v0), type 99 is invalid
        for type_val in [5u8, 99] {
            let bytes = [PROTOCOL_VERSION, type_val, 0, 0, 0, 0, 0, 8];
            let result = Message::from_bytes(&bytes);
            assert!(
                matches!(result, Err(ParseError::UnknownMessageType(t)) if t == type_val),
                "type {} should be rejected",
                type_val
            );
        }
    }

    #[test]
    fn test_parse_invalid_length() {
        // Serial Notify with wrong length (should be 12, set to 8)
        let bytes = [PROTOCOL_VERSION, 0, 0, 1, 0, 0, 0, 8];
        let result = Message::from_bytes(&bytes);
        assert!(matches!(result, Err(ParseError::InvalidLength { .. })));
    }

    #[test]
    fn test_parse_truncated_body() {
        // Serial Notify claims length 12 but only 10 bytes provided
        let bytes = [PROTOCOL_VERSION, 0, 0, 1, 0, 0, 0, 12, 0, 0];
        let result = Message::from_bytes(&bytes);
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn test_parse_extra_trailing_bytes() {
        let mut bytes = Message::ResetQuery(ResetQuery).serialize();
        bytes.extend_from_slice(&[0xDE, 0xAD]);
        let (msg, consumed) = Message::from_bytes(&bytes).expect("parse failed");
        assert_eq!(msg, Message::ResetQuery(ResetQuery));
        assert_eq!(consumed, 8);
    }

    #[test]
    fn test_parse_multiple_messages_in_buffer() {
        let msg1 = Message::CacheResponse(CacheResponse { session_id: 1 });
        let msg2 = Message::Ipv4Prefix(Ipv4Prefix {
            flags: 1,
            prefix_length: 24,
            max_length: 24,
            prefix: Ipv4Addr::new(10, 0, 0, 0),
            asn: 65001,
        });
        let msg3 = Message::EndOfData(EndOfData {
            session_id: 1,
            serial: Serial(42),
            refresh_interval: 3600,
            retry_interval: 600,
            expire_interval: 7200,
        });

        let mut buf = Vec::new();
        buf.extend_from_slice(&msg1.serialize());
        buf.extend_from_slice(&msg2.serialize());
        buf.extend_from_slice(&msg3.serialize());

        let (parsed1, consumed1) = Message::from_bytes(&buf).expect("parse msg1 failed");
        assert_eq!(parsed1, msg1);

        let (parsed2, consumed2) =
            Message::from_bytes(&buf[consumed1..]).expect("parse msg2 failed");
        assert_eq!(parsed2, msg2);

        let (parsed3, consumed3) =
            Message::from_bytes(&buf[consumed1 + consumed2..]).expect("parse msg3 failed");
        assert_eq!(parsed3, msg3);

        assert_eq!(consumed1 + consumed2 + consumed3, buf.len());
    }

    #[test]
    fn test_error_report_invalid_utf8() {
        let mut bytes = Vec::new();
        bytes.push(PROTOCOL_VERSION);
        bytes.push(MessageType::ErrorReport as u8);
        bytes.extend_from_slice(&(ErrorCode::CorruptData as u16).to_be_bytes());
        let length_offset = bytes.len();
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.push(0xFF);
        bytes.push(0xFE);
        let length = bytes.len() as u32;
        bytes[length_offset..length_offset + 4].copy_from_slice(&length.to_be_bytes());

        let result = Message::from_bytes(&bytes);
        assert!(matches!(result, Err(ParseError::InvalidErrorText)));
    }

    #[test]
    fn test_error_report_unknown_error_code() {
        let mut bytes = Vec::new();
        bytes.push(PROTOCOL_VERSION);
        bytes.push(MessageType::ErrorReport as u8);
        bytes.extend_from_slice(&99u16.to_be_bytes());
        let length = (HEADER_SIZE + 8) as u32;
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());

        let result = Message::from_bytes(&bytes);
        assert!(matches!(result, Err(ParseError::UnknownErrorCode(99))));
    }

    #[test]
    fn test_serialized_sizes() {
        let cases: Vec<(&str, Message, usize)> = vec![
            (
                "Serial Notify",
                Message::SerialNotify(SerialNotify {
                    session_id: 0,
                    serial: Serial(0),
                }),
                12,
            ),
            (
                "Serial Query",
                Message::SerialQuery(SerialQuery {
                    session_id: 0,
                    serial: Serial(0),
                }),
                12,
            ),
            ("Reset Query", Message::ResetQuery(ResetQuery), 8),
            (
                "Cache Response",
                Message::CacheResponse(CacheResponse { session_id: 0 }),
                8,
            ),
            (
                "IPv4 Prefix",
                Message::Ipv4Prefix(Ipv4Prefix {
                    flags: 1,
                    prefix_length: 24,
                    max_length: 24,
                    prefix: Ipv4Addr::LOCALHOST,
                    asn: 0,
                }),
                20,
            ),
            (
                "IPv6 Prefix",
                Message::Ipv6Prefix(Ipv6Prefix {
                    flags: 1,
                    prefix_length: 48,
                    max_length: 48,
                    prefix: Ipv6Addr::LOCALHOST,
                    asn: 0,
                }),
                32,
            ),
            (
                "End of Data",
                Message::EndOfData(EndOfData {
                    session_id: 0,
                    serial: Serial(0),
                    refresh_interval: 3600,
                    retry_interval: 600,
                    expire_interval: 7200,
                }),
                24,
            ),
            ("Cache Reset", Message::CacheReset(CacheReset), 8),
        ];
        for (name, msg, expected_size) in cases {
            let serialized = msg.serialize();
            assert_eq!(serialized.len(), expected_size, "case: {}", name);
        }
    }

    #[test]
    fn test_all_error_codes_roundtrip() {
        let codes = vec![
            ErrorCode::CorruptData,
            ErrorCode::InternalError,
            ErrorCode::NoDataAvailable,
            ErrorCode::InvalidRequest,
            ErrorCode::UnsupportedProtocolVersion,
            ErrorCode::UnsupportedMessageType,
            ErrorCode::WithdrawalOfUnknownRecord,
            ErrorCode::DuplicateAnnouncementReceived,
            ErrorCode::UnexpectedProtocolVersion,
        ];
        for code in codes {
            let msg = Message::ErrorReport(ErrorReport {
                error_code: code,
                erroneous_pdu: None,
                error_text: String::new(),
            });
            let parsed = roundtrip(&msg);
            assert_eq!(msg, parsed, "error code: {:?}", code);
        }
    }

    #[test]
    fn test_ipv4_prefix_flags_semantics() {
        let announce = Message::Ipv4Prefix(Ipv4Prefix {
            flags: 1,
            prefix_length: 24,
            max_length: 24,
            prefix: Ipv4Addr::new(10, 0, 0, 0),
            asn: 65001,
        });
        let withdraw = Message::Ipv4Prefix(Ipv4Prefix {
            flags: 0,
            prefix_length: 24,
            max_length: 24,
            prefix: Ipv4Addr::new(10, 0, 0, 0),
            asn: 65001,
        });
        let parsed_announce = roundtrip(&announce);
        let parsed_withdraw = roundtrip(&withdraw);

        if let Message::Ipv4Prefix(m) = parsed_announce {
            assert_eq!(m.flags, 1, "announce flag should be 1");
        }
        if let Message::Ipv4Prefix(m) = parsed_withdraw {
            assert_eq!(m.flags, 0, "withdraw flag should be 0");
        }
    }

    #[tokio::test]
    async fn test_rtr_reader() {
        use tokio::io::AsyncWriteExt;

        let reset_query = Message::ResetQuery(ResetQuery);
        let cache_resp = Message::CacheResponse(CacheResponse { session_id: 1 });
        let prefix = Message::Ipv4Prefix(Ipv4Prefix {
            flags: 1,
            prefix_length: 24,
            max_length: 24,
            prefix: Ipv4Addr::new(10, 0, 0, 0),
            asn: 65001,
        });
        let eod = Message::EndOfData(EndOfData {
            session_id: 1,
            serial: Serial(42),
            refresh_interval: 3600,
            retry_interval: 600,
            expire_interval: 7200,
        });

        // Write all messages, then EOF
        let (client, server) = tokio::io::duplex(1024);
        let (mut writer, reader) = (client, server);

        let mut buf = Vec::new();
        buf.extend_from_slice(&reset_query.serialize());
        buf.extend_from_slice(&cache_resp.serialize());
        buf.extend_from_slice(&prefix.serialize());
        buf.extend_from_slice(&eod.serialize());
        writer.write_all(&buf).await.unwrap();
        drop(writer); // EOF

        let mut rtr_reader = RtrReader::new(reader);
        assert_eq!(rtr_reader.next_message().await.unwrap(), reset_query);
        assert_eq!(rtr_reader.next_message().await.unwrap(), cache_resp);
        assert_eq!(rtr_reader.next_message().await.unwrap(), prefix);
        assert_eq!(rtr_reader.next_message().await.unwrap(), eod);
        assert!(matches!(
            rtr_reader.next_message().await,
            Err(RtrReadError::Eof)
        ));
    }
}
