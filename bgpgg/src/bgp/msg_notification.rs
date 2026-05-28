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
use super::utils::ParserError;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MessageHeaderError {
    ConnectionNotSynchronized = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
    Unknown(u8),
}

impl From<u8> for MessageHeaderError {
    fn from(value: u8) -> Self {
        match value {
            1 => MessageHeaderError::ConnectionNotSynchronized,
            2 => MessageHeaderError::BadMessageLength,
            3 => MessageHeaderError::BadMessageType,
            val => MessageHeaderError::Unknown(val),
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OpenMessageError {
    UnsupportedVersionNumber = 1,
    BadPeerAs = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptionalParameter = 4,
    UnacceptedHoldTime = 6,
    UnsupportedCapability = 7,
    Unknown(u8),
}

impl From<u8> for OpenMessageError {
    fn from(value: u8) -> Self {
        match value {
            1 => OpenMessageError::UnsupportedVersionNumber,
            2 => OpenMessageError::BadPeerAs,
            3 => OpenMessageError::BadBgpIdentifier,
            4 => OpenMessageError::UnsupportedOptionalParameter,
            6 => OpenMessageError::UnacceptedHoldTime,
            7 => OpenMessageError::UnsupportedCapability,
            val => OpenMessageError::Unknown(val),
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum UpdateMessageError {
    MalformedAttributeList = 1,
    UnrecognizedWellKnownAttribute = 2,
    MissingWellKnownAttribute = 3,
    AttributeFlagsError = 4,
    AttributeLengthError = 5,
    InvalidOriginAttribute = 6,
    // 7 is deprecated (was AS Routing Loop)
    InvalidNextHopAttribute = 8,
    OptionalAttributeError = 9,
    InvalidNetworkField = 10,
    MalformedASPath = 11,
    Unknown(u8),
}

impl From<u8> for UpdateMessageError {
    fn from(value: u8) -> Self {
        match value {
            1 => UpdateMessageError::MalformedAttributeList,
            2 => UpdateMessageError::UnrecognizedWellKnownAttribute,
            3 => UpdateMessageError::MissingWellKnownAttribute,
            4 => UpdateMessageError::AttributeFlagsError,
            5 => UpdateMessageError::AttributeLengthError,
            6 => UpdateMessageError::InvalidOriginAttribute,
            // 7 is deprecated
            8 => UpdateMessageError::InvalidNextHopAttribute,
            9 => UpdateMessageError::OptionalAttributeError,
            10 => UpdateMessageError::InvalidNetworkField,
            11 => UpdateMessageError::MalformedASPath,
            val => UpdateMessageError::Unknown(val),
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RouteRefreshMessageError {
    InvalidMessageLength = 1,
    Unknown(u8),
}

impl From<u8> for RouteRefreshMessageError {
    fn from(value: u8) -> Self {
        match value {
            1 => RouteRefreshMessageError::InvalidMessageLength,
            val => RouteRefreshMessageError::Unknown(val),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BgpError {
    MessageHeaderError(MessageHeaderError),
    OpenMessageError(OpenMessageError),
    UpdateMessageError(UpdateMessageError),
    HoldTimerExpired,
    FiniteStateMachineError,
    Cease(CeaseSubcode),
    RouteRefreshMessageError(RouteRefreshMessageError),
    Unknown,
}

/// RFC 4486 Cease NOTIFICATION subcodes
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CeaseSubcode {
    MaxPrefixesReached = 1,
    AdministrativeShutdown = 2,
    PeerDeconfigured = 3,
    AdministrativeReset = 4,
    ConnectionRejected = 5,
    OtherConfigurationChange = 6,
    ConnectionCollisionResolution = 7,
    OutOfResources = 8,
    Unknown(u8),
}

impl From<u8> for CeaseSubcode {
    fn from(value: u8) -> Self {
        match value {
            1 => CeaseSubcode::MaxPrefixesReached,
            2 => CeaseSubcode::AdministrativeShutdown,
            3 => CeaseSubcode::PeerDeconfigured,
            4 => CeaseSubcode::AdministrativeReset,
            5 => CeaseSubcode::ConnectionRejected,
            6 => CeaseSubcode::OtherConfigurationChange,
            7 => CeaseSubcode::ConnectionCollisionResolution,
            8 => CeaseSubcode::OutOfResources,
            val => CeaseSubcode::Unknown(val),
        }
    }
}

#[repr(u8)]
enum ErrorCode {
    MessageHeaderError = 1,
    OpenMessageError = 2,
    UpdateMessageError = 3,
    HoldTimerExpired = 4,
    FiniteStateMachineError = 5,
    Cease = 6,
    RouteRefreshMessageError = 7,
    Unknown,
}

impl From<u8> for ErrorCode {
    fn from(value: u8) -> Self {
        match value {
            1 => ErrorCode::MessageHeaderError,
            2 => ErrorCode::OpenMessageError,
            3 => ErrorCode::UpdateMessageError,
            4 => ErrorCode::HoldTimerExpired,
            5 => ErrorCode::FiniteStateMachineError,
            6 => ErrorCode::Cease,
            7 => ErrorCode::RouteRefreshMessageError,
            _ => ErrorCode::Unknown,
        }
    }
}

impl BgpError {
    fn new(err_code: u8, err_sub_code: u8) -> BgpError {
        match ErrorCode::from(err_code) {
            ErrorCode::Cease => BgpError::Cease(CeaseSubcode::from(err_sub_code)),
            ErrorCode::RouteRefreshMessageError => {
                BgpError::RouteRefreshMessageError(RouteRefreshMessageError::from(err_sub_code))
            }
            ErrorCode::MessageHeaderError => {
                let err = MessageHeaderError::from(err_sub_code);
                if matches!(err, MessageHeaderError::Unknown(_)) {
                    eprintln!(
                        "Warning: received NOTIFICATION with unknown MessageHeaderError subcode, subcode={:?}",
                        err_sub_code
                    );
                }
                BgpError::MessageHeaderError(err)
            }
            ErrorCode::OpenMessageError => {
                let err = OpenMessageError::from(err_sub_code);
                if matches!(err, OpenMessageError::Unknown(_)) {
                    eprintln!(
                        "Warning: received NOTIFICATION with unknown OpenMessageError subcode, subcode={:?}",
                        err_sub_code
                    );
                }
                BgpError::OpenMessageError(err)
            }
            ErrorCode::UpdateMessageError => {
                let err = UpdateMessageError::from(err_sub_code);
                if matches!(err, UpdateMessageError::Unknown(_)) {
                    eprintln!(
                        "Warning: received NOTIFICATION with unknown UpdateMessageError subcode, subcode={:?}",
                        err_sub_code
                    );
                }
                BgpError::UpdateMessageError(err)
            }
            ErrorCode::HoldTimerExpired => BgpError::HoldTimerExpired,
            ErrorCode::FiniteStateMachineError => BgpError::FiniteStateMachineError,
            ErrorCode::Unknown => {
                eprintln!(
                    "Warning: received NOTIFICATION with unknown error code, code={:?}",
                    err_code
                );
                BgpError::Unknown
            }
        }
    }

    fn error_code(&self) -> u8 {
        match self {
            BgpError::MessageHeaderError(_) => 1,
            BgpError::OpenMessageError(_) => 2,
            BgpError::UpdateMessageError(_) => 3,
            BgpError::HoldTimerExpired => 4,
            BgpError::FiniteStateMachineError => 5,
            BgpError::Cease(_) => 6,
            BgpError::RouteRefreshMessageError(_) => 7,
            BgpError::Unknown => 0,
        }
    }

    fn error_subcode(&self) -> u8 {
        match self {
            BgpError::MessageHeaderError(err) => match err {
                MessageHeaderError::ConnectionNotSynchronized => 1,
                MessageHeaderError::BadMessageLength => 2,
                MessageHeaderError::BadMessageType => 3,
                MessageHeaderError::Unknown(val) => *val,
            },
            BgpError::OpenMessageError(err) => match err {
                OpenMessageError::UnsupportedVersionNumber => 1,
                OpenMessageError::BadPeerAs => 2,
                OpenMessageError::BadBgpIdentifier => 3,
                OpenMessageError::UnsupportedOptionalParameter => 4,
                OpenMessageError::UnacceptedHoldTime => 6,
                OpenMessageError::UnsupportedCapability => 7,
                OpenMessageError::Unknown(val) => *val,
            },
            BgpError::UpdateMessageError(err) => match err {
                UpdateMessageError::MalformedAttributeList => 1,
                UpdateMessageError::UnrecognizedWellKnownAttribute => 2,
                UpdateMessageError::MissingWellKnownAttribute => 3,
                UpdateMessageError::AttributeFlagsError => 4,
                UpdateMessageError::AttributeLengthError => 5,
                UpdateMessageError::InvalidOriginAttribute => 6,
                // 7 is deprecated
                UpdateMessageError::InvalidNextHopAttribute => 8,
                UpdateMessageError::OptionalAttributeError => 9,
                UpdateMessageError::InvalidNetworkField => 10,
                UpdateMessageError::MalformedASPath => 11,
                UpdateMessageError::Unknown(val) => *val,
            },
            BgpError::Cease(subcode) => match subcode {
                CeaseSubcode::MaxPrefixesReached => 1,
                CeaseSubcode::AdministrativeShutdown => 2,
                CeaseSubcode::PeerDeconfigured => 3,
                CeaseSubcode::AdministrativeReset => 4,
                CeaseSubcode::ConnectionRejected => 5,
                CeaseSubcode::OtherConfigurationChange => 6,
                CeaseSubcode::ConnectionCollisionResolution => 7,
                CeaseSubcode::OutOfResources => 8,
                CeaseSubcode::Unknown(val) => *val,
            },
            BgpError::RouteRefreshMessageError(subcode) => match subcode {
                RouteRefreshMessageError::InvalidMessageLength => 1,
                RouteRefreshMessageError::Unknown(val) => *val,
            },
            _ => 0,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NotificationMessage {
    error: BgpError,
    data: Vec<u8>,
}

impl NotificationMessage {
    pub fn new(error: BgpError, data: Vec<u8>) -> Self {
        NotificationMessage { error, data }
    }

    pub fn from_parser_error(error: &ParserError) -> Option<Self> {
        match error {
            ParserError::BgpError { error, data } => {
                Some(NotificationMessage::new(error.clone(), data.clone()))
            }
            _ => None,
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        // RFC 4271: errors in NOTIFICATION messages cannot be reported back via NOTIFICATION,
        // so we log locally and return Unknown for malformed messages.
        if bytes.len() < 2 {
            eprintln!(
                "Warning: received malformed NOTIFICATION message, len={:?}",
                bytes.len()
            );
            return NotificationMessage {
                error: BgpError::Unknown,
                data: bytes,
            };
        }

        let err_code = bytes[0];
        let err_sub_code = bytes[1];

        let bgp_error = BgpError::new(err_code, err_sub_code);
        let data = &bytes[2..];

        NotificationMessage {
            error: bgp_error,
            data: data.to_vec(),
        }
    }

    pub fn error(&self) -> &BgpError {
        &self.error
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// RFC 4271 Event 24: Check if this is a version error NOTIFICATION
    pub fn is_version_error(&self) -> bool {
        matches!(
            self.error,
            BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber)
        )
    }
}

impl Message for NotificationMessage {
    fn kind(&self) -> MessageType {
        MessageType::Notification
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.error.error_code());
        bytes.push(self.error.error_subcode());
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_bgp_error_new {
        ($name: ident, $err_code: expr, $err_sub_code: expr, expected $expected:expr) => {
            #[test]
            fn $name() {
                let error = BgpError::new($err_code, $err_sub_code);
                assert_eq!(error, $expected)
            }
        };
    }

    test_bgp_error_new!(
        bgp_error_new_msg_header_1, 1, 1,
        expected BgpError::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized)
    );
    test_bgp_error_new!(
        bgp_error_new_open_message_1, 2, 1,
        expected BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber)
    );
    test_bgp_error_new!(
        bgp_error_new_update_message_1, 3, 1,
        expected BgpError::UpdateMessageError(UpdateMessageError::MalformedAttributeList)
    );
    test_bgp_error_new!(
        bgp_error_new_hold_timer, 4, 0,
        expected BgpError::HoldTimerExpired
    );
    test_bgp_error_new!(
        bgp_error_new_fsm, 5, 0,
        expected BgpError::FiniteStateMachineError
    );
    test_bgp_error_new!(
        bgp_error_new_cease, 6, 0,
        expected BgpError::Cease(CeaseSubcode::Unknown(0))
    );
    test_bgp_error_new!(
        bgp_error_new_cease_max_prefix, 6, 1,
        expected BgpError::Cease(CeaseSubcode::MaxPrefixesReached)
    );
    test_bgp_error_new!(
        bgp_error_new_cease_admin_shutdown, 6, 2,
        expected BgpError::Cease(CeaseSubcode::AdministrativeShutdown)
    );
    test_bgp_error_new!(
        bgp_error_new_cease_peer_deconfigured, 6, 3,
        expected BgpError::Cease(CeaseSubcode::PeerDeconfigured)
    );
    test_bgp_error_new!(
        bgp_error_new_cease_admin_reset, 6, 4,
        expected BgpError::Cease(CeaseSubcode::AdministrativeReset)
    );
    test_bgp_error_new!(
        bgp_error_new_cease_connection_rejected, 6, 5,
        expected BgpError::Cease(CeaseSubcode::ConnectionRejected)
    );
    test_bgp_error_new!(
        bgp_error_new_cease_other_config_change, 6, 6,
        expected BgpError::Cease(CeaseSubcode::OtherConfigurationChange)
    );
    test_bgp_error_new!(
        bgp_error_new_cease_collision_resolution, 6, 7,
        expected BgpError::Cease(CeaseSubcode::ConnectionCollisionResolution)
    );
    test_bgp_error_new!(
        bgp_error_new_cease_out_of_resources, 6, 8,
        expected BgpError::Cease(CeaseSubcode::OutOfResources)
    );
    test_bgp_error_new!(
        bgp_error_new_route_refresh_invalid_length, 7, 1,
        expected BgpError::RouteRefreshMessageError(RouteRefreshMessageError::InvalidMessageLength)
    );
    test_bgp_error_new!(
        bgp_error_new_route_refresh_unknown_subcode, 7, 99,
        expected BgpError::RouteRefreshMessageError(RouteRefreshMessageError::Unknown(99))
    );
    test_bgp_error_new!(
        bgp_error_new_unknown, 99, 0,
        expected BgpError::Unknown
    );

    #[test]
    fn test_notification_message_from_bytes() {
        let input = vec![
            0x03, // Error code
            0x02, // Error subcode
            // Data
            // https://datatracker.ietf.org/doc/html/rfc4271#section-6.3
            0x00, 0xff, // Attribute type
            0x01, // Attribute length
            0x02, // Attribute Value
        ];
        let result = NotificationMessage::from_bytes(input);

        assert_eq!(
            result,
            NotificationMessage {
                error: BgpError::UpdateMessageError(
                    UpdateMessageError::UnrecognizedWellKnownAttribute
                ),
                data: vec![0x00, 0xff, 0x01, 0x02],
            }
        )
    }

    #[test]
    fn test_notification_message_from_bytes_no_data() {
        let input = vec![
            0x02, // Error code
            0x04, // Error subcode
        ];
        let result = NotificationMessage::from_bytes(input);

        assert_eq!(
            result,
            NotificationMessage {
                error: BgpError::OpenMessageError(OpenMessageError::UnsupportedOptionalParameter),
                data: vec![],
            }
        )
    }

    #[test]
    fn test_notification_message_new_encode_decode() {
        let error = BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength);
        let data = vec![0x00, 0x12];

        let notif = NotificationMessage::new(error, data.clone());
        assert_eq!(notif.data(), &data);

        let bytes = notif.to_bytes();
        assert_eq!(bytes[0], 1);
        assert_eq!(bytes[1], 2);
        assert_eq!(&bytes[2..], &data);

        let decoded = NotificationMessage::from_bytes(bytes);
        assert_eq!(decoded, notif);
    }

    #[test]
    fn test_from_parser_error_connection_not_synchronized() {
        let parser_error = ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized),
            data: Vec::new(),
        };
        let notif = NotificationMessage::from_parser_error(&parser_error).unwrap();

        assert_eq!(
            notif.error(),
            &BgpError::MessageHeaderError(MessageHeaderError::ConnectionNotSynchronized)
        );
        assert_eq!(notif.data(), &[] as &[u8]);
    }

    #[test]
    fn test_from_parser_error_bad_message_length() {
        let parser_error = ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            data: vec![0x10, 0x01],
        };
        let notif = NotificationMessage::from_parser_error(&parser_error).unwrap();

        assert_eq!(
            notif.error(),
            &BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength)
        );
        assert_eq!(notif.data(), &[0x10, 0x01]);
    }

    #[test]
    fn test_from_parser_error_bad_message_type() {
        let parser_error = ParserError::BgpError {
            error: BgpError::MessageHeaderError(MessageHeaderError::BadMessageType),
            data: vec![99],
        };
        let notif = NotificationMessage::from_parser_error(&parser_error).unwrap();

        assert_eq!(
            notif.error(),
            &BgpError::MessageHeaderError(MessageHeaderError::BadMessageType)
        );
        assert_eq!(notif.data(), &[99]);
    }

    #[test]
    fn test_from_parser_error_none() {
        let parser_error = ParserError::IoError("connection reset".to_string());
        assert!(NotificationMessage::from_parser_error(&parser_error).is_none());
    }

    #[test]
    fn test_from_bytes_malformed_too_short() {
        let result = NotificationMessage::from_bytes(vec![0x01]);
        assert_eq!(result.error(), &BgpError::Unknown);
        assert_eq!(result.data(), &[0x01]);
    }

    #[test]
    fn test_from_bytes_unknown_error_code() {
        let result = NotificationMessage::from_bytes(vec![99, 0]);
        assert_eq!(result.error(), &BgpError::Unknown);
    }

    #[test]
    fn test_from_bytes_unknown_subcode() {
        let result = NotificationMessage::from_bytes(vec![1, 99]); // MessageHeaderError with unknown subcode
        assert_eq!(
            result.error(),
            &BgpError::MessageHeaderError(MessageHeaderError::Unknown(99))
        );
    }

    #[test]
    fn test_is_version_error() {
        // Version error should return true
        let notif = NotificationMessage::new(
            BgpError::OpenMessageError(OpenMessageError::UnsupportedVersionNumber),
            vec![],
        );
        assert!(notif.is_version_error());

        // Other OPEN errors should return false
        let notif = NotificationMessage::new(
            BgpError::OpenMessageError(OpenMessageError::BadPeerAs),
            vec![],
        );
        assert!(!notif.is_version_error());

        // Non-OPEN errors should return false
        let notif = NotificationMessage::new(
            BgpError::MessageHeaderError(MessageHeaderError::BadMessageLength),
            vec![],
        );
        assert!(!notif.is_version_error());

        let notif = NotificationMessage::new(BgpError::HoldTimerExpired, vec![]);
        assert!(!notif.is_version_error());

        let notif = NotificationMessage::new(
            BgpError::Cease(CeaseSubcode::AdministrativeShutdown),
            vec![],
        );
        assert!(!notif.is_version_error());
    }
}
