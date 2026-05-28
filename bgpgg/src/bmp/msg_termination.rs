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
use super::utils::{InformationTlv, TerminationType};

#[derive(Clone, Debug)]
pub struct TerminationMessage {
    pub information: Vec<InformationTlv>,
}

#[derive(Clone, Copy, Debug)]
pub enum TerminationReason {
    AdminClose,
    Unspecified,
    OutOfResources,
    RedundantConnection,
    PermanentlyAdminClose,
}

impl TerminationReason {
    pub fn as_u16(self) -> u16 {
        match self {
            TerminationReason::AdminClose => 0,
            TerminationReason::Unspecified => 1,
            TerminationReason::OutOfResources => 2,
            TerminationReason::RedundantConnection => 3,
            TerminationReason::PermanentlyAdminClose => 4,
        }
    }
}

impl TerminationMessage {
    /// Create Termination message with reason and optional string messages
    /// Multiple string TLVs may be included (RFC 7854)
    pub fn new(reason: TerminationReason, messages: &[&str]) -> Self {
        let mut information = Vec::new();

        // Reason TLV (type = 1, value = 2-byte reason code)
        information.push(InformationTlv::new(
            TerminationType::Reason as u16,
            reason.as_u16().to_be_bytes().to_vec(),
        ));

        // Optional string TLVs (multiple allowed per RFC 7854)
        for msg in messages {
            if !msg.is_empty() {
                information.push(InformationTlv::new(
                    TerminationType::String as u16,
                    msg.as_bytes().to_vec(),
                ));
            }
        }

        Self { information }
    }
}

impl Message for TerminationMessage {
    fn message_type(&self) -> MessageType {
        MessageType::Termination
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for tlv in &self.information {
            bytes.extend_from_slice(&tlv.to_bytes());
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_termination_message_with_reason() {
        let msg = TerminationMessage::new(TerminationReason::AdminClose, &[]);

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::Termination.as_u8());
    }

    #[test]
    fn test_termination_message_with_strings() {
        let msg = TerminationMessage::new(
            TerminationReason::OutOfResources,
            &["Shutting down", "Memory exhausted"],
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::Termination.as_u8());
    }

    #[test]
    fn test_termination_reason_codes() {
        assert_eq!(TerminationReason::AdminClose.as_u16(), 0);
        assert_eq!(TerminationReason::Unspecified.as_u16(), 1);
        assert_eq!(TerminationReason::OutOfResources.as_u16(), 2);
        assert_eq!(TerminationReason::RedundantConnection.as_u16(), 3);
        assert_eq!(TerminationReason::PermanentlyAdminClose.as_u16(), 4);
    }
}
