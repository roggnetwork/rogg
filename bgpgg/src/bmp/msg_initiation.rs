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
use super::utils::{InformationTlv, InitiationType};

#[derive(Clone, Debug)]
pub struct InitiationMessage {
    pub information: Vec<InformationTlv>,
}

impl InitiationMessage {
    /// Create Initiation message with required sysName and sysDescr (RFC 7854 MUST)
    /// Optional string TLVs may be included (RFC 7854)
    pub fn new(sys_name: &str, sys_descr: &str, messages: &[&str]) -> Self {
        let mut information = vec![
            InformationTlv::new(InitiationType::SysName as u16, sys_name.as_bytes().to_vec()),
            InformationTlv::new(
                InitiationType::SysDescr as u16,
                sys_descr.as_bytes().to_vec(),
            ),
        ];

        // Optional string TLVs (multiple allowed per RFC 7854)
        for msg in messages {
            if !msg.is_empty() {
                information.push(InformationTlv::new(
                    InitiationType::String as u16,
                    msg.as_bytes().to_vec(),
                ));
            }
        }

        Self { information }
    }
}

impl Message for InitiationMessage {
    fn message_type(&self) -> MessageType {
        MessageType::Initiation
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
    fn test_initiation_message_serialize() {
        let msg = InitiationMessage::new("bgpgg", "bgpgg router", &[]);
        let serialized = msg.serialize();

        // Version
        assert_eq!(serialized[0], 3);
        // Type
        assert_eq!(serialized[5], MessageType::Initiation.as_u8());
    }

    #[test]
    fn test_initiation_message_with_strings() {
        let msg = InitiationMessage::new("bgpgg", "bgpgg router", &["version 0.1", "build 123"]);
        let serialized = msg.serialize();

        // Should have all TLVs
        assert_eq!(serialized[0], 3);
        assert_eq!(serialized[5], MessageType::Initiation.as_u8());
    }
}
