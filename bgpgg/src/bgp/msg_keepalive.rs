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

#[derive(Debug, Clone)]
pub struct KeepaliveMessage {}

impl Message for KeepaliveMessage {
    fn kind(&self) -> MessageType {
        MessageType::Keepalive
    }

    fn to_bytes(&self) -> Vec<u8> {
        // KEEPALIVE has no body, just return empty vec
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keepalive_serialize() {
        let keepalive_msg = KeepaliveMessage {};

        // Serialize to complete BGP message with header
        let message = keepalive_msg.serialize();

        // Expected complete message
        let expected: Vec<u8> = vec![
            // BGP header marker (16 bytes of 0xFF)
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, // Message length (19 bytes - header only, no body)
            0x00, 0x13, // Message type (KEEPALIVE = 4)
            0x04,
        ];

        assert_eq!(message, expected);
        assert_eq!(message.len(), 19); // 19 byte header, no body
    }
}
