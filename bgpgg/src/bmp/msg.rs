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

use super::msg_initiation::InitiationMessage;
use super::msg_peer_down::PeerDownMessage;
use super::msg_peer_up::PeerUpMessage;
use super::msg_route_mirroring::RouteMirroringMessage;
use super::msg_route_monitoring::RouteMonitoringMessage;
use super::msg_statistics::StatisticsReportMessage;
use super::msg_termination::TerminationMessage;

pub const BMP_VERSION: u8 = 3;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MessageType {
    RouteMonitoring = 0,
    StatisticsReport = 1,
    PeerDownNotification = 2,
    PeerUpNotification = 3,
    Initiation = 4,
    Termination = 5,
    RouteMirroring = 6,
}

impl MessageType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

pub trait Message {
    fn message_type(&self) -> MessageType;
    fn to_bytes(&self) -> Vec<u8>;

    /// Serialize complete BMP message with common header
    fn serialize(&self) -> Vec<u8> {
        let body = self.to_bytes();
        let mut message = Vec::new();

        // Version (1 byte)
        message.push(BMP_VERSION);

        // Message Length (4 bytes) - includes header
        let length = 6u32 + body.len() as u32; // 6 = version(1) + length(4) + type(1)
        message.extend_from_slice(&length.to_be_bytes());

        // Message Type (1 byte)
        message.push(self.message_type().as_u8());

        // Message body
        message.extend_from_slice(&body);

        message
    }
}

pub enum BmpMessage {
    Initiation(InitiationMessage),
    PeerUp(PeerUpMessage),
    PeerDown(PeerDownMessage),
    RouteMonitoring(RouteMonitoringMessage),
    StatisticsReport(StatisticsReportMessage),
    RouteMirroring(RouteMirroringMessage),
    Termination(TerminationMessage),
}

impl BmpMessage {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Initiation(m) => m.serialize(),
            Self::PeerUp(m) => m.serialize(),
            Self::PeerDown(m) => m.serialize(),
            Self::RouteMonitoring(m) => m.serialize(),
            Self::StatisticsReport(m) => m.serialize(),
            Self::RouteMirroring(m) => m.serialize(),
            Self::Termination(m) => m.serialize(),
        }
    }
}
