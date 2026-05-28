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
use std::net::IpAddr;
use std::time::SystemTime;

/// Statistics counter types (RFC 7854 Section 4.8)
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub enum StatType {
    PrefixesRejected = 0,
    DuplicatePrefixes = 1,
    DuplicateWithdraws = 2,
    UpdatesInvalidatedClusterList = 3,
    UpdatesInvalidatedAsPath = 4,
    UpdatesInvalidatedOriginatorId = 5,
    UpdatesInvalidatedAsConfed = 6,
    RoutesInAdjRibIn = 7,
    RoutesInLocRib = 8,
    RoutesInPerAfiAdjRibIn = 9,
    RoutesInPerAfiLocRib = 10,
    UpdatesTreatedAsWithdraw = 11,
    PrefixesTreatedAsWithdraw = 12,
    DuplicateUpdateMessages = 13,
}

/// Statistics TLV
#[derive(Clone, Debug)]
pub struct StatisticsTlv {
    pub stat_type: u16,
    pub stat_value: Vec<u8>,
}

impl StatisticsTlv {
    pub fn new_counter32(stat_type: StatType, value: u32) -> Self {
        Self {
            stat_type: stat_type as u16,
            stat_value: value.to_be_bytes().to_vec(),
        }
    }

    pub fn new_counter64(stat_type: StatType, value: u64) -> Self {
        Self {
            stat_type: stat_type as u16,
            stat_value: value.to_be_bytes().to_vec(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.stat_type.to_be_bytes());
        bytes.extend_from_slice(&(self.stat_value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.stat_value);
        bytes
    }
}

/// Statistics Report message
#[derive(Clone, Debug)]
pub struct StatisticsReportMessage {
    pub peer_header: PeerHeader,
    pub statistics: Vec<StatisticsTlv>,
}

impl StatisticsReportMessage {
    pub fn new(
        peer_distinguisher: PeerDistinguisher,
        peer_address: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        use_4byte_asn: bool,
        timestamp: Option<SystemTime>,
        statistics: Vec<StatisticsTlv>,
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
            statistics,
        }
    }
}

impl Message for StatisticsReportMessage {
    fn message_type(&self) -> MessageType {
        MessageType::StatisticsReport
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Per-Peer Header (42 bytes)
        bytes.extend_from_slice(&self.peer_header.to_bytes());

        // Stats Count (4 bytes)
        bytes.extend_from_slice(&(self.statistics.len() as u32).to_be_bytes());

        // Statistics TLVs
        for stat in &self.statistics {
            bytes.extend_from_slice(&stat.to_bytes());
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_statistics_report_message() {
        use crate::bmp::utils::PeerDistinguisher;

        let stats = vec![
            StatisticsTlv::new_counter32(StatType::RoutesInAdjRibIn, 100),
            StatisticsTlv::new_counter32(StatType::PrefixesRejected, 5),
        ];

        let msg = StatisticsReportMessage::new(
            PeerDistinguisher::Global,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            true,
            Some(SystemTime::now()),
            stats,
        );

        let serialized = msg.serialize();
        assert_eq!(serialized[0], 3); // Version
        assert_eq!(serialized[5], MessageType::StatisticsReport.as_u8());
    }
}
