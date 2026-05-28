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

//! BMP testing utilities

use super::common::TestServer;
use bgpgg::bgp::msg::{AddPathMask, MessageFormat, BGP_HEADER_SIZE_BYTES};
use bgpgg::bgp::msg_open::OpenMessage;
use bgpgg::bgp::msg_update::UpdateMessage;
use bgpgg::bmp::msg::BmpMessage;
use bgpgg::bmp::msg::{MessageType as BmpMessageType, BMP_VERSION};
use bgpgg::bmp::msg_initiation::InitiationMessage;
use bgpgg::bmp::msg_peer_down::PeerDownMessage;
use bgpgg::bmp::msg_peer_up::PeerUpMessage;
use bgpgg::bmp::msg_route_monitoring::RouteMonitoringMessage;
use bgpgg::bmp::msg_statistics::{StatisticsReportMessage, StatisticsTlv};
use bgpgg::bmp::msg_termination::{TerminationMessage, TerminationReason};
use bgpgg::bmp::utils::{
    InformationTlv, InitiationType, PeerHeader, TerminationType, PEER_HEADER_SIZE,
};
use bgpgg::net::IpNetwork;
use bgpgg::types::PeerDownReason;
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

/// Expected PeerUp message (without timestamps and OPEN message details)
#[derive(Debug, Clone)]
pub struct ExpectedPeerUp {
    pub local_addr: IpAddr,
    pub peer_addr: IpAddr,
    pub peer_as: u32,
    pub peer_bgp_id: u32,
    /// Expected remote port. If None, port is not checked (useful for active-active peering
    /// where the connection direction is non-deterministic).
    pub peer_port: Option<u16>,
}

/// Expected Statistics message (without timestamps)
#[derive(Debug, Clone)]
pub struct ExpectedStatistics {
    pub peer_addr: IpAddr,
    pub peer_as: u32,
    pub peer_bgp_id: u32,
    pub stats: Vec<(u16, u64)>,
}

/// Expected PeerDown message (without timestamps)
#[derive(Debug, Clone)]
pub struct ExpectedPeerDown {
    pub peer_addr: IpAddr,
    pub peer_as: u32,
    pub peer_bgp_id: u32,
    pub reason: PeerDownReason,
}

/// Expected RouteMonitoring message (without timestamps)
#[derive(Debug, Clone)]
pub struct ExpectedRouteMonitoring {
    pub peer_addr: IpAddr,
    pub peer_as: u32,
    pub peer_bgp_id: u32,
    pub peer_flags: u8,
    pub nlri: Vec<IpNetwork>,
    pub withdrawn: Vec<IpNetwork>,
}

/// Expected BMP message for order-independent validation
#[derive(Debug, Clone)]
pub enum ExpectedBmpMessage {
    PeerUp(ExpectedPeerUp),
    PeerDown(ExpectedPeerDown),
    Statistics(ExpectedStatistics),
    RouteMonitoring(ExpectedRouteMonitoring),
}

/// Decode IP address from 16-byte BMP format (detects IPv4-mapped)
pub fn decode_bmp_ip_address(bytes: &[u8; 16]) -> IpAddr {
    // Check if it's IPv4-mapped (first 12 bytes are 0)
    if bytes[..12] == [0; 12] {
        IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::from(*bytes))
    }
}

/// Parse a BGP OPEN message from BMP body (includes BGP header)
/// Returns (OpenMessage, message_length_including_header)
fn parse_bgp_open_from_bmp(body: &[u8], offset: usize) -> (OpenMessage, usize) {
    // Read BGP message length from header (bytes 16-17)
    let msg_len = u16::from_be_bytes(body[offset + 16..offset + 18].try_into().unwrap()) as usize;
    let body_len = msg_len - BGP_HEADER_SIZE_BYTES;
    let open_msg = OpenMessage::from_bytes(
        body[offset + BGP_HEADER_SIZE_BYTES..offset + BGP_HEADER_SIZE_BYTES + body_len].to_vec(),
    )
    .unwrap();
    (open_msg, msg_len)
}

fn parse_peer_header(body: &[u8]) -> PeerHeader {
    let peer_type = body[0];
    let peer_flags = body[1];
    let peer_distinguisher_val = u64::from_be_bytes(body[2..10].try_into().unwrap());
    let peer_distinguisher = match peer_type {
        0 => bgpgg::bmp::utils::PeerDistinguisher::Global,
        1 => bgpgg::bmp::utils::PeerDistinguisher::Rd(peer_distinguisher_val),
        2 => bgpgg::bmp::utils::PeerDistinguisher::Local(peer_distinguisher_val),
        _ => panic!("Invalid peer type: {}", peer_type),
    };
    let peer_address_bytes: [u8; 16] = body[10..26].try_into().unwrap();
    let peer_address = decode_bmp_ip_address(&peer_address_bytes);
    let peer_as = u32::from_be_bytes(body[26..30].try_into().unwrap());
    let peer_bgp_id = u32::from_be_bytes(body[30..34].try_into().unwrap());
    let timestamp_seconds = u32::from_be_bytes(body[34..38].try_into().unwrap());
    let timestamp_microseconds = u32::from_be_bytes(body[38..42].try_into().unwrap());

    PeerHeader {
        peer_distinguisher,
        peer_flags,
        peer_address,
        peer_as,
        peer_bgp_id,
        timestamp_seconds,
        timestamp_microseconds,
    }
}

/// Fake BMP server for testing
pub struct FakeBmpServer {
    listener: TcpListener,
    stream: Option<TcpStream>,
}

impl FakeBmpServer {
    pub async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Self {
            listener,
            stream: None,
        }
    }

    pub fn address(&self) -> String {
        let addr = self.listener.local_addr().unwrap();
        format!("{}:{}", addr.ip(), addr.port())
    }

    pub async fn accept(&mut self) {
        let (stream, _) = self.listener.accept().await.unwrap();
        self.stream = Some(stream);
    }

    pub async fn read_message(&mut self) -> (u8, Vec<u8>) {
        let stream = self.stream.as_mut().unwrap();

        // Read BMP common header (6 bytes)
        let mut header_buf = [0u8; 6];
        stream.read_exact(&mut header_buf).await.unwrap();

        let version = header_buf[0];
        let length =
            u32::from_be_bytes([header_buf[1], header_buf[2], header_buf[3], header_buf[4]]);
        let message_type = header_buf[5];

        assert_eq!(version, BMP_VERSION, "Invalid BMP version");

        // Read message body (length includes the 6-byte header)
        let body_len = length as usize - 6;
        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body).await.unwrap();

        (message_type, body)
    }

    pub async fn read_peer_up(&mut self) -> PeerUpMessage {
        let (message_type, body) = self.read_message().await;
        assert_eq!(
            message_type,
            BmpMessageType::PeerUpNotification.as_u8(),
            "Expected PeerUpNotification message"
        );

        let peer_header = parse_peer_header(&body);
        let mut offset = PEER_HEADER_SIZE;

        // Local Address (16 bytes)
        let local_address_bytes: [u8; 16] = body[offset..offset + 16].try_into().unwrap();
        let local_address = decode_bmp_ip_address(&local_address_bytes);
        offset += 16;

        // Local Port (2 bytes)
        let local_port = u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap());
        offset += 2;

        // Remote Port (2 bytes)
        let remote_port = u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap());
        offset += 2;

        // Sent OPEN Message
        let (sent_open, sent_msg_len) = parse_bgp_open_from_bmp(&body, offset);
        offset += sent_msg_len;

        // Received OPEN Message
        let (received_open, _) = parse_bgp_open_from_bmp(&body, offset);

        // Information TLVs - skip
        let information = Vec::new();

        PeerUpMessage {
            peer_header,
            local_address,
            local_port,
            remote_port,
            sent_open_message: sent_open,
            received_open_message: received_open,
            information,
        }
    }

    pub async fn read_initiation(&mut self) -> InitiationMessage {
        let (message_type, body) = self.read_message().await;
        assert_eq!(
            message_type,
            BmpMessageType::Initiation.as_u8(),
            "Expected Initiation message"
        );

        let mut information = Vec::new();
        let mut offset = 0;

        while offset < body.len() {
            let info_type = u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap());
            offset += 2;

            let info_length =
                u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;

            let info_value = body[offset..offset + info_length].to_vec();
            offset += info_length;

            information.push(InformationTlv::new(info_type, info_value));
        }

        InitiationMessage { information }
    }

    pub async fn read_peer_down(&mut self) -> PeerDownMessage {
        let (message_type, body) = self.read_message().await;
        assert_eq!(
            message_type,
            BmpMessageType::PeerDownNotification.as_u8(),
            "Expected PeerDownNotification message"
        );

        let peer_header = parse_peer_header(&body);
        let reason_code = body[PEER_HEADER_SIZE];
        let offset = PEER_HEADER_SIZE + 1;

        let reason = match reason_code {
            1 => {
                // LocalNotification - parse BGP NOTIFICATION
                let notif_bytes = body[offset..].to_vec();
                let notif =
                    bgpgg::bgp::msg_notification::NotificationMessage::from_bytes(notif_bytes);
                PeerDownReason::LocalNotification(notif)
            }
            2 => {
                // LocalNoNotification - parse 2-byte FSM event code
                let event_code = u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap());
                // Use HoldTimerExpires as placeholder since we can't reconstruct all variants
                let fsm_event = match event_code {
                    10 => bgpgg::peer::FsmEvent::HoldTimerExpires,
                    _ => bgpgg::peer::FsmEvent::ManualStop, // Placeholder
                };
                PeerDownReason::LocalNoNotification(fsm_event)
            }
            3 => {
                // RemoteNotification - parse BGP NOTIFICATION
                let notif_bytes = body[offset..].to_vec();
                let notif =
                    bgpgg::bgp::msg_notification::NotificationMessage::from_bytes(notif_bytes);
                PeerDownReason::RemoteNotification(notif)
            }
            4 => PeerDownReason::RemoteNoNotification,
            5 => PeerDownReason::PeerDeConfigured,
            _ => panic!("Unknown peer down reason code: {}", reason_code),
        };

        PeerDownMessage {
            peer_header,
            reason,
        }
    }

    pub async fn read_route_monitoring(&mut self) -> RouteMonitoringMessage {
        let (message_type, body) = self.read_message().await;
        assert_eq!(
            message_type,
            BmpMessageType::RouteMonitoring.as_u8(),
            "Expected Route Monitoring message"
        );

        let peer_header = parse_peer_header(&body);

        // Skip BGP header (19 bytes: 16 marker + 2 length + 1 type) to get UPDATE body
        let bgp_msg_offset = PEER_HEADER_SIZE;
        let bgp_body_offset = bgp_msg_offset + BGP_HEADER_SIZE_BYTES;
        // BMP uses 4-byte ASN encoding per RFC 7854
        let bgp_update = UpdateMessage::from_bytes(
            body[bgp_body_offset..].to_vec(),
            MessageFormat {
                use_4byte_asn: true,
                add_path: AddPathMask::NONE,
                is_ebgp: false,
                enhanced_rr: false,
            },
        )
        .unwrap();

        RouteMonitoringMessage {
            peer_header,
            bgp_update,
        }
    }

    pub async fn read_termination(&mut self) -> TerminationMessage {
        let (message_type, body) = self.read_message().await;
        assert_eq!(
            message_type,
            BmpMessageType::Termination.as_u8(),
            "Expected Termination message"
        );

        let mut information = Vec::new();
        let mut offset = 0;

        while offset < body.len() {
            let info_type = u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap());
            offset += 2;

            let info_length =
                u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;

            let info_value = body[offset..offset + info_length].to_vec();
            offset += info_length;

            information.push(InformationTlv::new(info_type, info_value));
        }

        TerminationMessage { information }
    }

    pub async fn assert_route_monitoring(&mut self, expected: &ExpectedRouteMonitoring) {
        let msg = self.read_route_monitoring().await;
        assert_bmp_route_monitoring_msg(&msg, expected);
    }

    pub async fn assert_peer_up(&mut self, expected: &ExpectedPeerUp) {
        let msg = self.read_peer_up().await;
        assert_bmp_peer_up_msg(&msg, expected);
    }

    pub async fn assert_peer_down(&mut self, expected: &ExpectedPeerDown) {
        let msg = self.read_peer_down().await;
        assert_bmp_peer_down_msg(&msg, expected);
    }

    pub async fn assert_termination(&mut self, expected_reason: TerminationReason) {
        let msg = self.read_termination().await;
        assert_bmp_termination_msg(&msg, expected_reason);
    }

    pub async fn assert_bmp_initiation(
        &mut self,
        expected_sys_name: &str,
        expected_sys_descr: &str,
    ) {
        let msg = self.read_initiation().await;
        assert_bmp_initiation_msg(&msg, expected_sys_name, expected_sys_descr);
    }

    pub async fn read_statistics(&mut self) -> StatisticsReportMessage {
        let (message_type, body) = self.read_message().await;
        assert_eq!(
            message_type,
            BmpMessageType::StatisticsReport.as_u8(),
            "Expected Statistics Report message"
        );

        let peer_header = parse_peer_header(&body);
        let offset = PEER_HEADER_SIZE;

        // Stats count (4 bytes)
        let stats_count = u32::from_be_bytes(body[offset..offset + 4].try_into().unwrap()) as usize;
        let mut offset = offset + 4;

        // Parse statistics TLVs
        let mut statistics = Vec::new();
        for _ in 0..stats_count {
            let stat_type = u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap());
            offset += 2;

            let stat_len =
                u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;

            let stat_value = body[offset..offset + stat_len].to_vec();
            offset += stat_len;

            statistics.push(StatisticsTlv {
                stat_type,
                stat_value,
            });
        }

        StatisticsReportMessage {
            peer_header,
            statistics,
        }
    }

    pub async fn assert_statistics(&mut self, expected: &ExpectedStatistics) {
        let msg = self.read_statistics().await;
        assert_bmp_statistics_msg(&msg, expected);
    }

    /// Read and validate messages in any order
    pub async fn assert_messages_no_order(&mut self, expected: &[ExpectedBmpMessage]) {
        let mut remaining = expected.to_vec();

        for _ in 0..expected.len() {
            let (msg_type, body) = self.read_message().await;

            let msg = if msg_type == BmpMessageType::PeerUpNotification.as_u8() {
                BmpMessage::PeerUp(self.parse_peer_up_from_body(&body))
            } else if msg_type == BmpMessageType::PeerDownNotification.as_u8() {
                BmpMessage::PeerDown(self.parse_peer_down_from_body(&body))
            } else if msg_type == BmpMessageType::StatisticsReport.as_u8() {
                BmpMessage::StatisticsReport(self.parse_statistics_from_body(&body))
            } else if msg_type == BmpMessageType::RouteMonitoring.as_u8() {
                BmpMessage::RouteMonitoring(self.parse_route_monitoring_from_body(&body))
            } else {
                panic!("Unsupported message type: {}", msg_type);
            };

            let pos = remaining.iter().position(|exp_msg| match (&msg, exp_msg) {
                (BmpMessage::PeerUp(a), ExpectedBmpMessage::PeerUp(e)) => {
                    validate_bmp_peer_up_msg(a, e)
                }
                (BmpMessage::PeerDown(a), ExpectedBmpMessage::PeerDown(e)) => {
                    validate_bmp_peer_down_msg(a, e)
                }
                (BmpMessage::StatisticsReport(a), ExpectedBmpMessage::Statistics(e)) => {
                    validate_bmp_statistics_msg(a, e)
                }
                (BmpMessage::RouteMonitoring(a), ExpectedBmpMessage::RouteMonitoring(e)) => {
                    validate_bmp_route_monitoring_msg(a, e)
                }
                _ => false,
            });

            assert!(pos.is_some(), "Unexpected message");
            remaining.swap_remove(pos.unwrap());
        }

        assert!(
            remaining.is_empty(),
            "Missing expected messages: {:?}",
            remaining
        );
    }

    /// Read and validate messages in any order, skipping unexpected RouteMonitoring.
    /// Use this when tests don't care about RouteMonitoring (e.g., EOR messages).
    pub async fn assert_messages_skip_routes(&mut self, expected: &[ExpectedBmpMessage]) {
        let mut remaining = expected.to_vec();

        while !remaining.is_empty() {
            let (msg_type, body) = self.read_message().await;

            // Skip unexpected RouteMonitoring messages (e.g., EOR)
            if msg_type == BmpMessageType::RouteMonitoring.as_u8() {
                let has_expected_route = remaining
                    .iter()
                    .any(|e| matches!(e, ExpectedBmpMessage::RouteMonitoring(_)));
                if !has_expected_route {
                    continue;
                }
            }

            let msg = if msg_type == BmpMessageType::PeerUpNotification.as_u8() {
                BmpMessage::PeerUp(self.parse_peer_up_from_body(&body))
            } else if msg_type == BmpMessageType::PeerDownNotification.as_u8() {
                BmpMessage::PeerDown(self.parse_peer_down_from_body(&body))
            } else if msg_type == BmpMessageType::StatisticsReport.as_u8() {
                BmpMessage::StatisticsReport(self.parse_statistics_from_body(&body))
            } else if msg_type == BmpMessageType::RouteMonitoring.as_u8() {
                BmpMessage::RouteMonitoring(self.parse_route_monitoring_from_body(&body))
            } else {
                panic!("Unsupported message type: {}", msg_type);
            };

            let pos = remaining.iter().position(|exp_msg| match (&msg, exp_msg) {
                (BmpMessage::PeerUp(a), ExpectedBmpMessage::PeerUp(e)) => {
                    validate_bmp_peer_up_msg(a, e)
                }
                (BmpMessage::PeerDown(a), ExpectedBmpMessage::PeerDown(e)) => {
                    validate_bmp_peer_down_msg(a, e)
                }
                (BmpMessage::StatisticsReport(a), ExpectedBmpMessage::Statistics(e)) => {
                    validate_bmp_statistics_msg(a, e)
                }
                (BmpMessage::RouteMonitoring(a), ExpectedBmpMessage::RouteMonitoring(e)) => {
                    validate_bmp_route_monitoring_msg(a, e)
                }
                _ => false,
            });

            assert!(pos.is_some(), "Unexpected message type: {}", msg_type);
            remaining.swap_remove(pos.unwrap());
        }
    }

    fn parse_peer_up_from_body(&self, body: &[u8]) -> PeerUpMessage {
        let peer_header = parse_peer_header(body);
        let mut offset = PEER_HEADER_SIZE;
        let local_address_bytes: [u8; 16] = body[offset..offset + 16].try_into().unwrap();
        let local_address = decode_bmp_ip_address(&local_address_bytes);
        offset += 16;
        let local_port = u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap());
        offset += 2;
        let remote_port = u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap());
        offset += 2;
        let (sent_open, sent_msg_len) = parse_bgp_open_from_bmp(body, offset);
        offset += sent_msg_len;
        let (received_open, _) = parse_bgp_open_from_bmp(body, offset);

        PeerUpMessage {
            peer_header,
            local_address,
            local_port,
            remote_port,
            sent_open_message: sent_open,
            received_open_message: received_open,
            information: Vec::new(),
        }
    }

    fn parse_statistics_from_body(&self, body: &[u8]) -> StatisticsReportMessage {
        let peer_header = parse_peer_header(body);
        let offset = PEER_HEADER_SIZE;
        let stats_count = u32::from_be_bytes(body[offset..offset + 4].try_into().unwrap()) as usize;
        let mut offset = offset + 4;
        let mut statistics = Vec::new();
        for _ in 0..stats_count {
            let stat_type = u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap());
            offset += 2;
            let stat_len =
                u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap()) as usize;
            offset += 2;
            let stat_value = body[offset..offset + stat_len].to_vec();
            offset += stat_len;
            statistics.push(StatisticsTlv {
                stat_type,
                stat_value,
            });
        }
        StatisticsReportMessage {
            peer_header,
            statistics,
        }
    }

    fn parse_peer_down_from_body(&self, body: &[u8]) -> PeerDownMessage {
        let peer_header = parse_peer_header(body);
        let reason_code = body[PEER_HEADER_SIZE];
        let offset = PEER_HEADER_SIZE + 1;

        let reason = match reason_code {
            1 => {
                let notif_bytes = body[offset..].to_vec();
                let notif =
                    bgpgg::bgp::msg_notification::NotificationMessage::from_bytes(notif_bytes);
                PeerDownReason::LocalNotification(notif)
            }
            2 => {
                let event_code = u16::from_be_bytes(body[offset..offset + 2].try_into().unwrap());
                let fsm_event = match event_code {
                    10 => bgpgg::peer::FsmEvent::HoldTimerExpires,
                    _ => bgpgg::peer::FsmEvent::ManualStop,
                };
                PeerDownReason::LocalNoNotification(fsm_event)
            }
            3 => {
                let notif_bytes = body[offset..].to_vec();
                let notif =
                    bgpgg::bgp::msg_notification::NotificationMessage::from_bytes(notif_bytes);
                PeerDownReason::RemoteNotification(notif)
            }
            4 => PeerDownReason::RemoteNoNotification,
            5 => PeerDownReason::PeerDeConfigured,
            _ => panic!("Unknown peer down reason code: {}", reason_code),
        };

        PeerDownMessage {
            peer_header,
            reason,
        }
    }

    fn parse_route_monitoring_from_body(&self, body: &[u8]) -> RouteMonitoringMessage {
        let peer_header = parse_peer_header(body);
        let bgp_msg_offset = PEER_HEADER_SIZE;
        let bgp_body_offset = bgp_msg_offset + BGP_HEADER_SIZE_BYTES;
        let bgp_update = UpdateMessage::from_bytes(
            body[bgp_body_offset..].to_vec(),
            MessageFormat {
                use_4byte_asn: false,
                add_path: AddPathMask::NONE,
                is_ebgp: false,
                enhanced_rr: false,
            },
        )
        .unwrap();

        RouteMonitoringMessage {
            peer_header,
            bgp_update,
        }
    }
}

pub async fn setup_bmp_monitoring(server: &mut TestServer, bmp_server: &mut FakeBmpServer) {
    server
        .client
        .add_bmp_server(bmp_server.address(), None)
        .await
        .unwrap();
    bmp_server.accept().await;
    bmp_server
        .assert_bmp_initiation(&server.config.sys_name(), &server.config.sys_descr())
        .await;
}

/// Assert that an InitiationMessage contains expected sysName and sysDescr
pub fn assert_bmp_initiation_msg(
    actual: &InitiationMessage,
    expected_sys_name: &str,
    expected_sys_descr: &str,
) {
    let sys_name = actual
        .information
        .iter()
        .find(|tlv| tlv.info_type == InitiationType::SysName as u16);
    let sys_descr = actual
        .information
        .iter()
        .find(|tlv| tlv.info_type == InitiationType::SysDescr as u16);

    assert!(sys_name.is_some(), "sysName TLV not found");
    assert!(sys_descr.is_some(), "sysDescr TLV not found");

    assert_eq!(
        String::from_utf8_lossy(&sys_name.unwrap().info_value),
        expected_sys_name
    );
    assert_eq!(
        String::from_utf8_lossy(&sys_descr.unwrap().info_value),
        expected_sys_descr
    );
}

fn validate_bmp_peer_down_msg(actual: &PeerDownMessage, expected: &ExpectedPeerDown) -> bool {
    if actual.peer_header.peer_address != expected.peer_addr
        || actual.peer_header.peer_as != expected.peer_as
        || actual.peer_header.peer_bgp_id != expected.peer_bgp_id
    {
        return false;
    }

    peer_down_reasons_match(&actual.reason, &expected.reason)
}

fn peer_down_reasons_match(actual: &PeerDownReason, expected: &PeerDownReason) -> bool {
    match (actual, expected) {
        (PeerDownReason::LocalNotification(a), PeerDownReason::LocalNotification(e)) => {
            a.error() == e.error() && a.data() == e.data()
        }
        (PeerDownReason::LocalNoNotification(a), PeerDownReason::LocalNoNotification(e)) => {
            a.to_event_code() == e.to_event_code()
        }
        (PeerDownReason::RemoteNotification(a), PeerDownReason::RemoteNotification(e)) => {
            a.error() == e.error() && a.data() == e.data()
        }
        (PeerDownReason::RemoteNoNotification, PeerDownReason::RemoteNoNotification) => true,
        (PeerDownReason::PeerDeConfigured, PeerDownReason::PeerDeConfigured) => true,
        _ => false,
    }
}

/// Assert that a PeerDownMessage matches expected values (ignoring timestamp)
fn assert_bmp_peer_down_msg(actual: &PeerDownMessage, expected: &ExpectedPeerDown) {
    assert!(validate_bmp_peer_down_msg(actual, expected));
}

fn validate_bmp_peer_up_msg(actual: &PeerUpMessage, expected: &ExpectedPeerUp) -> bool {
    actual.local_address == expected.local_addr
        && actual.peer_header.peer_address == expected.peer_addr
        && actual.peer_header.peer_as == expected.peer_as
        && actual.peer_header.peer_bgp_id == expected.peer_bgp_id
        && expected
            .peer_port
            .is_none_or(|port| actual.remote_port == port)
}

/// Assert that a PeerUpMessage matches expected values (ignoring timestamp and local_port)
///
/// Note: local_port is not checked because it's an ephemeral port when the connection
/// is initiated (not the listening port).
pub fn assert_bmp_peer_up_msg(actual: &PeerUpMessage, expected: &ExpectedPeerUp) {
    assert!(
        validate_bmp_peer_up_msg(actual, expected),
        "PeerUpMessage mismatch:\n\
        actual: local={} peer={} as={} bgp_id={} port={}\n\
        expected: local={} peer={} as={} bgp_id={} port={:?}",
        actual.local_address,
        actual.peer_header.peer_address,
        actual.peer_header.peer_as,
        actual.peer_header.peer_bgp_id,
        actual.remote_port,
        expected.local_addr,
        expected.peer_addr,
        expected.peer_as,
        expected.peer_bgp_id,
        expected.peer_port
    );
}

fn validate_bmp_route_monitoring_msg(
    actual: &RouteMonitoringMessage,
    expected: &ExpectedRouteMonitoring,
) -> bool {
    if actual.peer_header().peer_address != expected.peer_addr
        || actual.peer_header().peer_as != expected.peer_as
        || actual.peer_header().peer_bgp_id != expected.peer_bgp_id
        || actual.peer_header().peer_flags != expected.peer_flags
    {
        return false;
    }

    let mut actual_nlri = actual.bgp_update().nlri_prefixes().to_vec();
    let mut expected_nlri = expected.nlri.clone();
    actual_nlri.sort_by_key(|n| format!("{:?}", n));
    expected_nlri.sort_by_key(|n| format!("{:?}", n));

    if actual_nlri != expected_nlri {
        return false;
    }

    let mut actual_withdrawn: Vec<IpNetwork> = actual
        .bgp_update()
        .withdrawn_routes()
        .iter()
        .map(|entry| entry.prefix)
        .collect();
    let mut expected_withdrawn_vec = expected.withdrawn.clone();
    actual_withdrawn.sort_by_key(|n| format!("{:?}", n));
    expected_withdrawn_vec.sort_by_key(|n| format!("{:?}", n));

    actual_withdrawn == expected_withdrawn_vec
}

/// Assert that a RouteMonitoringMessage matches expected values (ignoring timestamp)
pub fn assert_bmp_route_monitoring_msg(
    actual: &RouteMonitoringMessage,
    expected: &ExpectedRouteMonitoring,
) {
    assert!(validate_bmp_route_monitoring_msg(actual, expected));
}

/// Assert that a Termination message has the expected reason code
pub fn assert_bmp_termination_msg(msg: &TerminationMessage, expected_reason: TerminationReason) {
    // Extract reason code from the Reason TLV
    let actual_reason_code = msg
        .information
        .iter()
        .find(|tlv| tlv.info_type == TerminationType::Reason as u16)
        .map(|tlv| u16::from_be_bytes(tlv.info_value[..2].try_into().unwrap()))
        .unwrap_or(1);

    assert_eq!(
        actual_reason_code,
        expected_reason.as_u16(),
        "Termination reason code mismatch"
    );
}

fn validate_bmp_statistics_msg(
    actual: &StatisticsReportMessage,
    expected: &ExpectedStatistics,
) -> bool {
    if actual.peer_header.peer_address != expected.peer_addr
        || actual.peer_header.peer_as != expected.peer_as
        || actual.peer_header.peer_bgp_id != expected.peer_bgp_id
        || actual.statistics.len() != expected.stats.len()
    {
        return false;
    }

    for (stat_tlv, (expected_type, expected_value)) in
        actual.statistics.iter().zip(expected.stats.iter())
    {
        if stat_tlv.stat_type != *expected_type {
            return false;
        }

        let actual_value = match stat_tlv.stat_value.len() {
            4 => u32::from_be_bytes(stat_tlv.stat_value[..].try_into().unwrap()) as u64,
            8 => u64::from_be_bytes(stat_tlv.stat_value[..].try_into().unwrap()),
            _ => return false,
        };

        if actual_value != *expected_value {
            return false;
        }
    }

    true
}

/// Assert that a Statistics Report message matches expected values
pub fn assert_bmp_statistics_msg(actual: &StatisticsReportMessage, expected: &ExpectedStatistics) {
    assert!(validate_bmp_statistics_msg(actual, expected));
}
