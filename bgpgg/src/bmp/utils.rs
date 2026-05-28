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

use std::net::IpAddr;
use std::time::SystemTime;

/// Encode IP address to 16-byte format (IPv4-mapped for IPv4)
pub(super) fn encode_ip_address(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(ipv4) => {
            let mut bytes = [0u8; 16];
            bytes[12..16].copy_from_slice(&ipv4.octets());
            bytes
        }
        IpAddr::V6(ipv6) => ipv6.octets(),
    }
}

/// Initiation message Information TLV types
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub enum InitiationType {
    String = 0,
    SysDescr = 1,
    SysName = 2,
}

/// Termination message Information TLV types
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub enum TerminationType {
    String = 0,
    Reason = 1,
}

/// Peer Up message Information TLV types (RFC 7854 Section 4.10)
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub(super) enum PeerUpInfoType {
    String = 0, // Only type defined for Peer Up messages
}

/// BMP Peer Type (RFC 7854 Section 4.2)
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerType {
    GlobalInstance = 0,
    RdInstance = 1,
    LocalInstance = 2,
}

/// Peer Distinguisher field interpretation based on peer type (RFC 7854 Section 4.2)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerDistinguisher {
    /// Global Instance - zero-filled
    Global,
    /// RD Instance - route distinguisher value
    Rd(u64),
    /// Local Instance - locally defined unique value
    Local(u64),
}

impl PeerDistinguisher {
    fn to_u64(self) -> u64 {
        match self {
            Self::Global => 0,
            Self::Rd(rd) => rd,
            Self::Local(id) => id,
        }
    }

    fn peer_type(self) -> PeerType {
        match self {
            Self::Global => PeerType::GlobalInstance,
            Self::Rd(_) => PeerType::RdInstance,
            Self::Local(_) => PeerType::LocalInstance,
        }
    }
}

/// Information TLV used in Initiation and Termination messages
#[derive(Clone, Debug)]
pub struct InformationTlv {
    pub info_type: u16,
    pub info_value: Vec<u8>,
}

impl InformationTlv {
    pub fn new(info_type: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            info_type,
            info_value: value.into(),
        }
    }

    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.info_type.to_be_bytes());
        bytes.extend_from_slice(&(self.info_value.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.info_value);
        bytes
    }
}

/// Per-Peer Header size in bytes (RFC 7854 Section 4.2)
pub const PEER_HEADER_SIZE: usize = 42;

/// Per-Peer Header used in most BMP messages
#[derive(Clone, Debug)]
pub struct PeerHeader {
    pub peer_distinguisher: PeerDistinguisher,
    pub peer_flags: u8,
    pub peer_address: IpAddr,
    pub peer_as: u32,
    pub peer_bgp_id: u32,
    pub timestamp_seconds: u32,
    pub timestamp_microseconds: u32,
}

impl PeerHeader {
    const FLAG_V6: u8 = 0b10000000; // V flag: IPv6 address
    const FLAG_L: u8 = 0b01000000; // L flag: post-policy Adj-RIB-In
    const FLAG_A: u8 = 0b00100000; // A flag: legacy 2-byte AS_PATH format

    pub(super) fn new(
        peer_distinguisher: PeerDistinguisher,
        peer_address: IpAddr,
        peer_as: u32,
        peer_bgp_id: u32,
        post_policy: bool,
        use_4byte_asn: bool,
        timestamp: Option<SystemTime>,
    ) -> Self {
        let (timestamp_seconds, timestamp_microseconds) = timestamp
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| (d.as_secs() as u32, d.subsec_micros()))
            .unwrap_or((0, 0));

        Self {
            peer_distinguisher,
            peer_flags: Self::build_peer_flags(peer_address, post_policy, use_4byte_asn),
            peer_address,
            peer_as,
            peer_bgp_id,
            timestamp_seconds,
            timestamp_microseconds,
        }
    }

    pub(super) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Peer Type (1 byte)
        bytes.push(self.peer_distinguisher.peer_type() as u8);

        // Peer Flags (1 byte)
        bytes.push(self.peer_flags);

        // Peer Distinguisher (8 bytes)
        bytes.extend_from_slice(&self.peer_distinguisher.to_u64().to_be_bytes());

        // Peer Address (16 bytes, IPv4-mapped if IPv4)
        bytes.extend_from_slice(&encode_ip_address(self.peer_address));

        // Peer AS (4 bytes)
        bytes.extend_from_slice(&self.peer_as.to_be_bytes());

        // Peer BGP ID (4 bytes)
        bytes.extend_from_slice(&self.peer_bgp_id.to_be_bytes());

        // Timestamp (4 + 4 bytes)
        bytes.extend_from_slice(&self.timestamp_seconds.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp_microseconds.to_be_bytes());

        bytes
    }

    fn build_peer_flags(peer_address: IpAddr, post_policy: bool, use_4byte_asn: bool) -> u8 {
        let mut flags = match peer_address {
            IpAddr::V6(_) => Self::FLAG_V6,
            IpAddr::V4(_) => 0,
        };

        if post_policy {
            flags |= Self::FLAG_L;
        }

        if !use_4byte_asn {
            flags |= Self::FLAG_A;
        }

        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_encode_ip_address() {
        let tests = [
            (
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1],
            ),
            (
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1],
            ),
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ),
        ];

        for (addr, expected) in tests {
            assert_eq!(encode_ip_address(addr), expected);
        }
    }

    #[test]
    fn test_peer_distinguisher() {
        let tests = [
            (PeerDistinguisher::Global, PeerType::GlobalInstance, 0),
            (PeerDistinguisher::Rd(12345), PeerType::RdInstance, 12345),
            (PeerDistinguisher::Local(99), PeerType::LocalInstance, 99),
        ];

        for (dist, expected_type, expected_value) in tests {
            assert_eq!(dist.peer_type(), expected_type);
            assert_eq!(dist.to_u64(), expected_value);
        }
    }

    #[test]
    fn test_peer_header_distinguisher_serialization() {
        let tests = [
            (PeerDistinguisher::Global, 0u8, 0u64),
            (
                PeerDistinguisher::Rd(0x1234567890abcdef),
                1u8,
                0x1234567890abcdef,
            ),
            (PeerDistinguisher::Local(42), 2u8, 42),
        ];

        for (dist, expected_type_byte, expected_distinguisher_value) in tests {
            let header = PeerHeader::new(
                dist,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                65001,
                0x01010101,
                false,
                false,
                Some(SystemTime::now()),
            );
            let bytes = header.to_bytes();

            assert_eq!(bytes[0], expected_type_byte);
            let distinguisher_bytes = &bytes[2..10];
            let distinguisher = u64::from_be_bytes(distinguisher_bytes.try_into().unwrap());
            assert_eq!(distinguisher, expected_distinguisher_value);
        }
    }

    #[test]
    fn test_peer_header_timestamp() {
        // Test with actual timestamp
        let now = SystemTime::now();
        let header_with_time = PeerHeader::new(
            PeerDistinguisher::Global,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            false,
            false,
            Some(now),
        );
        assert_ne!(header_with_time.timestamp_seconds, 0);

        // Test with None - should produce 0,0 (RFC 7854 Section 5)
        let header_without_time = PeerHeader::new(
            PeerDistinguisher::Global,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            65001,
            0x01010101,
            false,
            false,
            None,
        );
        assert_eq!(header_without_time.timestamp_seconds, 0);
        assert_eq!(header_without_time.timestamp_microseconds, 0);

        let bytes = header_without_time.to_bytes();
        // Timestamp starts at offset 34 (4 bytes seconds + 4 bytes microseconds)
        assert_eq!(&bytes[34..38], &[0, 0, 0, 0]); // seconds
        assert_eq!(&bytes[38..42], &[0, 0, 0, 0]); // microseconds
    }

    #[test]
    fn test_peer_header_flags() {
        let tests = [
            // (address, post_policy, use_4byte_asn, expected_flags)
            (
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                false,
                true,
                0b00000000,
            ),
            (
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                true,
                true,
                0b01000000,
            ),
            (
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                false,
                false,
                0b00100000,
            ),
            (
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                true,
                false,
                0b01100000,
            ),
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                false,
                true,
                0b10000000,
            ),
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                true,
                true,
                0b11000000,
            ),
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                false,
                false,
                0b10100000,
            ),
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                true,
                false,
                0b11100000,
            ),
        ];

        for (addr, post_policy, use_4byte_asn, expected_flags) in tests {
            let header = PeerHeader::new(
                PeerDistinguisher::Global,
                addr,
                65001,
                0x01010101,
                post_policy,
                use_4byte_asn,
                Some(SystemTime::now()),
            );
            let bytes = header.to_bytes();

            assert_eq!(
                bytes[1], expected_flags,
                "flags mismatch for {:?}, post_policy={}, use_4byte_asn={}",
                addr, post_policy, use_4byte_asn
            );
        }
    }
}
