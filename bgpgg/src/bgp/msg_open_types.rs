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

use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use std::collections::HashSet;

pub(crate) const BGP_VERSION: u8 = 4;

/// RFC 7911: ADD-PATH send/receive mode per AFI/SAFI
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum AddPathMode {
    Receive = 1,
    Send = 2,
    Both = 3,
}

impl AddPathMode {
    pub fn from_flags(send: bool, receive: bool) -> Option<Self> {
        match (send, receive) {
            (true, true) => Some(AddPathMode::Both),
            (true, false) => Some(AddPathMode::Send),
            (false, true) => Some(AddPathMode::Receive),
            (false, false) => None,
        }
    }

    pub fn can_send(self) -> bool {
        matches!(self, AddPathMode::Send | AddPathMode::Both)
    }

    pub fn can_receive(self) -> bool {
        matches!(self, AddPathMode::Receive | AddPathMode::Both)
    }
}

impl TryFrom<u8> for AddPathMode {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AddPathMode::Receive),
            2 => Ok(AddPathMode::Send),
            3 => Ok(AddPathMode::Both),
            _ => Err(()),
        }
    }
}

/// RFC 7911: ADD-PATH capability information
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AddPathCapability {
    pub entries: Vec<(AfiSafi, AddPathMode)>,
}

/// Graceful Restart capability information
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GracefulRestartCapability {
    pub(crate) restart_time: u16,
    pub(crate) restart_state: bool,
    pub(crate) afi_safi_list: Vec<(AfiSafi, bool)>,
}

impl GracefulRestartCapability {
    /// Extract just the AFI/SAFIs (without F-bit flags)
    pub fn afi_safis(&self) -> Vec<AfiSafi> {
        self.afi_safi_list
            .iter()
            .map(|(afi_safi, _f_bit)| *afi_safi)
            .collect()
    }

    /// Check if forwarding state was preserved for a specific AFI/SAFI (RFC 4724 F-bit)
    /// Returns None if AFI/SAFI is not in the capability
    pub fn forwarding_preserved(&self, afi_safi: AfiSafi) -> Option<bool> {
        self.afi_safi_list
            .iter()
            .find(|(as_, _)| *as_ == afi_safi)
            .map(|(_, f_bit)| *f_bit)
    }
}

/// RFC 9494: Per-AFI/SAFI entry in LLGR capability
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LlgrEntry {
    pub afi_safi: AfiSafi,
    /// F-bit: forwarding state preserved during LLGR
    pub forwarding_preserved: bool,
    /// Long-Lived Stale Time in seconds (24-bit on wire)
    pub stale_time: u32,
}

/// RFC 9494: Long-Lived Graceful Restart capability information
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LlgrCapability {
    pub(crate) entries: Vec<LlgrEntry>,
}

/// F-bit based stale route filtering for GR and LLGR capabilities.
pub trait StaleFilter {
    /// Returns true if stale routes for this AFI/SAFI should be cleared on reconnect.
    fn should_clear_stale(&self, afi_safi: AfiSafi) -> bool;

    /// Filter stale AFI/SAFIs to those that should be cleared on reconnect.
    fn filter_stale(&self, stale: HashSet<AfiSafi>) -> Vec<AfiSafi> {
        stale
            .into_iter()
            .filter(|a| self.should_clear_stale(*a))
            .collect()
    }
}

impl StaleFilter for GracefulRestartCapability {
    fn should_clear_stale(&self, afi_safi: AfiSafi) -> bool {
        self.forwarding_preserved(afi_safi) != Some(true)
    }
}

impl StaleFilter for LlgrCapability {
    fn should_clear_stale(&self, afi_safi: AfiSafi) -> bool {
        match self.entries.iter().find(|e| e.afi_safi == afi_safi) {
            Some(entry) => !entry.forwarding_preserved,
            None => true,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum BgpCapabiltyCode {
    Multiprotocol = 1,
    RouteRefresh = 2,
    GracefulRestart = 64,
    FourOctetAsn = 65,
    AddPath = 69,
    EnhancedRouteRefresh = 70,
    Llgr = 71,
    Unknown,
}

impl From<u8> for BgpCapabiltyCode {
    fn from(value: u8) -> Self {
        match value {
            1 => BgpCapabiltyCode::Multiprotocol,
            2 => BgpCapabiltyCode::RouteRefresh,
            64 => BgpCapabiltyCode::GracefulRestart,
            65 => BgpCapabiltyCode::FourOctetAsn,
            69 => BgpCapabiltyCode::AddPath,
            70 => BgpCapabiltyCode::EnhancedRouteRefresh,
            71 => BgpCapabiltyCode::Llgr,
            _ => BgpCapabiltyCode::Unknown,
        }
    }
}

impl BgpCapabiltyCode {
    pub(crate) fn as_u8(&self) -> u8 {
        match self {
            BgpCapabiltyCode::Multiprotocol => 1,
            BgpCapabiltyCode::RouteRefresh => 2,
            BgpCapabiltyCode::GracefulRestart => 64,
            BgpCapabiltyCode::FourOctetAsn => 65,
            BgpCapabiltyCode::AddPath => 69,
            BgpCapabiltyCode::EnhancedRouteRefresh => 70,
            BgpCapabiltyCode::Llgr => 71,
            BgpCapabiltyCode::Unknown => 0,
        }
    }
}

// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11
#[derive(Debug, PartialEq, Clone)]
#[repr(u8)]
pub(crate) enum OptParamType {
    Capabilities = 2, // RFC3392
    Unknown(u8),
}

impl From<u8> for OptParamType {
    fn from(value: u8) -> Self {
        match value {
            2 => OptParamType::Capabilities,
            val => OptParamType::Unknown(val),
        }
    }
}

impl OptParamType {
    pub(crate) fn as_u8(&self) -> u8 {
        match self {
            OptParamType::Capabilities => 2,
            OptParamType::Unknown(val) => *val,
        }
    }
}

/// Value of a BGP OPEN Optional Parameter (RFC 5492).
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum OptParamVal {
    Capabilities(Vec<Capability>),
    Unknown(Vec<u8>),
}

impl OptParamVal {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        match self {
            OptParamVal::Capabilities(caps) => {
                let mut bytes = Vec::new();
                for cap in caps {
                    bytes.extend_from_slice(&cap.to_bytes());
                }
                bytes
            }
            OptParamVal::Unknown(data) => data.clone(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct Capability {
    pub(crate) code: BgpCapabiltyCode,
    pub(crate) len: u8,
    pub(crate) val: Vec<u8>,
}

/// Convert AfiSafi to capability bytes
/// Format: [AFI_HIGH, AFI_LOW, RESERVED, SAFI]
pub(crate) fn afi_safi_to_capability_bytes(afi_safi: &AfiSafi) -> Vec<u8> {
    let afi_bytes = (afi_safi.afi as u16).to_be_bytes();
    vec![afi_bytes[0], afi_bytes[1], 0x00, afi_safi.safi as u8]
}

impl Capability {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.code.as_u8());
        bytes.push(self.len);
        bytes.extend_from_slice(&self.val);
        bytes
    }

    /// Create a Route Refresh capability (RFC 2918)
    pub(crate) fn new_route_refresh() -> Self {
        Capability {
            code: BgpCapabiltyCode::RouteRefresh,
            len: 0,
            val: vec![],
        }
    }

    /// Create an Enhanced Route Refresh capability (RFC 7313, capability code 70)
    pub(crate) fn new_enhanced_route_refresh() -> Self {
        Capability {
            code: BgpCapabiltyCode::EnhancedRouteRefresh,
            len: 0,
            val: vec![],
        }
    }

    /// Create a Multiprotocol capability (RFC 4760)
    pub(crate) fn new_multiprotocol(afi_safi: &AfiSafi) -> Self {
        let val = afi_safi_to_capability_bytes(afi_safi);

        Capability {
            code: BgpCapabiltyCode::Multiprotocol,
            len: val.len() as u8,
            val,
        }
    }

    /// Create a Four-Octet ASN capability (RFC 6793)
    pub(crate) fn new_four_octet_asn(asn: u32) -> Self {
        Capability {
            code: BgpCapabiltyCode::FourOctetAsn,
            len: 4,
            val: asn.to_be_bytes().to_vec(),
        }
    }

    /// Extract the four-octet ASN value if this is a FourOctetAsn capability
    pub(crate) fn as_four_octet_asn(&self) -> Option<u32> {
        if matches!(self.code, BgpCapabiltyCode::FourOctetAsn) && self.val.len() == 4 {
            Some(u32::from_be_bytes([
                self.val[0],
                self.val[1],
                self.val[2],
                self.val[3],
            ]))
        } else {
            None
        }
    }

    // RFC 9494 LLGR capability format constants
    const LLGR_TUPLE_LEN: usize = 7; // AFI(2) + SAFI(1) + Flags(1) + StaleTime(3)
    const LLGR_F_FLAG: u8 = 0x80; // F bit (MSB): forwarding state preserved

    // RFC 7911 ADD-PATH capability format constants
    const ADD_PATH_TUPLE_LEN: usize = 4; // AFI(2) + SAFI(1) + Send/Receive(1)

    // RFC 4724 Graceful Restart capability format constants
    const GR_RESTART_HEADER_LEN: usize = 2; // Restart flags (4 bits) + Time (12 bits)
    const GR_AFI_SAFI_TUPLE_LEN: usize = 4; // AFI(2) + SAFI(1) + Flags(1)
    const GR_RESTART_FLAG_MASK: u8 = 0x80; // R bit (MSB)
    const GR_FORWARDING_FLAG_MASK: u8 = 0x80; // F bit (MSB)
    const GR_RESTART_TIME_MASK: u16 = 0x0FFF; // 12 bits
    const GR_RESTART_TIME_LOW_MASK: u8 = 0x0F; // Lower 4 bits of first byte

    /// Create a Graceful Restart capability (RFC 4724)
    /// restart_time: seconds (12 bits, max 4095)
    /// restart_state: R bit - if true, indicates router is restarting
    /// afi_safi_list: list of (AfiSafi, forwarding_state) tuples
    ///   forwarding_state: F bit - if true, forwarding state preserved
    pub(crate) fn new_graceful_restart(
        restart_time: u16,
        restart_state: bool,
        afi_safi_list: Vec<(AfiSafi, bool)>,
    ) -> Self {
        debug_assert!(
            restart_time <= Self::GR_RESTART_TIME_MASK,
            "restart_time {} exceeds 12-bit maximum (4095)",
            restart_time
        );

        let mut val = Vec::new();

        // Restart Flags (4 bits) + Restart Time (12 bits)
        let restart_flags = if restart_state {
            Self::GR_RESTART_FLAG_MASK
        } else {
            0x00
        };
        let restart_time_masked = restart_time & Self::GR_RESTART_TIME_MASK;
        let first_byte = restart_flags | ((restart_time_masked >> 8) as u8);
        let second_byte = (restart_time_masked & 0xFF) as u8;
        val.push(first_byte);
        val.push(second_byte);

        // AFI/SAFI tuples: AFI(2) + SAFI(1) + Flags(1)
        for (afi_safi, forwarding_state) in afi_safi_list {
            let afi_bytes = (afi_safi.afi as u16).to_be_bytes();
            val.push(afi_bytes[0]);
            val.push(afi_bytes[1]);
            val.push(afi_safi.safi as u8);
            let flags = if forwarding_state {
                Self::GR_FORWARDING_FLAG_MASK
            } else {
                0x00
            };
            val.push(flags);
        }

        Capability {
            code: BgpCapabiltyCode::GracefulRestart,
            len: val.len() as u8,
            val,
        }
    }

    /// Create an ADD-PATH capability (RFC 7911)
    /// Each entry is (AfiSafi, mode) where mode indicates send/receive/both
    pub(crate) fn new_add_path(entries: &[(AfiSafi, AddPathMode)]) -> Self {
        let mut val = Vec::new();
        for (afi_safi, mode) in entries {
            let afi_bytes = (afi_safi.afi as u16).to_be_bytes();
            val.push(afi_bytes[0]);
            val.push(afi_bytes[1]);
            val.push(afi_safi.safi as u8);
            val.push(*mode as u8);
        }
        Capability {
            code: BgpCapabiltyCode::AddPath,
            len: val.len() as u8,
            val,
        }
    }

    /// Extract ADD-PATH capability info if this is an AddPath capability
    pub(crate) fn as_add_path(&self) -> Option<AddPathCapability> {
        if !matches!(self.code, BgpCapabiltyCode::AddPath) {
            return None;
        }

        let mut entries = Vec::new();
        let mut offset = 0;
        while offset + Self::ADD_PATH_TUPLE_LEN <= self.val.len() {
            let afi_val = u16::from_be_bytes([self.val[offset], self.val[offset + 1]]);
            let safi_val = self.val[offset + 2];
            let mode_val = self.val[offset + 3];

            if let (Ok(afi), Ok(safi), Ok(mode)) = (
                Afi::try_from(afi_val),
                Safi::try_from(safi_val),
                AddPathMode::try_from(mode_val),
            ) {
                entries.push((AfiSafi::new(afi, safi), mode));
            }
            offset += Self::ADD_PATH_TUPLE_LEN;
        }

        Some(AddPathCapability { entries })
    }

    /// Extract Graceful Restart capability info if this is a GracefulRestart capability
    pub(crate) fn as_graceful_restart(&self) -> Option<GracefulRestartCapability> {
        if !matches!(self.code, BgpCapabiltyCode::GracefulRestart)
            || self.val.len() < Self::GR_RESTART_HEADER_LEN
        {
            return None;
        }

        // Parse restart flags and time
        let first_byte = self.val[0];
        let second_byte = self.val[1];

        let restart_state = (first_byte & Self::GR_RESTART_FLAG_MASK) != 0;
        let restart_time =
            (((first_byte & Self::GR_RESTART_TIME_LOW_MASK) as u16) << 8) | (second_byte as u16);

        // Parse AFI/SAFI tuples
        let mut afi_safi_list = Vec::new();
        let mut offset = Self::GR_RESTART_HEADER_LEN;
        while offset + Self::GR_AFI_SAFI_TUPLE_LEN <= self.val.len() {
            let afi_bytes = [self.val[offset], self.val[offset + 1]];
            let afi_val = u16::from_be_bytes(afi_bytes);
            let safi_val = self.val[offset + 2];
            let flags = self.val[offset + 3];

            // Try to parse AFI/SAFI, skip if unknown
            if let (Ok(afi), Ok(safi)) = (Afi::try_from(afi_val), Safi::try_from(safi_val)) {
                let forwarding_state = (flags & Self::GR_FORWARDING_FLAG_MASK) != 0;
                afi_safi_list.push((AfiSafi::new(afi, safi), forwarding_state));
            }

            offset += Self::GR_AFI_SAFI_TUPLE_LEN;
        }

        Some(GracefulRestartCapability {
            restart_time,
            restart_state,
            afi_safi_list,
        })
    }

    /// Create a Long-Lived Graceful Restart capability (RFC 9494)
    pub(crate) fn new_llgr(entries: &[LlgrEntry]) -> Self {
        let mut val = Vec::new();
        for entry in entries {
            let afi_bytes = (entry.afi_safi.afi as u16).to_be_bytes();
            val.push(afi_bytes[0]);
            val.push(afi_bytes[1]);
            val.push(entry.afi_safi.safi as u8);
            let flags = if entry.forwarding_preserved {
                Self::LLGR_F_FLAG
            } else {
                0x00
            };
            val.push(flags);
            // Stale time: 3 bytes big-endian
            val.push((entry.stale_time >> 16) as u8);
            val.push((entry.stale_time >> 8) as u8);
            val.push(entry.stale_time as u8);
        }
        Capability {
            code: BgpCapabiltyCode::Llgr,
            len: val.len() as u8,
            val,
        }
    }

    /// Extract LLGR capability info if this is an Llgr capability
    pub(crate) fn as_llgr(&self) -> Option<LlgrCapability> {
        if !matches!(self.code, BgpCapabiltyCode::Llgr) {
            return None;
        }

        let mut entries = Vec::new();
        let mut offset = 0;
        while offset + Self::LLGR_TUPLE_LEN <= self.val.len() {
            let afi_val = u16::from_be_bytes([self.val[offset], self.val[offset + 1]]);
            let safi_val = self.val[offset + 2];
            let flags = self.val[offset + 3];
            let stale_time = ((self.val[offset + 4] as u32) << 16)
                | ((self.val[offset + 5] as u32) << 8)
                | (self.val[offset + 6] as u32);

            if let (Ok(afi), Ok(safi)) = (Afi::try_from(afi_val), Safi::try_from(safi_val)) {
                entries.push(LlgrEntry {
                    afi_safi: AfiSafi::new(afi, safi),
                    forwarding_preserved: (flags & Self::LLGR_F_FLAG) != 0,
                    stale_time,
                });
            }

            offset += Self::LLGR_TUPLE_LEN;
        }

        Some(LlgrCapability { entries })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct OptionalParam {
    pub(crate) param_type: OptParamType,
    pub(crate) param_len: u8,
    pub(crate) param_value: OptParamVal,
}

impl OptionalParam {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.param_type.as_u8());
        bytes.push(self.param_len);
        bytes.extend_from_slice(&self.param_value.to_bytes());
        bytes
    }

    /// Create a Capabilities Optional Parameter from a list of capabilities.
    pub(crate) fn from_capabilities(capabilities: Vec<Capability>) -> Self {
        let param_len: usize = capabilities.iter().map(|cap| 2 + cap.len as usize).sum();
        OptionalParam {
            param_type: OptParamType::Capabilities,
            param_len: param_len as u8,
            param_value: OptParamVal::Capabilities(capabilities),
        }
    }

    pub(crate) fn capabilities(&self) -> &[Capability] {
        match &self.param_value {
            OptParamVal::Capabilities(caps) => caps,
            OptParamVal::Unknown(_) => &[],
        }
    }

    /// Find and extract the four-octet ASN capability from optional parameters.
    pub(crate) fn find_four_octet_asn(params: &[OptionalParam]) -> Option<u32> {
        params
            .iter()
            .flat_map(|p| p.capabilities())
            .find_map(|cap| cap.as_four_octet_asn())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};

    #[test]
    fn test_afi_safi_to_capability_bytes() {
        let cases = vec![
            (
                AfiSafi::new(Afi::Ipv4, Safi::Unicast),
                vec![0x00, 0x01, 0x00, 0x01],
            ),
            (
                AfiSafi::new(Afi::Ipv6, Safi::Unicast),
                vec![0x00, 0x02, 0x00, 0x01],
            ),
            (
                AfiSafi::new(Afi::Ipv4, Safi::Multicast),
                vec![0x00, 0x01, 0x00, 0x02],
            ),
        ];

        for (afi_safi, expected_bytes) in cases {
            let bytes = afi_safi_to_capability_bytes(&afi_safi);
            assert_eq!(bytes, expected_bytes, "{:?}", afi_safi);
        }
    }

    #[test]
    fn test_find_four_octet_asn() {
        let ipv4 = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        let cases: Vec<(&str, Vec<OptionalParam>, Option<u32>)> = vec![
            (
                "single cap",
                vec![OptionalParam::from_capabilities(vec![
                    Capability::new_four_octet_asn(65536),
                ])],
                Some(65536),
            ),
            (
                "split across params",
                vec![
                    OptionalParam::from_capabilities(vec![Capability::new_route_refresh()]),
                    OptionalParam::from_capabilities(vec![Capability::new_four_octet_asn(
                        4200000000,
                    )]),
                    OptionalParam::from_capabilities(vec![Capability::new_multiprotocol(&ipv4)]),
                ],
                Some(4200000000),
            ),
            (
                "packed in one param",
                vec![OptionalParam::from_capabilities(vec![
                    Capability::new_route_refresh(),
                    Capability::new_multiprotocol(&ipv4),
                    Capability::new_four_octet_asn(4242423914),
                ])],
                Some(4242423914),
            ),
            (
                "no four-octet cap",
                vec![OptionalParam::from_capabilities(vec![
                    Capability::new_route_refresh(),
                ])],
                None,
            ),
            ("empty", vec![], None),
        ];

        for (name, params, expected) in cases {
            assert_eq!(
                OptionalParam::find_four_octet_asn(&params),
                expected,
                "case: {name}"
            );
        }
    }

    #[test]
    fn test_graceful_restart_roundtrip() {
        let cases = vec![
            (
                120,
                false,
                vec![(AfiSafi::new(Afi::Ipv4, Safi::Unicast), false)],
            ),
            (
                180,
                true,
                vec![(AfiSafi::new(Afi::Ipv4, Safi::Unicast), true)],
            ),
            (
                4095,
                true,
                vec![
                    (AfiSafi::new(Afi::Ipv4, Safi::Unicast), true),
                    (AfiSafi::new(Afi::Ipv6, Safi::Unicast), false),
                ],
            ),
            (0, false, vec![]),
        ];

        for (restart_time, restart_state, afi_safi_list) in cases {
            let cap = Capability::new_graceful_restart(
                restart_time,
                restart_state,
                afi_safi_list.clone(),
            );

            let parsed = cap
                .as_graceful_restart()
                .expect("should parse created capability");

            assert_eq!(parsed.restart_time, restart_time);
            assert_eq!(parsed.restart_state, restart_state);
            assert_eq!(parsed.afi_safi_list, afi_safi_list);
        }
    }

    #[test]
    fn test_add_path_roundtrip() {
        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        let ipv6_unicast = AfiSafi::new(Afi::Ipv6, Safi::Unicast);

        let cases = vec![
            vec![(ipv4_unicast, AddPathMode::Send)],
            vec![(ipv4_unicast, AddPathMode::Receive)],
            vec![(ipv4_unicast, AddPathMode::Both)],
            vec![
                (ipv4_unicast, AddPathMode::Send),
                (ipv6_unicast, AddPathMode::Both),
            ],
        ];

        for entries in cases {
            let cap = Capability::new_add_path(&entries);
            let parsed = cap.as_add_path().expect("should parse ADD-PATH capability");
            assert_eq!(parsed.entries, entries);
        }
    }

    #[test]
    fn test_llgr_capability_roundtrip() {
        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        let ipv6_unicast = AfiSafi::new(Afi::Ipv6, Safi::Unicast);

        let entry = |afi_safi, forwarding_preserved, stale_time| LlgrEntry {
            afi_safi,
            forwarding_preserved,
            stale_time,
        };

        let cases = vec![
            vec![entry(ipv4_unicast, false, 3600)],
            vec![
                entry(ipv4_unicast, false, 120),
                entry(ipv6_unicast, true, 86400),
            ],
            vec![entry(ipv4_unicast, true, 0xFFFFFF)],
            vec![entry(ipv4_unicast, false, 0)],
        ];

        for entries in cases {
            let cap = Capability::new_llgr(&entries);
            let parsed = cap.as_llgr().expect("should parse LLGR capability");
            assert_eq!(parsed.entries, entries);
        }
    }

    #[test]
    fn test_llgr_capability_f_bit() {
        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);

        let cap = Capability::new_llgr(&[LlgrEntry {
            afi_safi: ipv4_unicast,
            forwarding_preserved: true,
            stale_time: 100,
        }]);
        let parsed = cap.as_llgr().unwrap();
        assert!(parsed.entries[0].forwarding_preserved);

        let cap = Capability::new_llgr(&[LlgrEntry {
            afi_safi: ipv4_unicast,
            forwarding_preserved: false,
            stale_time: 100,
        }]);
        let parsed = cap.as_llgr().unwrap();
        assert!(!parsed.entries[0].forwarding_preserved);
    }

    #[test]
    fn test_llgr_should_clear_stale() {
        let ipv4_unicast = AfiSafi::new(Afi::Ipv4, Safi::Unicast);
        let ipv6_unicast = AfiSafi::new(Afi::Ipv6, Safi::Unicast);
        let ipv4_multicast = AfiSafi::new(Afi::Ipv4, Safi::Multicast);

        let llgr = LlgrCapability {
            entries: vec![
                LlgrEntry {
                    afi_safi: ipv4_unicast,
                    forwarding_preserved: true,
                    stale_time: 3600,
                },
                LlgrEntry {
                    afi_safi: ipv6_unicast,
                    forwarding_preserved: false,
                    stale_time: 3600,
                },
            ],
        };

        // F-bit=true -> don't clear
        assert!(!llgr.should_clear_stale(ipv4_unicast));
        // F-bit=false -> clear
        assert!(llgr.should_clear_stale(ipv6_unicast));
        // Not in cap -> clear
        assert!(llgr.should_clear_stale(ipv4_multicast));
    }

    #[test]
    fn test_add_path_mode_helpers() {
        assert!(AddPathMode::Send.can_send());
        assert!(!AddPathMode::Send.can_receive());
        assert!(!AddPathMode::Receive.can_send());
        assert!(AddPathMode::Receive.can_receive());
        assert!(AddPathMode::Both.can_send());
        assert!(AddPathMode::Both.can_receive());
    }
}
