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

/// Helper functions for BGP community values.
/// RFC 1997: community = (ASN << 16) | value
/// Create a community value from ASN and local value (ASN:value format).
pub const fn from_asn_value(asn: u16, value: u16) -> u32 {
    ((asn as u32) << 16) | (value as u32)
}

/// Extract ASN from a community value (high 16 bits).
pub const fn asn(community: u32) -> u16 {
    (community >> 16) as u16
}

/// Extract local value from a community value (low 16 bits).
pub const fn value(community: u32) -> u16 {
    community as u16
}

pub const NO_EXPORT: u32 = 0xFFFFFF01;
pub const NO_ADVERTISE: u32 = 0xFFFFFF02;
pub const NO_EXPORT_SUBCONFED: u32 = 0xFFFFFF03;
/// RFC 8326: well-known community for graceful BGP session shutdown
pub const GRACEFUL_SHUTDOWN: u32 = 0xFFFF0000;
/// RFC 9494: route was retained during Long-Lived Graceful Restart
pub const LLGR_STALE: u32 = 0xFFFF0006;
/// RFC 9494: do not retain this route during Long-Lived Graceful Restart
pub const NO_LLGR: u32 = 0xFFFF0007;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_community_from_asn_value() {
        assert_eq!(from_asn_value(1, 100), 0x00010064);
        assert_eq!(from_asn_value(65001, 200), 0xFDE900C8);
        assert_eq!(from_asn_value(0, 1), 0x00000001);
        assert_eq!(from_asn_value(65535, 65535), 0xFFFFFFFF);
    }

    #[test]
    fn test_community_asn() {
        assert_eq!(asn(0x00010064), 1);
        assert_eq!(asn(0xFDE900C8), 65001);
        assert_eq!(asn(NO_EXPORT), 0xFFFF);
        assert_eq!(asn(NO_ADVERTISE), 0xFFFF);
    }

    #[test]
    fn test_community_value() {
        assert_eq!(value(0x00010064), 100);
        assert_eq!(value(0xFDE900C8), 200);
        assert_eq!(value(NO_EXPORT), 0xFF01);
        assert_eq!(value(NO_ADVERTISE), 0xFF02);
    }

    #[test]
    fn test_community_roundtrip() {
        let test_cases = [(1, 100), (65001, 200), (0, 1), (65535, 65535)];
        for (test_asn, test_value) in test_cases {
            let community = from_asn_value(test_asn, test_value);
            assert_eq!(asn(community), test_asn);
            assert_eq!(value(community), test_value);
        }
    }
}
