// Copyright 2026 bgpgg Authors
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

// RFC 8092: BGP Large Communities Attribute
// Large community = 12 bytes
// Format: [Global Administrator (4 bytes)][Local Data Part 1 (4 bytes)][Local Data Part 2 (4 bytes)]

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LargeCommunity {
    pub global_admin: u32,
    pub local_data_1: u32,
    pub local_data_2: u32,
}

impl LargeCommunity {
    /// Create a large community from its three components
    /// GA:LD1:LD2 format
    pub const fn new(global_admin: u32, local_data_1: u32, local_data_2: u32) -> Self {
        LargeCommunity {
            global_admin,
            local_data_1,
            local_data_2,
        }
    }

    /// Convert to wire format (12 bytes, big-endian)
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&self.global_admin.to_be_bytes());
        buf[4..8].copy_from_slice(&self.local_data_1.to_be_bytes());
        buf[8..12].copy_from_slice(&self.local_data_2.to_be_bytes());
        buf
    }

    /// Parse from wire format (12 bytes, big-endian)
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        LargeCommunity {
            global_admin: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            local_data_1: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            local_data_2: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseLargeCommunityError {
    InvalidFormat,
    InvalidGlobalAdmin,
    InvalidLocalData1,
    InvalidLocalData2,
}

impl std::fmt::Display for ParseLargeCommunityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseLargeCommunityError::InvalidFormat => {
                write!(f, "invalid format (expected GA:LD1:LD2)")
            }
            ParseLargeCommunityError::InvalidGlobalAdmin => {
                write!(f, "invalid global administrator value")
            }
            ParseLargeCommunityError::InvalidLocalData1 => {
                write!(f, "invalid local data part 1 value")
            }
            ParseLargeCommunityError::InvalidLocalData2 => {
                write!(f, "invalid local data part 2 value")
            }
        }
    }
}

/// Parse a large community from a string
/// Format: "GA:LD1:LD2" (e.g., "65536:100:200")
pub fn parse_large_community(s: &str) -> Result<LargeCommunity, ParseLargeCommunityError> {
    let parts: Vec<&str> = s.split(':').collect();

    if parts.len() != 3 {
        return Err(ParseLargeCommunityError::InvalidFormat);
    }

    let global_admin: u32 = parts[0]
        .parse()
        .map_err(|_| ParseLargeCommunityError::InvalidGlobalAdmin)?;
    let local_data_1: u32 = parts[1]
        .parse()
        .map_err(|_| ParseLargeCommunityError::InvalidLocalData1)?;
    let local_data_2: u32 = parts[2]
        .parse()
        .map_err(|_| ParseLargeCommunityError::InvalidLocalData2)?;

    Ok(LargeCommunity::new(
        global_admin,
        local_data_1,
        local_data_2,
    ))
}

impl std::fmt::Display for LargeCommunity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.global_admin, self.local_data_1, self.local_data_2
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_construction() {
        let test_cases = [
            (65536, 100, 200),
            (0, 0, 0),
            (u32::MAX, u32::MAX, u32::MAX),
            (4200000000, 1, 2),
            (1, 4200000000, 3),
            (1, 2, 4200000000),
        ];

        for (ga, ld1, ld2) in test_cases {
            let lc = LargeCommunity::new(ga, ld1, ld2);
            assert_eq!(lc.global_admin, ga);
            assert_eq!(lc.local_data_1, ld1);
            assert_eq!(lc.local_data_2, ld2);
        }
    }

    #[test]
    fn test_roundtrip_string_parsing() {
        let test_cases = [
            "65536:100:200",
            "0:0:0",
            "4294967295:4294967295:4294967295",
            "4200000000:100:200",
            "1:2:3",
        ];

        for original in test_cases {
            let lc = parse_large_community(original).unwrap();
            let formatted = lc.to_string();
            assert_eq!(original, formatted);
        }
    }

    #[test]
    fn test_parse_errors() {
        let test_cases = [
            ("65536:100", ParseLargeCommunityError::InvalidFormat),
            ("65536:100:200:300", ParseLargeCommunityError::InvalidFormat),
            ("", ParseLargeCommunityError::InvalidFormat),
            (
                "notanumber:100:200",
                ParseLargeCommunityError::InvalidGlobalAdmin,
            ),
            (
                "65536:notanumber:200",
                ParseLargeCommunityError::InvalidLocalData1,
            ),
            (
                "65536:100:notanumber",
                ParseLargeCommunityError::InvalidLocalData2,
            ),
            (
                "4294967296:100:200",
                ParseLargeCommunityError::InvalidGlobalAdmin,
            ),
        ];

        for (input, expected_error) in test_cases {
            assert_eq!(parse_large_community(input), Err(expected_error));
        }
    }

    #[test]
    fn test_different_field_values() {
        let lc1 = LargeCommunity::new(1, 0, 0);
        let lc2 = LargeCommunity::new(0, 1, 0);
        let lc3 = LargeCommunity::new(0, 0, 1);

        assert_ne!(lc1, lc2);
        assert_ne!(lc2, lc3);
        assert_ne!(lc1, lc3);

        assert_eq!(lc1.global_admin, 1);
        assert_eq!(lc2.local_data_1, 1);
        assert_eq!(lc3.local_data_2, 1);
    }
}
