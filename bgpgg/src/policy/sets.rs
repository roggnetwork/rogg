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

use crate::bgp::msg_update_types::LargeCommunity;
use crate::net::IpNetwork;
use conf::bgp::{DefinedSetsConfig, PrefixMatchConfig};
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

#[cfg(test)]
use conf::bgp::{AsPathSetConfig, CommunitySetConfig, NeighborSetConfig, PrefixSetConfig};

/// Type of defined set
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefinedSetType {
    PrefixSet,
    AsPathSet,
    CommunitySet,
    ExtCommunitySet,
    LargeCommunitySet,
    NeighborSet,
}

impl DefinedSetType {
    /// Parse set type from string (kebab-case)
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "prefix-set" => Ok(DefinedSetType::PrefixSet),
            "as-path-set" => Ok(DefinedSetType::AsPathSet),
            "community-set" => Ok(DefinedSetType::CommunitySet),
            "ext-community-set" => Ok(DefinedSetType::ExtCommunitySet),
            "large-community-set" => Ok(DefinedSetType::LargeCommunitySet),
            "neighbor-set" => Ok(DefinedSetType::NeighborSet),
            _ => Err(format!("invalid set type: {}", s)),
        }
    }

    /// Convert set type to string (kebab-case)
    pub fn as_str(&self) -> &'static str {
        match self {
            DefinedSetType::PrefixSet => "prefix-set",
            DefinedSetType::AsPathSet => "as-path-set",
            DefinedSetType::CommunitySet => "community-set",
            DefinedSetType::ExtCommunitySet => "ext-community-set",
            DefinedSetType::LargeCommunitySet => "large-community-set",
            DefinedSetType::NeighborSet => "neighbor-set",
        }
    }
}

/// Runtime representation of defined sets with compiled regexes and parsed values
#[derive(Debug, Clone, Default)]
pub struct DefinedSets {
    pub prefix_sets: HashMap<String, PrefixSet>,
    pub neighbor_sets: HashMap<String, NeighborSet>,
    pub as_path_sets: HashMap<String, AsPathSet>,
    pub community_sets: HashMap<String, CommunitySet>,
    pub ext_community_sets: HashMap<String, ExtCommunitySet>,
    pub large_community_sets: HashMap<String, LargeCommunitySet>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PrefixSet {
    pub name: String,
    pub prefixes: Vec<PrefixMatch>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PrefixMatch {
    pub network: IpNetwork,
    pub min_len: u8,
    pub max_len: u8,
}

impl PrefixMatch {
    /// Create new PrefixMatch from config, parsing and validating the prefix and masklength range
    pub fn new(config: &PrefixMatchConfig) -> Result<Self, String> {
        // Parse the base prefix
        let network = IpNetwork::from_str(&config.prefix)
            .map_err(|e| format!("invalid prefix '{}': {}", config.prefix, e))?;

        let prefix_len = match &network {
            IpNetwork::V4(net) => net.prefix_length,
            IpNetwork::V6(net) => net.prefix_length,
        };

        let max_len = match &network {
            IpNetwork::V4(_) => 32,
            IpNetwork::V6(_) => 128,
        };

        // Parse masklength range
        let (min_len, max_len) = if let Some(ref range_str) = config.masklength_range {
            parse_masklength_range(range_str, prefix_len, max_len)?
        } else {
            // No range specified -> exact match
            (prefix_len, prefix_len)
        };

        Ok(PrefixMatch {
            network,
            min_len,
            max_len,
        })
    }

    /// Check if a prefix matches this prefix match (within network and length range)
    pub fn contains(&self, prefix: &IpNetwork) -> bool {
        // Check if prefix length is in range
        let prefix_len = prefix.prefix_len();
        if prefix_len < self.min_len || prefix_len > self.max_len {
            return false;
        }

        // Check if prefix is within network
        self.network.contains(prefix)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NeighborSet {
    pub name: String,
    pub neighbors: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct AsPathSet {
    pub name: String,
    pub patterns: Vec<Regex>,
}

// Manual PartialEq for AsPathSet since Regex doesn't implement PartialEq
impl PartialEq for AsPathSet {
    fn eq(&self, other: &Self) -> bool {
        if self.name != other.name || self.patterns.len() != other.patterns.len() {
            return false;
        }
        // Compare regex pattern strings
        self.patterns
            .iter()
            .zip(other.patterns.iter())
            .all(|(a, b)| a.as_str() == b.as_str())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommunitySet {
    pub name: String,
    pub communities: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExtCommunitySet {
    pub name: String,
    pub ext_communities: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LargeCommunitySet {
    pub name: String,
    pub large_communities: Vec<LargeCommunity>,
}

impl DefinedSets {
    /// Create new DefinedSets from config, validating and compiling all sets
    pub fn new(config: &DefinedSetsConfig) -> Result<Self, String> {
        let mut sets = DefinedSets::default();

        // Build prefix sets
        for prefix_set in &config.prefix_sets {
            let mut prefixes = Vec::new();
            for pm in &prefix_set.prefixes {
                prefixes.push(PrefixMatch::new(pm)?);
            }
            sets.prefix_sets.insert(
                prefix_set.name.clone(),
                PrefixSet {
                    name: prefix_set.name.clone(),
                    prefixes,
                },
            );
        }

        // Build neighbor sets
        for neighbor_set in &config.neighbor_sets {
            let mut neighbors = Vec::new();
            for neighbor_str in &neighbor_set.neighbors {
                let addr = IpAddr::from_str(neighbor_str).map_err(|e| {
                    format!(
                        "neighbor-set '{}': invalid IP '{}': {}",
                        neighbor_set.name, neighbor_str, e
                    )
                })?;
                neighbors.push(addr);
            }
            sets.neighbor_sets.insert(
                neighbor_set.name.clone(),
                NeighborSet {
                    name: neighbor_set.name.clone(),
                    neighbors,
                },
            );
        }

        // Build AS path sets
        for as_path_set in &config.as_path_sets {
            let mut patterns = Vec::new();
            for pattern_str in &as_path_set.patterns {
                let regex = Regex::new(pattern_str).map_err(|e| {
                    format!(
                        "as-path-set '{}': invalid regex '{}': {}",
                        as_path_set.name, pattern_str, e
                    )
                })?;
                patterns.push(regex);
            }
            sets.as_path_sets.insert(
                as_path_set.name.clone(),
                AsPathSet {
                    name: as_path_set.name.clone(),
                    patterns,
                },
            );
        }

        // Build community sets
        for community_set in &config.community_sets {
            let mut communities = Vec::new();
            for community_str in &community_set.communities {
                let value = parse_community(community_str).map_err(|e| {
                    format!(
                        "community-set '{}': invalid community '{}': {}",
                        community_set.name, community_str, e
                    )
                })?;
                communities.push(value);
            }
            sets.community_sets.insert(
                community_set.name.clone(),
                CommunitySet {
                    name: community_set.name.clone(),
                    communities,
                },
            );
        }

        // Build extended community sets
        for ext_community_set in &config.ext_community_sets {
            let mut ext_communities = Vec::new();
            for ext_community_str in &ext_community_set.ext_communities {
                let value = crate::bgp::ext_community::parse_extended_community(ext_community_str)
                    .map_err(|e| {
                        format!(
                            "ext-community-set '{}': invalid extended community '{}': {}",
                            ext_community_set.name, ext_community_str, e
                        )
                    })?;
                ext_communities.push(value);
            }
            sets.ext_community_sets.insert(
                ext_community_set.name.clone(),
                ExtCommunitySet {
                    name: ext_community_set.name.clone(),
                    ext_communities,
                },
            );
        }

        // Build large community sets
        for large_community_set in &config.large_community_sets {
            let mut large_communities = Vec::new();
            for large_community_str in &large_community_set.large_communities {
                let value = crate::bgp::large_community::parse_large_community(large_community_str)
                    .map_err(|e| {
                        format!(
                            "large-community-set '{}': invalid large community '{}': {}",
                            large_community_set.name, large_community_str, e
                        )
                    })?;
                large_communities.push(value);
            }
            sets.large_community_sets.insert(
                large_community_set.name.clone(),
                LargeCommunitySet {
                    name: large_community_set.name.clone(),
                    large_communities,
                },
            );
        }

        Ok(sets)
    }

    /// Check if a set with given name exists for the specified type
    pub fn contains(&self, set_type: DefinedSetType, name: &str) -> bool {
        match set_type {
            DefinedSetType::PrefixSet => self.prefix_sets.contains_key(name),
            DefinedSetType::AsPathSet => self.as_path_sets.contains_key(name),
            DefinedSetType::CommunitySet => self.community_sets.contains_key(name),
            DefinedSetType::ExtCommunitySet => self.ext_community_sets.contains_key(name),
            DefinedSetType::LargeCommunitySet => self.large_community_sets.contains_key(name),
            DefinedSetType::NeighborSet => self.neighbor_sets.contains_key(name),
        }
    }

    /// Remove a set with given name for the specified type, returns true if removed
    pub fn remove(&mut self, set_type: DefinedSetType, name: &str) -> bool {
        match set_type {
            DefinedSetType::PrefixSet => self.prefix_sets.remove(name).is_some(),
            DefinedSetType::AsPathSet => self.as_path_sets.remove(name).is_some(),
            DefinedSetType::CommunitySet => self.community_sets.remove(name).is_some(),
            DefinedSetType::ExtCommunitySet => self.ext_community_sets.remove(name).is_some(),
            DefinedSetType::LargeCommunitySet => self.large_community_sets.remove(name).is_some(),
            DefinedSetType::NeighborSet => self.neighbor_sets.remove(name).is_some(),
        }
    }

    /// Clear all sets of the specified type
    pub fn clear(&mut self, set_type: DefinedSetType) {
        match set_type {
            DefinedSetType::PrefixSet => self.prefix_sets.clear(),
            DefinedSetType::AsPathSet => self.as_path_sets.clear(),
            DefinedSetType::CommunitySet => self.community_sets.clear(),
            DefinedSetType::ExtCommunitySet => self.ext_community_sets.clear(),
            DefinedSetType::LargeCommunitySet => self.large_community_sets.clear(),
            DefinedSetType::NeighborSet => self.neighbor_sets.clear(),
        }
    }
}

/// Parse community string in format "65000:100" or decimal
fn parse_community(s: &str) -> Result<u32, String> {
    // Try decimal format first
    if let Ok(val) = s.parse::<u32>() {
        return Ok(val);
    }

    // Try "65000:100" format
    if let Some((high, low)) = s.split_once(':') {
        let high_val = high
            .parse::<u16>()
            .map_err(|_| format!("invalid high part '{}'", high))?;
        let low_val = low
            .parse::<u16>()
            .map_err(|_| format!("invalid low part '{}'", low))?;
        return Ok((high_val as u32) << 16 | (low_val as u32));
    }

    Err(format!(
        "invalid community format '{}' (expected '65000:100' or decimal)",
        s
    ))
}

/// Parse masklength range string
/// Formats:
/// - "exact" -> (prefix_len, prefix_len)
/// - "21..24" -> (21, 24)
/// - "..24" -> (prefix_len, 24)
/// - "21.." -> (21, max_len)
fn parse_masklength_range(s: &str, prefix_len: u8, max_len: u8) -> Result<(u8, u8), String> {
    if s == "exact" {
        return Ok((prefix_len, prefix_len));
    }

    if let Some((min_str, max_str)) = s.split_once("..") {
        let min = if min_str.is_empty() {
            prefix_len
        } else {
            min_str
                .parse::<u8>()
                .map_err(|_| format!("invalid min length '{}'", min_str))?
        };

        let max = if max_str.is_empty() {
            max_len
        } else {
            max_str
                .parse::<u8>()
                .map_err(|_| format!("invalid max length '{}'", max_str))?
        };

        if min > max {
            return Err(format!("min length {} > max length {}", min, max));
        }

        if min < prefix_len {
            return Err(format!("min length {} < prefix length {}", min, prefix_len));
        }

        if max > max_len {
            return Err(format!("max length {} > max allowed {}", max, max_len));
        }

        return Ok((min, max));
    }

    Err(format!("invalid masklength range format '{}'", s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Ipv4Net;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_community() {
        // Decimal format
        assert_eq!(parse_community("65536").unwrap(), 65536);

        // AS:NN format
        assert_eq!(parse_community("65000:100").unwrap(), (65000 << 16) | 100);

        // Invalid formats
        assert!(parse_community("invalid").is_err());
        assert!(parse_community("65000:").is_err());
        assert!(parse_community(":100").is_err());
    }

    #[test]
    fn test_parse_masklength_range_exact() {
        let (min, max) = parse_masklength_range("exact", 24, 32).unwrap();
        assert_eq!(min, 24);
        assert_eq!(max, 24);
    }

    #[test]
    fn test_parse_masklength_range_explicit() {
        let (min, max) = parse_masklength_range("16..24", 8, 32).unwrap();
        assert_eq!(min, 16);
        assert_eq!(max, 24);
    }

    #[test]
    fn test_parse_masklength_range_le() {
        let (min, max) = parse_masklength_range("..24", 16, 32).unwrap();
        assert_eq!(min, 16);
        assert_eq!(max, 24);
    }

    #[test]
    fn test_parse_masklength_range_ge() {
        let (min, max) = parse_masklength_range("16..", 8, 32).unwrap();
        assert_eq!(min, 16);
        assert_eq!(max, 32);
    }

    #[test]
    fn test_prefix_match_contains() {
        let compiled = PrefixMatch {
            network: IpNetwork::V4(Ipv4Net {
                address: Ipv4Addr::new(10, 0, 0, 0),
                prefix_length: 8,
            }),
            min_len: 16,
            max_len: 24,
        };

        // Within range
        let prefix16 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 1, 0, 0),
            prefix_length: 16,
        });
        assert!(compiled.contains(&prefix16));

        let prefix24 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 1, 1, 0),
            prefix_length: 24,
        });
        assert!(compiled.contains(&prefix24));

        // Too short
        let prefix8 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 0, 0, 0),
            prefix_length: 8,
        });
        assert!(!compiled.contains(&prefix8));

        // Too long
        let prefix32 = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(10, 1, 1, 1),
            prefix_length: 32,
        });
        assert!(!compiled.contains(&prefix32));

        // Outside network
        let outside = IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(192, 168, 0, 0),
            prefix_length: 16,
        });
        assert!(!compiled.contains(&outside));
    }

    #[test]
    fn test_compile_defined_sets() {
        let config = DefinedSetsConfig {
            prefix_sets: vec![PrefixSetConfig {
                name: "test-set".to_string(),
                prefixes: vec![PrefixMatchConfig {
                    prefix: "10.0.0.0/8".to_string(),
                    masklength_range: Some("16..24".to_string()),
                }],
            }],
            neighbor_sets: vec![NeighborSetConfig {
                name: "test-neighbors".to_string(),
                neighbors: vec!["10.0.0.1".to_string()],
            }],
            as_path_sets: vec![AsPathSetConfig {
                name: "test-as-path".to_string(),
                patterns: vec!["_65001$".to_string()],
            }],
            community_sets: vec![CommunitySetConfig {
                name: "test-community".to_string(),
                communities: vec!["65000:100".to_string()],
            }],
            ext_community_sets: vec![],
            large_community_sets: vec![],
        };

        let sets = DefinedSets::new(&config).unwrap();

        assert!(sets.prefix_sets.contains_key("test-set"));
        assert!(sets.neighbor_sets.contains_key("test-neighbors"));
        assert!(sets.as_path_sets.contains_key("test-as-path"));
        assert!(sets.community_sets.contains_key("test-community"));
    }
}
