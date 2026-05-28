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

//! VRP (Validated ROA Payload) storage and route origin validation per RFC 6811.

use crate::net::{IpNetwork, Ipv4Net, Ipv6Net};
use crate::table::{Prefix, PrefixTrie};
use conf::bgp::RpkiValidationConfig;

/// A Validated ROA Payload entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Vrp {
    pub prefix: IpNetwork,
    pub max_length: u8,
    pub origin_as: u32,
}

impl Vrp {
    /// Returns true if this VRP covers a route with the given prefix length and origin AS.
    fn covers(&self, route_prefix_len: u8, origin_as: u32) -> bool {
        route_prefix_len <= self.max_length && self.origin_as != 0 && origin_as == self.origin_as
    }
}

/// RPKI route origin validation result per RFC 6811 Section 2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RpkiValidation {
    Valid,
    Invalid,
    #[default]
    NotFound,
}

impl RpkiValidation {
    /// RFC 8097 wire values for origin validation state extended community
    pub const VALID: u8 = 0;
    pub const NOT_FOUND: u8 = 1;
    pub const INVALID: u8 = 2;

    pub const fn to_u8(self) -> u8 {
        match self {
            RpkiValidation::Valid => Self::VALID,
            RpkiValidation::NotFound => Self::NOT_FOUND,
            RpkiValidation::Invalid => Self::INVALID,
        }
    }
}

impl From<RpkiValidationConfig> for RpkiValidation {
    fn from(config: RpkiValidationConfig) -> Self {
        match config {
            RpkiValidationConfig::Valid => RpkiValidation::Valid,
            RpkiValidationConfig::Invalid => RpkiValidation::Invalid,
            RpkiValidationConfig::NotFound => RpkiValidation::NotFound,
        }
    }
}

/// Convert RpkiValidation to RpkiValidationConfig.
/// Free function because orphan rules prevent From impl (both types are foreign to each other).
pub fn rpki_validation_to_config(state: RpkiValidation) -> RpkiValidationConfig {
    match state {
        RpkiValidation::Valid => RpkiValidationConfig::Valid,
        RpkiValidation::Invalid => RpkiValidationConfig::Invalid,
        RpkiValidation::NotFound => RpkiValidationConfig::NotFound,
    }
}

/// Table of VRPs indexed by prefix for efficient covering-prefix lookups.
pub struct VrpTable {
    ipv4: PrefixTrie<Ipv4Net, Vec<Vrp>>,
    ipv6: PrefixTrie<Ipv6Net, Vec<Vrp>>,
}

impl VrpTable {
    pub fn new() -> Self {
        VrpTable {
            ipv4: PrefixTrie::new(),
            ipv6: PrefixTrie::new(),
        }
    }

    /// Add VRPs to the table, deduplicating entries.
    pub fn add(&mut self, vrps: &[Vrp]) {
        for vrp in vrps {
            match vrp.prefix {
                IpNetwork::V4(net) => add_entry(&mut self.ipv4, net, vrp.clone()),
                IpNetwork::V6(net) => add_entry(&mut self.ipv6, net, vrp.clone()),
            }
        }
    }

    /// Remove VRPs from the table. Removes trie nodes when their entry list becomes empty.
    pub fn remove(&mut self, vrps: &[Vrp]) {
        for vrp in vrps {
            match vrp.prefix {
                IpNetwork::V4(net) => remove_entry(&mut self.ipv4, &net, vrp),
                IpNetwork::V6(net) => remove_entry(&mut self.ipv6, &net, vrp),
            }
        }
    }

    /// Validate a route announcement per RFC 6811 Section 2.
    ///
    /// Returns Valid if any covering VRP matches the prefix length and origin AS,
    /// Invalid if covering VRPs exist but none match, or NotFound if no VRPs cover
    /// the prefix.
    pub fn validate(&self, prefix: IpNetwork, origin_as: u32) -> RpkiValidation {
        // Routes with AS 0 (AS_SET, confederation) cannot be validated.
        if origin_as == 0 {
            return RpkiValidation::NotFound;
        }

        let covering = self.covering_vrps(prefix);
        if covering.is_empty() {
            return RpkiValidation::NotFound;
        }

        let route_prefix_len = prefix.prefix_len();
        let matched = covering
            .iter()
            .any(|vrp| vrp.covers(route_prefix_len, origin_as));

        if matched {
            RpkiValidation::Valid
        } else {
            RpkiValidation::Invalid
        }
    }

    pub fn covering_vrps(&self, prefix: IpNetwork) -> Vec<Vrp> {
        let mut result = Vec::new();
        match prefix {
            IpNetwork::V4(net) => {
                for (_key, vrps) in self.ipv4.covering(&net) {
                    result.extend_from_slice(vrps);
                }
            }
            IpNetwork::V6(net) => {
                for (_key, vrps) in self.ipv6.covering(&net) {
                    result.extend_from_slice(vrps);
                }
            }
        }
        result
    }

    /// Total number of prefix entries (trie nodes with values) across both AFIs.
    pub fn len(&self) -> usize {
        self.ipv4.len() + self.ipv6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }
}

impl Default for VrpTable {
    fn default() -> Self {
        Self::new()
    }
}

fn add_entry<K: Prefix>(trie: &mut PrefixTrie<K, Vec<Vrp>>, key: K, vrp: Vrp) {
    if let Some(vrps) = trie.get_mut(&key) {
        if !vrps.contains(&vrp) {
            vrps.push(vrp);
        }
    } else {
        trie.insert(key, vec![vrp]);
    }
}

fn remove_entry<K: Prefix>(trie: &mut PrefixTrie<K, Vec<Vrp>>, key: &K, vrp: &Vrp) {
    if let Some(vrps) = trie.get_mut(key) {
        vrps.retain(|existing| existing != vrp);
        if vrps.is_empty() {
            trie.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> IpNetwork {
        IpNetwork::V4(Ipv4Net {
            address: Ipv4Addr::new(a, b, c, d),
            prefix_length: len,
        })
    }

    fn v6(addr: u128, len: u8) -> IpNetwork {
        IpNetwork::V6(Ipv6Net {
            address: Ipv6Addr::from(addr),
            prefix_length: len,
        })
    }

    fn vrp(prefix: IpNetwork, max_length: u8, origin_as: u32) -> Vrp {
        Vrp {
            prefix,
            max_length,
            origin_as,
        }
    }

    #[test]
    fn test_vrp_covers() {
        let cases = [
            (
                "exact prefix len",
                vrp(v4(10, 0, 0, 0, 8), 24, 65001),
                8,
                65001,
                true,
            ),
            (
                "less than max_length",
                vrp(v4(10, 0, 0, 0, 8), 24, 65001),
                16,
                65001,
                true,
            ),
            (
                "equal to max_length",
                vrp(v4(10, 0, 0, 0, 8), 24, 65001),
                24,
                65001,
                true,
            ),
            (
                "beyond max_length",
                vrp(v4(10, 0, 0, 0, 8), 24, 65001),
                25,
                65001,
                false,
            ),
            (
                "wrong origin AS",
                vrp(v4(10, 0, 0, 0, 8), 24, 65001),
                16,
                65002,
                false,
            ),
            (
                "VRP origin AS 0",
                vrp(v4(10, 0, 0, 0, 8), 24, 0),
                16,
                65001,
                false,
            ),
        ];

        for (name, entry, route_len, origin_as, expected) in cases {
            assert_eq!(entry.covers(route_len, origin_as), expected, "{name}");
        }
    }

    #[test]
    fn test_basic_validation_states() {
        let mut table = VrpTable::new();
        let v6_addr = u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        table.add(&[
            vrp(v4(10, 0, 0, 0, 8), 24, 65001),
            vrp(v6(v6_addr, 32), 48, 65001),
        ]);

        let cases = [
            (
                "v4 valid - exact prefix match",
                v4(10, 0, 0, 0, 8),
                65001,
                RpkiValidation::Valid,
            ),
            (
                "v4 valid - more specific within max_length",
                v4(10, 1, 0, 0, 24),
                65001,
                RpkiValidation::Valid,
            ),
            (
                "v4 invalid - wrong origin AS",
                v4(10, 0, 0, 0, 8),
                65002,
                RpkiValidation::Invalid,
            ),
            (
                "v4 not found - no covering VRP",
                v4(192, 168, 0, 0, 16),
                65001,
                RpkiValidation::NotFound,
            ),
            (
                "v6 valid - within max_length",
                v6(
                    u128::from(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0)),
                    48,
                ),
                65001,
                RpkiValidation::Valid,
            ),
            (
                "v6 invalid - wrong AS",
                v6(v6_addr, 32),
                65002,
                RpkiValidation::Invalid,
            ),
            (
                "v6 not found - different prefix",
                v6(
                    u128::from(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 0)),
                    32,
                ),
                65001,
                RpkiValidation::NotFound,
            ),
        ];
        for (name, prefix, origin_as, expected) in cases {
            assert_eq!(table.validate(prefix, origin_as), expected, "{name}");
        }
    }

    #[test]
    fn test_asn_zero_vrp() {
        let mut table = VrpTable::new();
        table.add(&[vrp(v4(10, 0, 0, 0, 8), 24, 0)]);

        assert_eq!(
            table.validate(v4(10, 1, 0, 0, 16), 65001),
            RpkiValidation::Invalid,
            "ASN 0 VRP covers but never matches"
        );
    }

    #[test]
    fn test_origin_as_zero() {
        let mut table = VrpTable::new();
        table.add(&[vrp(v4(10, 0, 0, 0, 8), 24, 65001)]);

        assert_eq!(
            table.validate(v4(10, 0, 0, 0, 8), 0),
            RpkiValidation::NotFound,
            "origin AS 0 is always NotFound"
        );
    }

    #[test]
    fn test_multiple_covering_vrps() {
        let mut table = VrpTable::new();
        // Same prefix, different max_lengths: 65001 allowed up to /24, 65002 only up to /16
        table.add(&[
            vrp(v4(10, 0, 0, 0, 8), 24, 65001),
            vrp(v4(10, 0, 0, 0, 8), 16, 65002),
        ]);

        let cases = [
            (
                "any AS match wins",
                v4(10, 1, 0, 0, 16),
                65002,
                RpkiValidation::Valid,
            ),
            (
                "/20 within 65001 max_length",
                v4(10, 1, 0, 0, 20),
                65001,
                RpkiValidation::Valid,
            ),
            (
                "/20 exceeds 65002 max_length",
                v4(10, 1, 0, 0, 20),
                65002,
                RpkiValidation::Invalid,
            ),
        ];
        for (name, prefix, origin_as, expected) in cases {
            assert_eq!(table.validate(prefix, origin_as), expected, "{name}");
        }
    }

    #[test]
    fn test_add_remove() {
        let mut table = VrpTable::new();
        let vrp1 = vrp(v4(10, 0, 0, 0, 8), 24, 65001);
        let vrp2 = vrp(v4(10, 0, 0, 0, 8), 24, 65002);

        table.add(&[vrp1.clone(), vrp2.clone()]);
        assert_eq!(
            table.validate(v4(10, 1, 0, 0, 16), 65001),
            RpkiValidation::Valid
        );
        assert_eq!(
            table.validate(v4(10, 1, 0, 0, 16), 65002),
            RpkiValidation::Valid
        );

        table.remove(&[vrp1]);
        assert_eq!(
            table.validate(v4(10, 1, 0, 0, 16), 65001),
            RpkiValidation::Invalid
        );
        assert_eq!(
            table.validate(v4(10, 1, 0, 0, 16), 65002),
            RpkiValidation::Valid
        );

        table.remove(&[vrp2]);
        assert_eq!(
            table.validate(v4(10, 1, 0, 0, 16), 65001),
            RpkiValidation::NotFound
        );
        assert!(table.is_empty());
    }

    #[test]
    fn test_duplicate_add() {
        let mut table = VrpTable::new();
        let vrp1 = vrp(v4(10, 0, 0, 0, 8), 24, 65001);

        table.add(&[vrp1.clone(), vrp1.clone()]);
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.validate(v4(10, 0, 0, 0, 8), 65001),
            RpkiValidation::Valid
        );

        table.add(&[vrp1]);
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.validate(v4(10, 0, 0, 0, 8), 65001),
            RpkiValidation::Valid
        );
    }

    #[test]
    fn test_covering_vrps() {
        let mut table = VrpTable::new();
        table.add(&[
            vrp(v4(10, 0, 0, 0, 8), 24, 65001),
            vrp(v4(10, 0, 0, 0, 8), 16, 65002),
            vrp(v4(10, 1, 0, 0, 16), 24, 65003),
        ]);

        let covering = table.covering_vrps(v4(10, 1, 2, 0, 24));
        assert_eq!(covering.len(), 3);

        let covering = table.covering_vrps(v4(10, 0, 0, 0, 12));
        assert_eq!(covering.len(), 2);
        for vrp in &covering {
            assert_eq!(vrp.prefix, v4(10, 0, 0, 0, 8));
        }
    }

    #[test]
    fn test_hierarchical_covering() {
        let mut table = VrpTable::new();
        // /8 allows AS 65001 up to /16, /16 allows AS 65002 up to /24
        table.add(&[
            vrp(v4(10, 0, 0, 0, 8), 16, 65001),
            vrp(v4(10, 1, 0, 0, 16), 24, 65002),
        ]);

        let cases = [
            (
                "matches /8 VRP",
                v4(10, 2, 0, 0, 16),
                65001,
                RpkiValidation::Valid,
            ),
            (
                "matches /16 VRP",
                v4(10, 1, 1, 0, 24),
                65002,
                RpkiValidation::Valid,
            ),
            (
                "/24 covered by both, wrong AS",
                v4(10, 1, 1, 0, 24),
                65003,
                RpkiValidation::Invalid,
            ),
            (
                "beyond /8 max_length, only /16 covers",
                v4(10, 1, 1, 0, 24),
                65001,
                RpkiValidation::Invalid,
            ),
        ];
        for (name, prefix, origin_as, expected) in cases {
            assert_eq!(table.validate(prefix, origin_as), expected, "{name}");
        }
    }

    #[test]
    fn test_remove_nonexistent() {
        let mut table = VrpTable::new();
        table.add(&[vrp(v4(10, 0, 0, 0, 8), 24, 65001)]);

        // Remove a VRP that doesn't exist — should be a no-op
        table.remove(&[vrp(v4(10, 0, 0, 0, 8), 24, 65002)]);
        assert_eq!(table.len(), 1);

        // Remove from a prefix that doesn't exist
        table.remove(&[vrp(v4(192, 168, 0, 0, 16), 24, 65001)]);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_empty_table() {
        let table = VrpTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert_eq!(
            table.validate(v4(10, 0, 0, 0, 8), 65001),
            RpkiValidation::NotFound
        );
    }

    #[test]
    fn test_rpki_validation_to_u8() {
        assert_eq!(RpkiValidation::Valid.to_u8(), 0);
        assert_eq!(RpkiValidation::NotFound.to_u8(), 1);
        assert_eq!(RpkiValidation::Invalid.to_u8(), 2);
    }
}
