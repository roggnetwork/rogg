// Copyright 2026 rogg Authors
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

//! Per-family route tables shared by the adj-ribs. One table per address
//! family, keyed by the family's native key type. This is the single place
//! that dispatches a RouteKey to its family table.

use crate::bgp::bgpls_nlri::LsNlri;
use crate::bgp::multiprotocol::{Afi, AfiSafi, Safi};
use crate::net::{IpNetwork, Ipv4Net, Ipv6Net};
use crate::rib::types::RouteKey;
use std::collections::HashMap;

pub(crate) struct FamilyTables<V> {
    ipv4_unicast: HashMap<Ipv4Net, V>,
    ipv6_unicast: HashMap<Ipv6Net, V>,
    link_state: HashMap<LsNlri, V>,
}

impl<V> FamilyTables<V> {
    pub fn new() -> Self {
        Self {
            ipv4_unicast: HashMap::new(),
            ipv6_unicast: HashMap::new(),
            link_state: HashMap::new(),
        }
    }

    pub fn get(&self, key: &RouteKey) -> Option<&V> {
        match key {
            RouteKey::Prefix(IpNetwork::V4(net)) => self.ipv4_unicast.get(net),
            RouteKey::Prefix(IpNetwork::V6(net)) => self.ipv6_unicast.get(net),
            RouteKey::LinkState(nlri) => self.link_state.get(nlri),
        }
    }

    pub fn get_mut(&mut self, key: &RouteKey) -> Option<&mut V> {
        match key {
            RouteKey::Prefix(IpNetwork::V4(net)) => self.ipv4_unicast.get_mut(net),
            RouteKey::Prefix(IpNetwork::V6(net)) => self.ipv6_unicast.get_mut(net),
            RouteKey::LinkState(nlri) => self.link_state.get_mut(nlri),
        }
    }

    pub fn get_or_insert_with(&mut self, key: &RouteKey, default: impl FnOnce() -> V) -> &mut V {
        match key {
            RouteKey::Prefix(IpNetwork::V4(net)) => {
                self.ipv4_unicast.entry(*net).or_insert_with(default)
            }
            RouteKey::Prefix(IpNetwork::V6(net)) => {
                self.ipv6_unicast.entry(*net).or_insert_with(default)
            }
            RouteKey::LinkState(nlri) => self
                .link_state
                .entry((**nlri).clone())
                .or_insert_with(default),
        }
    }

    pub fn remove(&mut self, key: &RouteKey) -> Option<V> {
        match key {
            RouteKey::Prefix(IpNetwork::V4(net)) => self.ipv4_unicast.remove(net),
            RouteKey::Prefix(IpNetwork::V6(net)) => self.ipv6_unicast.remove(net),
            RouteKey::LinkState(nlri) => self.link_state.remove(nlri),
        }
    }

    pub fn clear(&mut self) {
        self.ipv4_unicast.clear();
        self.ipv6_unicast.clear();
        self.link_state.clear();
    }

    /// Clear one family. Returns how many entries were removed.
    pub fn clear_family(&mut self, family: AfiSafi) -> usize {
        match (family.afi, family.safi) {
            (Afi::Ipv4, Safi::Unicast) => {
                let count = self.ipv4_unicast.len();
                self.ipv4_unicast.clear();
                count
            }
            (Afi::Ipv6, Safi::Unicast) => {
                let count = self.ipv6_unicast.len();
                self.ipv6_unicast.clear();
                count
            }
            (Afi::LinkState, Safi::LinkState | Safi::LinkStateVpn) => {
                let count = self.link_state.len();
                self.link_state.clear();
                count
            }
            _ => 0,
        }
    }

    /// Clear every family under an AFI. Returns how many entries were removed.
    pub fn clear_afi(&mut self, afi: Afi) -> usize {
        match afi {
            Afi::Ipv4 => self.clear_family(AfiSafi::new(Afi::Ipv4, Safi::Unicast)),
            Afi::Ipv6 => self.clear_family(AfiSafi::new(Afi::Ipv6, Safi::Unicast)),
            Afi::LinkState => self.clear_family(AfiSafi::new(Afi::LinkState, Safi::LinkState)),
        }
    }

    /// Total entry count across all families.
    pub fn len(&self) -> usize {
        self.ipv4_unicast.len() + self.ipv6_unicast.len() + self.link_state.len()
    }

    /// Entry count per family. Zero counts included.
    pub fn family_counts(&self) -> [(AfiSafi, usize); 3] {
        [
            (
                AfiSafi::new(Afi::Ipv4, Safi::Unicast),
                self.ipv4_unicast.len(),
            ),
            (
                AfiSafi::new(Afi::Ipv6, Safi::Unicast),
                self.ipv6_unicast.len(),
            ),
            (
                AfiSafi::new(Afi::LinkState, Safi::LinkState),
                self.link_state.len(),
            ),
        ]
    }

    /// Entry count for one family.
    pub fn family_count(&self, family: &AfiSafi) -> usize {
        match (family.afi, family.safi) {
            (Afi::Ipv4, Safi::Unicast) => self.ipv4_unicast.len(),
            (Afi::Ipv6, Safi::Unicast) => self.ipv6_unicast.len(),
            (Afi::LinkState, Safi::LinkState | Safi::LinkStateVpn) => self.link_state.len(),
            _ => 0,
        }
    }

    /// Iterate one family (or all), reconstructing each entry's RouteKey.
    pub fn iter(&self, family: Option<AfiSafi>) -> impl Iterator<Item = (RouteKey, &V)> {
        let (ipv4, ipv6, link_state) = match family {
            None => (true, true, true),
            Some(af) => match (af.afi, af.safi) {
                (Afi::Ipv4, Safi::Unicast) => (true, false, false),
                (Afi::Ipv6, Safi::Unicast) => (false, true, false),
                (Afi::LinkState, Safi::LinkState | Safi::LinkStateVpn) => (false, false, true),
                _ => (false, false, false),
            },
        };
        self.ipv4_unicast
            .iter()
            .filter(move |_| ipv4)
            .map(|(net, val)| (RouteKey::Prefix(IpNetwork::V4(*net)), val))
            .chain(
                self.ipv6_unicast
                    .iter()
                    .filter(move |_| ipv6)
                    .map(|(net, val)| (RouteKey::Prefix(IpNetwork::V6(*net)), val)),
            )
            .chain(
                self.link_state
                    .iter()
                    .filter(move |_| link_state)
                    .map(|(nlri, val)| (RouteKey::LinkState(Box::new(nlri.clone())), val)),
            )
    }

    /// Drain one family, reconstructing each entry's RouteKey.
    pub fn drain_family(&mut self, family: AfiSafi) -> Vec<(RouteKey, V)> {
        match (family.afi, family.safi) {
            (Afi::Ipv4, Safi::Unicast) => self
                .ipv4_unicast
                .drain()
                .map(|(net, val)| (RouteKey::Prefix(IpNetwork::V4(net)), val))
                .collect(),
            (Afi::Ipv6, Safi::Unicast) => self
                .ipv6_unicast
                .drain()
                .map(|(net, val)| (RouteKey::Prefix(IpNetwork::V6(net)), val))
                .collect(),
            (Afi::LinkState, Safi::LinkState | Safi::LinkStateVpn) => self
                .link_state
                .drain()
                .map(|(nlri, val)| (RouteKey::LinkState(Box::new(nlri)), val))
                .collect(),
            _ => vec![],
        }
    }
}

impl<V> Default for FamilyTables<V> {
    fn default() -> Self {
        Self::new()
    }
}
