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

//! HashMap + PrefixTrie kept in sync. HashMap for hot-path lookups,
//! trie for subtree/covering queries.

use super::trie::{Prefix, PrefixTrie};
use std::collections::hash_map;
use std::collections::HashMap;
use std::hash::Hash;

/// HashMap + PrefixTrie kept in sync. HashMap for hot-path lookups,
/// trie for subtree/covering queries.
pub struct PrefixMap<K: Prefix + Eq + Hash, V> {
    map: HashMap<K, V>,
    trie: PrefixTrie<K, ()>,
}

impl<K: Prefix + Eq + Hash, V> PrefixMap<K, V> {
    pub fn new() -> Self {
        PrefixMap {
            map: HashMap::new(),
            trie: PrefixTrie::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    pub fn values(&self) -> hash_map::Values<'_, K, V> {
        self.map.values()
    }

    pub fn values_mut(&mut self) -> hash_map::ValuesMut<'_, K, V> {
        self.map.values_mut()
    }

    pub fn keys(&self) -> hash_map::Keys<'_, K, V> {
        self.map.keys()
    }

    pub fn iter(&self) -> hash_map::Iter<'_, K, V> {
        self.map.iter()
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.trie.insert(key, ());
        self.map.insert(key, value)
    }

    /// Get or insert a value, keeping the trie in sync for new keys.
    pub fn get_or_insert(&mut self, key: K, value: V) -> &mut V {
        match self.map.entry(key) {
            hash_map::Entry::Occupied(entry) => entry.into_mut(),
            hash_map::Entry::Vacant(entry) => {
                self.trie.insert(key, ());
                entry.insert(value)
            }
        }
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let val = self.map.remove(key)?;
        self.trie.remove(key);
        Some(val)
    }

    pub fn retain(&mut self, mut f: impl FnMut(&K, &mut V) -> bool) {
        let mut to_remove = Vec::new();
        for (key, value) in self.map.iter_mut() {
            if !f(key, value) {
                to_remove.push(*key);
            }
        }
        for key in to_remove {
            self.map.remove(&key);
            self.trie.remove(&key);
        }
    }

    /// All keys whose prefix is a subnet of (or equal to) `key`.
    pub fn subtree(&self, key: &K) -> Vec<&K> {
        self.trie.subtree(key).into_iter().map(|(k, _)| k).collect()
    }

    /// All keys whose prefix contains (is a supernet of, or equal to) `key`.
    pub fn covering(&self, key: &K) -> Vec<&K> {
        self.trie
            .covering(key)
            .into_iter()
            .map(|(k, _)| k)
            .collect()
    }
}

impl<K: Prefix + Eq + Hash, V> Default for PrefixMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Ipv4Net;
    use std::net::Ipv4Addr;

    fn ipv4net(a: u8, b: u8, c: u8, d: u8, len: u8) -> Ipv4Net {
        Ipv4Net {
            address: Ipv4Addr::new(a, b, c, d),
            prefix_length: len,
        }
    }

    #[test]
    fn test_insert_get_remove() {
        let mut table: PrefixMap<Ipv4Net, i32> = PrefixMap::new();
        let p8 = ipv4net(10, 0, 0, 0, 8);
        let p16 = ipv4net(10, 1, 0, 0, 16);

        assert!(table.is_empty());

        // Insert returns None for new keys
        assert_eq!(table.insert(p8, 8), None);
        assert_eq!(table.insert(p16, 16), None);
        assert_eq!(table.len(), 2);

        // Lookups
        assert_eq!(table.get(&p8), Some(&8));
        assert_eq!(table.get(&p16), Some(&16));
        assert!(table.contains_key(&p8));
        assert!(!table.contains_key(&ipv4net(192, 168, 0, 0, 16)));

        // Overwrite returns old value
        assert_eq!(table.insert(p8, 80), Some(8));
        assert_eq!(table.get(&p8), Some(&80));
        assert_eq!(table.len(), 2);

        // get_mut
        *table.get_mut(&p8).unwrap() = 800;
        assert_eq!(table.get(&p8), Some(&800));

        // Remove
        assert_eq!(table.remove(&p8), Some(800));
        assert_eq!(table.len(), 1);
        assert!(!table.contains_key(&p8));

        // Remove nonexistent
        assert_eq!(table.remove(&p8), None);
    }

    #[test]
    fn test_subtree_covering() {
        let mut table: PrefixMap<Ipv4Net, i32> = PrefixMap::new();
        table.insert(ipv4net(10, 0, 0, 0, 8), 8);
        table.insert(ipv4net(10, 1, 0, 0, 16), 16);
        table.insert(ipv4net(10, 1, 2, 0, 24), 24);
        table.insert(ipv4net(192, 168, 0, 0, 16), 99);

        // Subtree: all subnets of /8
        let subtree = table.subtree(&ipv4net(10, 0, 0, 0, 8));
        assert_eq!(subtree.len(), 3);

        // Covering: all supernets of /24
        let covering = table.covering(&ipv4net(10, 1, 2, 0, 24));
        assert_eq!(covering.len(), 3);

        // Subtree after remove stays in sync
        table.remove(&ipv4net(10, 1, 0, 0, 16));
        let subtree = table.subtree(&ipv4net(10, 0, 0, 0, 8));
        assert_eq!(subtree.len(), 2);
    }

    #[test]
    fn test_retain() {
        let mut table: PrefixMap<Ipv4Net, i32> = PrefixMap::new();
        table.insert(ipv4net(10, 0, 0, 0, 8), 1);
        table.insert(ipv4net(10, 1, 0, 0, 16), 2);
        table.insert(ipv4net(192, 168, 0, 0, 16), 3);

        // Keep only values > 1
        table.retain(|_, v| *v > 1);
        assert_eq!(table.len(), 2);
        assert!(!table.contains_key(&ipv4net(10, 0, 0, 0, 8)));
        assert!(table.contains_key(&ipv4net(10, 1, 0, 0, 16)));

        // Trie stays in sync -- subtree of /8 should only find /16
        let subtree = table.subtree(&ipv4net(10, 0, 0, 0, 8));
        assert_eq!(subtree.len(), 1);
    }

    #[test]
    fn test_get_or_insert() {
        let mut table: PrefixMap<Ipv4Net, i32> = PrefixMap::new();
        let prefix = ipv4net(10, 0, 0, 0, 8);

        // Inserts when missing
        let val = table.get_or_insert(prefix, 42);
        assert_eq!(*val, 42);
        assert_eq!(table.len(), 1);

        // Returns existing, ignores new value
        let val = table.get_or_insert(prefix, 99);
        assert_eq!(*val, 42);
        assert_eq!(table.len(), 1);

        // Trie in sync
        assert_eq!(table.subtree(&prefix).len(), 1);
    }

    #[test]
    fn test_iterators() {
        let mut table: PrefixMap<Ipv4Net, i32> = PrefixMap::new();
        table.insert(ipv4net(10, 0, 0, 0, 8), 1);
        table.insert(ipv4net(10, 1, 0, 0, 16), 2);

        let mut values: Vec<i32> = table.values().copied().collect();
        values.sort();
        assert_eq!(values, vec![1, 2]);

        assert_eq!(table.keys().count(), 2);

        let mut iter_values: Vec<i32> = table.iter().map(|(_, v)| *v).collect();
        iter_values.sort();
        assert_eq!(iter_values, vec![1, 2]);
    }
}
