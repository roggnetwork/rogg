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

//! Patricia trie for IP prefix lookups.
//!
//! Supports subtree (more-specific) and covering (less-specific) queries.
//! Arena-allocated with implicit path compression.

use crate::net::{Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Trait for types that can be used as trie keys.
pub trait Prefix: Copy + Eq {
    fn prefix_len(&self) -> u8;
    fn bit_at(&self, pos: u8) -> bool;
    fn common_prefix_len(&self, other: &Self) -> u8;
    fn masked(&self, len: u8) -> Self;
}

impl Prefix for Ipv4Net {
    fn prefix_len(&self) -> u8 {
        self.prefix_length
    }

    fn bit_at(&self, pos: u8) -> bool {
        let bits = u32::from(self.address);
        (bits >> (31 - pos)) & 1 == 1
    }

    fn common_prefix_len(&self, other: &Self) -> u8 {
        let xor = u32::from(self.address) ^ u32::from(other.address);
        let leading = xor.leading_zeros() as u8;
        leading.min(self.prefix_length).min(other.prefix_length)
    }

    fn masked(&self, len: u8) -> Self {
        if len == 0 {
            return Ipv4Net {
                address: Ipv4Addr::new(0, 0, 0, 0),
                prefix_length: 0,
            };
        }
        let bits = u32::from(self.address);
        let mask = !0u32 << (32 - len);
        Ipv4Net {
            address: Ipv4Addr::from(bits & mask),
            prefix_length: len,
        }
    }
}

impl Prefix for Ipv6Net {
    fn prefix_len(&self) -> u8 {
        self.prefix_length
    }

    fn bit_at(&self, pos: u8) -> bool {
        let bits = u128::from(self.address);
        (bits >> (127 - pos)) & 1 == 1
    }

    fn common_prefix_len(&self, other: &Self) -> u8 {
        let xor = u128::from(self.address) ^ u128::from(other.address);
        let leading = xor.leading_zeros() as u8;
        leading.min(self.prefix_length).min(other.prefix_length)
    }

    fn masked(&self, len: u8) -> Self {
        if len == 0 {
            return Ipv6Net {
                address: Ipv6Addr::from(0u128),
                prefix_length: 0,
            };
        }
        let bits = u128::from(self.address);
        let mask = !0u128 << (128 - len);
        Ipv6Net {
            address: Ipv6Addr::from(bits & mask),
            prefix_length: len,
        }
    }
}

struct TrieNode<K: Prefix, V> {
    prefix: K,
    value: Option<V>,
    children: [Option<u32>; 2],
}

/// Binary Patricia trie for IP prefix lookups.
pub struct PrefixTrie<K: Prefix, V> {
    nodes: Vec<TrieNode<K, V>>,
    free_list: Vec<u32>,
    root: Option<u32>,
    len: usize,
}

impl<K: Prefix, V> PrefixTrie<K, V> {
    pub fn new() -> Self {
        PrefixTrie {
            nodes: Vec::new(),
            free_list: Vec::new(),
            root: None,
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Exact prefix lookup.
    #[cfg(test)]
    pub fn get(&self, key: &K) -> Option<&V> {
        let idx = self.find_exact(key)?;
        self.node(idx).value.as_ref()
    }

    /// Mutable exact prefix lookup.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let idx = self.find_exact(key)?;
        self.node_mut(idx).value.as_mut()
    }

    /// Insert or replace. Returns old value if key already existed.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let root = match self.root {
            Some(root) => root,
            None => {
                let idx = self.alloc_node(key, Some(value));
                self.root = Some(idx);
                self.len += 1;
                return None;
            }
        };

        self.insert_at(root, None, key, value)
    }

    /// Remove value for exact prefix. Returns removed value.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let root = self.root?;
        self.remove_at(root, None, key)
    }

    /// All entries whose prefix is a subnet of (or equal to) `key`.
    pub fn subtree(&self, key: &K) -> Vec<(&K, &V)> {
        let mut current = match self.root {
            Some(root) => root,
            None => return Vec::new(),
        };

        let start = loop {
            let node = self.node(current);
            let common = key.common_prefix_len(&node.prefix);

            if common < node.prefix.prefix_len() {
                // Key doesn't fully match this node. But if the key is shorter
                // than the common bits, this node is inside the key's range
                // (e.g. query /8 hits a branch at /23 -> collect from here).
                if key.prefix_len() <= common {
                    break Some(current);
                }
                break None;
            }

            if key.prefix_len() <= node.prefix.prefix_len() {
                break Some(current);
            }

            let next = key.bit_at(node.prefix.prefix_len()) as usize;
            match node.children[next] {
                Some(child) => current = child,
                None => break None,
            }
        };

        match start {
            Some(idx) => self.collect_all(idx),
            None => Vec::new(),
        }
    }

    /// All entries whose prefix contains (is a supernet of, or equal to) `key`.
    pub fn covering(&self, key: &K) -> Vec<(&K, &V)> {
        let mut results = Vec::new();
        let mut current = match self.root {
            Some(root) => root,
            None => return results,
        };

        loop {
            let node = self.node(current);
            let common = key.common_prefix_len(&node.prefix);

            if common < node.prefix.prefix_len() {
                break;
            }

            if let Some(ref value) = node.value {
                results.push((&node.prefix, value));
            }

            if node.prefix.prefix_len() == key.prefix_len() {
                break;
            }

            let next = key.bit_at(node.prefix.prefix_len()) as usize;
            match node.children[next] {
                Some(child) => current = child,
                None => break,
            }
        }

        results
    }

    /// Iterate all entries via DFS.
    #[cfg(test)]
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        match self.root {
            Some(root) => self.collect_all(root).into_iter(),
            None => Vec::new().into_iter(),
        }
    }

    fn node(&self, idx: u32) -> &TrieNode<K, V> {
        &self.nodes[idx as usize]
    }

    fn node_mut(&mut self, idx: u32) -> &mut TrieNode<K, V> {
        &mut self.nodes[idx as usize]
    }

    fn alloc_node(&mut self, prefix: K, value: Option<V>) -> u32 {
        if let Some(idx) = self.free_list.pop() {
            *self.node_mut(idx) = TrieNode {
                prefix,
                value,
                children: [None, None],
            };
            idx
        } else {
            let idx = self.nodes.len() as u32;
            self.nodes.push(TrieNode {
                prefix,
                value,
                children: [None, None],
            });
            idx
        }
    }

    fn free_node(&mut self, idx: u32) {
        self.free_list.push(idx);
    }

    fn find_exact(&self, key: &K) -> Option<u32> {
        let mut current = self.root?;
        loop {
            let node = self.node(current);
            let common = key.common_prefix_len(&node.prefix);

            // Node prefix doesn't fully match -> key not in trie
            if common < node.prefix.prefix_len() {
                return None;
            }

            // Exact match
            if node.prefix.prefix_len() == key.prefix_len() {
                return Some(current);
            }

            // Key is more specific, descend
            let next = key.bit_at(node.prefix.prefix_len());
            match node.children[next as usize] {
                Some(child) => current = child,
                None => return None,
            }
        }
    }

    fn insert_at(&mut self, node_idx: u32, parent: Option<u32>, key: K, value: V) -> Option<V> {
        let node_prefix = self.node(node_idx).prefix;
        let common = key.common_prefix_len(&node_prefix);

        // Key diverges from node -> insert a branch node at the split point
        if common < node_prefix.prefix_len() {
            self.split_node(node_idx, parent, key, value, common);
            self.len += 1;
            return None;
        }

        // Case: exact match
        if node_prefix.prefix_len() == key.prefix_len() {
            let old = self.node_mut(node_idx).value.take();
            self.node_mut(node_idx).value = Some(value);
            if old.is_none() {
                self.len += 1;
            }
            return old;
        }

        // Case: key is more specific, descend into child
        let next = key.bit_at(node_prefix.prefix_len()) as usize;
        match self.node(node_idx).children[next] {
            Some(child) => self.insert_at(child, Some(node_idx), key, value),
            None => {
                let new_idx = self.alloc_node(key, Some(value));
                self.node_mut(node_idx).children[next] = Some(new_idx);
                self.len += 1;
                None
            }
        }
    }

    fn remove_at(&mut self, node_idx: u32, parent: Option<u32>, key: &K) -> Option<V> {
        let node_prefix = self.node(node_idx).prefix;
        let common = key.common_prefix_len(&node_prefix);

        if common < node_prefix.prefix_len() {
            return None; // key not in trie
        }

        if node_prefix.prefix_len() == key.prefix_len() {
            // Found the node
            let value = self.node_mut(node_idx).value.take()?;
            self.len -= 1;
            self.try_collapse(node_idx, parent);
            return Some(value);
        }

        // Descend
        let next = key.bit_at(node_prefix.prefix_len()) as usize;
        let child = self.node(node_idx).children[next]?;
        let result = self.remove_at(child, Some(node_idx), key);

        if result.is_some() {
            self.try_collapse(node_idx, parent);
        }
        result
    }

    /// Insert a branch node above the given node where `key` diverges from it.
    fn split_node(&mut self, node_idx: u32, parent: Option<u32>, key: K, value: V, common: u8) {
        let node_prefix = self.node(node_idx).prefix;
        let branch_idx = self.alloc_node(node_prefix.masked(common), None);

        let existing_side = node_prefix.bit_at(common) as usize;
        self.node_mut(branch_idx).children[existing_side] = Some(node_idx);

        if common == key.prefix_len() {
            // Key is a supernet of the existing node (e.g. inserting /8
            // when /16 exists) -> branch node IS the key, store value in it
            self.node_mut(branch_idx).value = Some(value);
        } else {
            let new_side = key.bit_at(common) as usize;
            let new_idx = self.alloc_node(key, Some(value));
            self.node_mut(branch_idx).children[new_side] = Some(new_idx);
        }

        self.replace_child(parent, node_idx, Some(branch_idx));
    }

    /// Replace the child slot in `parent` that points to `old_child`.
    fn replace_child(&mut self, parent: Option<u32>, old_child: u32, new_child: Option<u32>) {
        match parent {
            Some(parent_idx) => {
                let parent_node = self.node_mut(parent_idx);
                if parent_node.children[0] == Some(old_child) {
                    parent_node.children[0] = new_child;
                } else {
                    parent_node.children[1] = new_child;
                }
            }
            None => {
                self.root = new_child;
            }
        }
    }

    /// Remove a valueless node with 0-1 children by collapsing it into its parent.
    fn try_collapse(&mut self, node_idx: u32, parent: Option<u32>) {
        let node = self.node(node_idx);
        if node.value.is_some() {
            return;
        }

        let child_count = node.children.iter().filter(|c| c.is_some()).count();
        match child_count {
            2 => {}
            1 => {
                let only_child = node.children[0].or(node.children[1]);
                self.replace_child(parent, node_idx, only_child);
                self.free_node(node_idx);
            }
            0 => {
                self.replace_child(parent, node_idx, None);
                self.free_node(node_idx);
            }
            _ => {}
        }
    }

    fn collect_all(&self, start: u32) -> Vec<(&K, &V)> {
        let mut results = Vec::new();
        let mut stack = vec![start];

        while let Some(idx) = stack.pop() {
            let node = self.node(idx);

            if let Some(ref value) = node.value {
                results.push((&node.prefix, value));
            }

            for child in node.children.iter().flatten() {
                stack.push(*child);
            }
        }

        results
    }
}

impl<K: Prefix, V> Default for PrefixTrie<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ipv4net(a: u8, b: u8, c: u8, d: u8, len: u8) -> Ipv4Net {
        Ipv4Net {
            address: Ipv4Addr::new(a, b, c, d),
            prefix_length: len,
        }
    }

    fn ipv6net(addr: u128, len: u8) -> Ipv6Net {
        Ipv6Net {
            address: Ipv6Addr::from(addr),
            prefix_length: len,
        }
    }

    /// Collect values from a Vec<(&K, &V)>, sorted for stable comparison.
    fn sorted_values(results: &[(&Ipv4Net, &i32)]) -> Vec<i32> {
        let mut values: Vec<i32> = results.iter().map(|(_, v)| **v).collect();
        values.sort();
        values
    }

    #[test]
    fn test_prefix_trait() {
        // bit_at: 10 = 0000_1010
        let prefix = ipv4net(10, 0, 0, 0, 8);
        let bits: Vec<bool> = (0..8).map(|i| prefix.bit_at(i)).collect();
        assert_eq!(
            bits,
            vec![false, false, false, false, true, false, true, false]
        );

        // common_prefix_len
        let cases = [
            (
                "same /8 vs /16",
                ipv4net(10, 0, 0, 0, 8),
                ipv4net(10, 1, 0, 0, 16),
                8,
            ),
            (
                "same /8 vs /24",
                ipv4net(10, 0, 0, 0, 8),
                ipv4net(10, 0, 0, 0, 24),
                8,
            ),
            (
                "10 vs 11 at /8",
                ipv4net(10, 0, 0, 0, 8),
                ipv4net(11, 0, 0, 0, 8),
                7,
            ),
        ];
        for (name, a, b, expected) in cases {
            assert_eq!(a.common_prefix_len(&b), expected, "{name}");
        }

        // masked
        let p = ipv4net(10, 1, 2, 3, 24);
        assert_eq!(p.masked(8), ipv4net(10, 0, 0, 0, 8));
        assert_eq!(p.masked(0), ipv4net(0, 0, 0, 0, 0));

        // IPv6 basic sanity
        let v6 = ipv6net(
            u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
            32,
        );
        assert!(v6.bit_at(2)); // 0x2001 = 0010_0000...
    }

    #[test]
    fn test_insert_and_get() {
        let mut trie = PrefixTrie::new();
        let p8 = ipv4net(10, 0, 0, 0, 8);
        let p16 = ipv4net(10, 1, 0, 0, 16);
        let p24 = ipv4net(10, 1, 2, 0, 24);

        // Fresh inserts return None
        assert!(trie.insert(p8, 8).is_none());
        assert!(trie.insert(p16, 16).is_none());
        assert!(trie.insert(p24, 24).is_none());
        assert_eq!(trie.len(), 3);

        // Lookups
        assert_eq!(trie.get(&p8), Some(&8));
        assert_eq!(trie.get(&p16), Some(&16));
        assert_eq!(trie.get(&p24), Some(&24));
        assert_eq!(trie.get(&ipv4net(192, 168, 0, 0, 16)), None);

        // Overwrite returns old value, len unchanged
        assert_eq!(trie.insert(p8, 80), Some(8));
        assert_eq!(trie.get(&p8), Some(&80));
        assert_eq!(trie.len(), 3);

        // get_mut
        *trie.get_mut(&p8).unwrap() = 800;
        assert_eq!(trie.get(&p8), Some(&800));

        // Divergent prefixes create branch node
        let a = ipv4net(10, 0, 0, 0, 24);
        let b = ipv4net(10, 0, 1, 0, 24);
        trie.insert(a, 1);
        trie.insert(b, 2);
        assert_eq!(trie.get(&a), Some(&1));
        assert_eq!(trie.get(&b), Some(&2));

        // Insert more-specific first, then less-specific
        let mut trie2 = PrefixTrie::new();
        trie2.insert(ipv4net(10, 1, 0, 0, 24), 24);
        trie2.insert(ipv4net(10, 0, 0, 0, 16), 16);
        assert_eq!(trie2.get(&ipv4net(10, 1, 0, 0, 24)), Some(&24));
        assert_eq!(trie2.get(&ipv4net(10, 0, 0, 0, 16)), Some(&16));
    }

    #[test]
    fn test_remove() {
        // Remove leaf
        let mut trie = PrefixTrie::new();
        trie.insert(ipv4net(10, 0, 0, 0, 8), 1);
        assert_eq!(trie.remove(&ipv4net(10, 0, 0, 0, 8)), Some(1));
        assert!(trie.is_empty());
        assert!(trie.root.is_none());

        // Remove nonexistent from empty
        assert_eq!(trie.remove(&ipv4net(10, 0, 0, 0, 8)), None);

        // Remove parent with one child -> child promoted
        let mut trie = PrefixTrie::new();
        trie.insert(ipv4net(10, 0, 0, 0, 8), 8);
        trie.insert(ipv4net(10, 1, 0, 0, 16), 16);
        assert_eq!(trie.remove(&ipv4net(10, 0, 0, 0, 8)), Some(8));
        assert_eq!(trie.get(&ipv4net(10, 1, 0, 0, 16)), Some(&16));
        assert_eq!(trie.len(), 1);

        // Remove parent with two children -> becomes branch
        let mut trie = PrefixTrie::new();
        trie.insert(ipv4net(10, 0, 0, 0, 8), 8);
        trie.insert(ipv4net(10, 0, 0, 0, 16), 1);
        trie.insert(ipv4net(10, 128, 0, 0, 16), 2);
        assert_eq!(trie.remove(&ipv4net(10, 0, 0, 0, 8)), Some(8));
        assert_eq!(trie.len(), 2);
        assert_eq!(trie.get(&ipv4net(10, 0, 0, 0, 16)), Some(&1));
        assert_eq!(trie.get(&ipv4net(10, 128, 0, 0, 16)), Some(&2));

        // Branch collapse: insert two divergent, remove one
        let mut trie = PrefixTrie::new();
        trie.insert(ipv4net(10, 0, 0, 0, 24), 1);
        trie.insert(ipv4net(10, 0, 1, 0, 24), 2);
        trie.remove(&ipv4net(10, 0, 0, 0, 24));
        assert_eq!(trie.get(&ipv4net(10, 0, 1, 0, 24)), Some(&2));
        assert_eq!(
            trie.root.map(|idx| trie.node(idx).prefix),
            Some(ipv4net(10, 0, 1, 0, 24))
        );
    }

    #[test]
    fn test_subtree() {
        let mut trie = PrefixTrie::new();
        trie.insert(ipv4net(10, 0, 0, 0, 8), 8);
        trie.insert(ipv4net(10, 1, 0, 0, 16), 16);
        trie.insert(ipv4net(10, 1, 2, 0, 24), 24);
        trie.insert(ipv4net(192, 168, 0, 0, 16), 99);

        let cases: Vec<(&str, Ipv4Net, Vec<i32>)> = vec![
            ("all under /8", ipv4net(10, 0, 0, 0, 8), vec![8, 16, 24]),
            ("self only", ipv4net(10, 1, 2, 0, 24), vec![24]),
            ("unrelated", ipv4net(192, 168, 0, 0, 16), vec![99]),
            ("no match", ipv4net(172, 16, 0, 0, 12), vec![]),
        ];
        for (name, key, expected) in cases {
            assert_eq!(sorted_values(&trie.subtree(&key)), expected, "{name}");
        }

        // Subtree through branch nodes (no value at branch)
        let mut trie2 = PrefixTrie::new();
        trie2.insert(ipv4net(10, 0, 0, 0, 24), 1);
        trie2.insert(ipv4net(10, 0, 1, 0, 24), 2);
        assert_eq!(trie2.subtree(&ipv4net(10, 0, 0, 0, 8)).len(), 2);
    }

    #[test]
    fn test_covering() {
        let mut trie = PrefixTrie::new();
        trie.insert(ipv4net(10, 0, 0, 0, 8), 8);
        trie.insert(ipv4net(10, 1, 0, 0, 16), 16);
        trie.insert(ipv4net(10, 1, 2, 0, 24), 24);
        trie.insert(ipv4net(192, 168, 0, 0, 16), 99);

        let cases: Vec<(&str, Ipv4Net, Vec<i32>)> = vec![
            (
                "all parents of /24",
                ipv4net(10, 1, 2, 0, 24),
                vec![8, 16, 24],
            ),
            ("self only", ipv4net(10, 0, 0, 0, 8), vec![8]),
            ("no match", ipv4net(172, 16, 0, 0, 12), vec![]),
        ];
        for (name, key, expected) in cases {
            assert_eq!(sorted_values(&trie.covering(&key)), expected, "{name}");
        }
    }

    #[test]
    fn test_empty_trie() {
        let trie: PrefixTrie<Ipv4Net, i32> = PrefixTrie::new();
        assert!(trie.is_empty());
        assert_eq!(trie.get(&ipv4net(10, 0, 0, 0, 8)), None);
        assert!(trie.subtree(&ipv4net(10, 0, 0, 0, 8)).is_empty());
        assert!(trie.covering(&ipv4net(10, 0, 0, 0, 8)).is_empty());
        assert_eq!(trie.iter().count(), 0);
    }

    #[test]
    fn test_boundary_prefix_lengths() {
        // Default route /0 covers everything
        let mut trie = PrefixTrie::new();
        trie.insert(ipv4net(0, 0, 0, 0, 0), 0);
        trie.insert(ipv4net(10, 0, 0, 0, 8), 8);
        assert_eq!(trie.subtree(&ipv4net(0, 0, 0, 0, 0)).len(), 2);
        assert_eq!(
            sorted_values(&trie.covering(&ipv4net(10, 0, 0, 0, 8))),
            vec![0, 8]
        );

        // Host routes: /32 (IPv4), /128 (IPv6)
        let mut trie = PrefixTrie::new();
        trie.insert(ipv4net(10, 0, 0, 1, 32), 1);
        assert_eq!(trie.get(&ipv4net(10, 0, 0, 1, 32)), Some(&1));
        assert_eq!(trie.subtree(&ipv4net(10, 0, 0, 1, 32)).len(), 1);

        let mut trie6 = PrefixTrie::new();
        trie6.insert(ipv6net(1, 128), 1);
        assert_eq!(trie6.get(&ipv6net(1, 128)), Some(&1));
    }

    #[test]
    fn test_iter() {
        let mut trie = PrefixTrie::new();
        trie.insert(ipv4net(10, 0, 0, 0, 8), 1);
        trie.insert(ipv4net(10, 1, 0, 0, 16), 2);
        trie.insert(ipv4net(192, 168, 0, 0, 16), 3);

        let mut values: Vec<i32> = trie.iter().map(|(_, v)| *v).collect();
        values.sort();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[test]
    fn test_ipv6() {
        let mut trie = PrefixTrie::new();
        let addr_a = u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0));
        let addr_b = u128::from(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0));

        trie.insert(ipv6net(addr_a, 32), 32);
        trie.insert(ipv6net(addr_b, 48), 48);

        assert_eq!(trie.get(&ipv6net(addr_a, 32)), Some(&32));
        assert_eq!(trie.get(&ipv6net(addr_b, 48)), Some(&48));
        assert_eq!(trie.subtree(&ipv6net(addr_a, 32)).len(), 2);
        assert_eq!(trie.covering(&ipv6net(addr_b, 48)).len(), 2);
    }

    #[test]
    fn test_free_list_reuse() {
        let mut trie = PrefixTrie::new();
        let prefix = ipv4net(10, 0, 0, 0, 8);

        trie.insert(prefix, 1);
        let nodes_after_insert = trie.nodes.len();

        trie.remove(&prefix);
        assert_eq!(trie.free_list.len(), 1);

        // Re-insert reuses freed slot, vec doesn't grow
        trie.insert(prefix, 2);
        assert_eq!(trie.nodes.len(), nodes_after_insert);
        assert!(trie.free_list.is_empty());
        assert_eq!(trie.get(&prefix), Some(&2));
    }
}
