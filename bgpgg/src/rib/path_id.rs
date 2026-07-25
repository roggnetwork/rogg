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

pub trait PathIdAllocator {
    fn alloc(&mut self) -> u32;
    fn free(&mut self, id: u32);
    fn free_all(&mut self, ids: Vec<u32>);
}

/// Bitmap allocator for ADD-PATH local path IDs.
///
/// Each bit represents one ID. IDs are 1-based (0 is reserved as sentinel
/// for unallocated paths in adj-rib-in). `pos` tracks the lowest word that
/// might have a free bit, so sequential allocation is O(1).
/// `trailing_ones()` compiles to a single TZCNT instruction.
///
/// Auto-grows when all bits are set. Free is O(1).
pub struct BitmapPathIdAllocator {
    bits: Vec<u64>,
    pos: usize,
}

impl Default for BitmapPathIdAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl BitmapPathIdAllocator {
    pub fn new() -> Self {
        BitmapPathIdAllocator {
            bits: Vec::new(),
            pos: 0,
        }
    }
}

impl PathIdAllocator for BitmapPathIdAllocator {
    fn alloc(&mut self) -> u32 {
        for idx in self.pos..self.bits.len() {
            let word = self.bits[idx];
            if word != u64::MAX {
                let bit = word.trailing_ones();
                self.bits[idx] |= 1 << bit;
                self.pos = idx;
                return (idx as u32) * 64 + bit + 1;
            }
        }
        // All full or empty: grow by one word
        self.bits.push(1);
        self.pos = self.bits.len() - 1;
        (self.pos as u32) * 64 + 1
    }

    fn free_all(&mut self, ids: Vec<u32>) {
        for id in ids {
            self.free(id);
        }
    }

    fn free(&mut self, id: u32) {
        if id == 0 {
            return;
        }
        let id = id - 1; // adjust for 1-based offset
        let word_idx = id as usize / 64;
        let bit_idx = id % 64;
        if word_idx < self.bits.len() {
            self.bits[word_idx] &= !(1u64 << bit_idx);
            if word_idx < self.pos {
                self.pos = word_idx;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_id_allocator() {
        let tests = [
            ("sequential alloc", vec!["a", "a", "a"], vec![1, 2, 3]),
            (
                "free and reuse",
                vec!["a", "a", "a", "f2", "a"],
                vec![1, 2, 3, 0, 2],
            ),
            ("free(0) is no-op then alloc", vec!["f0", "a"], vec![0, 1]),
        ];

        for (name, ops, expected) in tests {
            let mut alloc = BitmapPathIdAllocator::new();
            let mut results = Vec::new();
            for op in &ops {
                if *op == "a" {
                    results.push(alloc.alloc());
                } else if let Some(id_str) = op.strip_prefix('f') {
                    let id: u32 = id_str.parse().unwrap();
                    alloc.free(id);
                    results.push(0); // placeholder
                }
            }
            assert_eq!(results, expected, "test case: {}", name);
        }
    }

    #[test]
    fn test_grow_past_first_word() {
        let mut alloc = BitmapPathIdAllocator::new();
        // Fill 64 IDs (one full word)
        for expected in 1..=64 {
            assert_eq!(alloc.alloc(), expected);
        }
        // 65th should grow to second word
        assert_eq!(alloc.alloc(), 65);
        assert_eq!(alloc.bits.len(), 2);
    }

    #[test]
    fn test_free_enables_reuse_from_earlier_word() {
        let mut alloc = BitmapPathIdAllocator::new();
        // Alloc 65 IDs (spans 2 words)
        for _ in 0..65 {
            alloc.alloc();
        }
        // Free ID 1 (in word 0)
        alloc.free(1);
        // Next alloc should return 1 (scans from word 0)
        assert_eq!(alloc.alloc(), 1);
    }
}
