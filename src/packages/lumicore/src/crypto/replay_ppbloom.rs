// Bloom filter for SS2022 replay protection. Clean-room, MIT.

/// Count-Min sketch-based Bloom filter for SS2022 replay protection.
///
/// This is a "PPBloom" filter — a Bloom filter variant that supports parallel
/// partitions. It is used by SS2022 to detect replayed packets by storing
/// recently-seen (salt, nonce) tuples.
#[derive(Clone)]
pub struct PpbloomFilter {
    width: usize,
    depth: usize,
    tables: Vec<Vec<u8>>,
    seeds: Vec<u32>,
}

impl PpbloomFilter {
    /// Create a new PpBloom filter with `depth` parallel tables of `width` cells.
    pub fn new(width: usize, depth: usize) -> Self {
        let tables = (0..depth).map(|_| vec![0u8; width]).collect();
        let seeds: Vec<u32> = (0..depth)
            .map(|i| {
                // FNV-style seed mixing.
                let mut s = 2166136261u32;
                for _ in 0..i {
                    s = s.wrapping_mul(16777619);
                }
                s
            })
            .collect();
        Self { width, depth, tables, seeds }
    }

    /// Insert a value into the filter.
    pub fn insert(&mut self, value: &[u8]) {
        // Precompute all indices to avoid holding a mutable borrow while calling self.hash.
        let indices: Vec<usize> = self.seeds
            .iter()
            .map(|&seed| self.hash(value, seed) as usize % self.width)
            .collect();
        for (i, table) in self.tables.iter_mut().enumerate() {
            let idx = indices[i];
            table[idx] = table[idx].saturating_add(1);
        }
    }

    /// Check if a value has been seen (approximate — false positives possible).
    pub fn contains(&self, value: &[u8]) -> bool {
        self.tables.iter().enumerate().all(|(i, table)| {
            let idx = self.hash(value, self.seeds[i]) as usize % self.width;
            table[idx] > 0
        })
    }

    fn hash(&self, data: &[u8], seed: u32) -> u32 {
        let mut h = seed;
        for &b in data {
            h = h.wrapping_mul(16777619).wrapping_add(b as u32);
        }
        h
    }
}

/// Replay guard wrapping a PpbloomFilter with SS2022-specific helpers.
pub struct ReplayGuard {
    filter: PpbloomFilter,
}

impl ReplayGuard {
    /// Create a new replay guard with default sizing.
    pub fn new() -> Self {
        Self::with_capacity(1 << 16, 4)
    }

    /// Create a replay guard with custom sizing.
    pub fn with_capacity(width: usize, depth: usize) -> Self {
        Self {
            filter: PpbloomFilter::new(width, depth),
        }
    }

    /// Check if a packet with the given salt and nonce is a replay.
    /// Returns `true` if this is a replay and should be rejected.
    pub fn is_replay(&self, salt: &[u8], nonce: u64) -> bool {
        let mut key = Vec::with_capacity(salt.len() + 8);
        key.extend_from_slice(salt);
        key.extend_from_slice(&nonce.to_le_bytes());
        self.filter.contains(&key)
    }

    /// Record a packet so future replays are detected.
    pub fn record(&mut self, salt: &[u8], nonce: u64) {
        let mut key = Vec::with_capacity(salt.len() + 8);
        key.extend_from_slice(salt);
        key.extend_from_slice(&nonce.to_le_bytes());
        self.filter.insert(&key);
    }
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_contains() {
        let mut filter = PpbloomFilter::new(1024, 3);
        let value = b"unique-packet-42";
        assert!(!filter.contains(value));
        filter.insert(value);
        assert!(filter.contains(value));
    }

    #[test]
    fn test_replay_guard_detects_replay() {
        let mut guard = ReplayGuard::new();
        let salt = [0xAA; 32];
        assert!(!guard.is_replay(&salt, 42));
        guard.record(&salt, 42);
        assert!(guard.is_replay(&salt, 42));
    }

    #[test]
    fn test_replay_guard_different_nonce_not_replay() {
        let mut guard = ReplayGuard::new();
        let salt = [0xAA; 32];
        guard.record(&salt, 42);
        assert!(!guard.is_replay(&salt, 99));
    }

    #[test]
    fn test_replay_guard_different_salt_not_replay() {
        let mut guard = ReplayGuard::new();
        guard.record(&[0xAA; 32], 42);
        assert!(!guard.is_replay(&[0xBB; 32], 42));
    }

    #[test]
    fn test_false_positive_rate_bounded() {
        let mut filter = PpbloomFilter::new(4096, 3);
        for i in 0..500 {
            let key = format!("key-{}", i);
            filter.insert(key.as_bytes());
        }
        // 200 unseen values, expect some false positives but not all.
        let mut fps = 0;
        for i in 10000..10200 {
            let key = format!("unseen-{}", i);
            if filter.contains(key.as_bytes()) {
                fps += 1;
            }
        }
        assert!(fps < 200, "too many false positives: {fps}");
    }
}
