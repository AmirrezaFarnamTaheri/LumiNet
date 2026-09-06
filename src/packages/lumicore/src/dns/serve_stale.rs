//! # Serve-Stale Cache (Rust)
//!
//! Serves cached DNS responses past their TTL when the upstream resolver is
//! unavailable or slow. Entries are retained past their nominal expiry up to
//! a configurable  window, improving UX on flaky connections.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// A wire-format DNS response with its expiry metadata.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// Normalised query name (lowercase, no trailing dot).
    pub query: String,
    /// Raw DNS wire-format bytes.
    pub wire: Vec<u8>,
    /// Wall-clock expiry time.
    pub expires_at: Instant,
    /// Minimum TTL from the original response (used for serve-stale decision).
    pub min_ttl: u32,
    /// Upstream that supplied this response.
    pub upstream: String,
}

/// A TTL-bounded cache of DNS responses that can serve stale entries.
#[derive(Debug, Default)]
pub struct StaleCache {
    /// Inner map keyed by normalised query name.
    entries: HashMap<String, CachedResponse>,
    /// Maximum stale window past expiry.
    max_stale: Duration,
    /// Maximum number of entries before eviction.
    entry_limit: usize,
    /// Number of entries to evict when at capacity.
    evict_batch: usize,
}

impl StaleCache {
    /// Construct a cache with sensible defaults (max_stale: 24h, limit: 10000).
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_stale: Duration::from_secs(86400),
            entry_limit: 10_000,
            evict_batch: 100,
        }
    }

    /// Construct a cache with explicit configuration.
    pub fn with_config(max_stale: Duration, entry_limit: usize, evict_batch: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_stale,
            entry_limit,
            evict_batch,
        }
    }

    /// Store a response. Implements LRU-style eviction when at capacity.
    pub fn set(&mut self, query: &str, resp: CachedResponse) {
        let key = normalise_key(query);
        if self.entries.len() >= self.entry_limit {
            self.evict_stale();
        }
        if self.entries.len() >= self.entry_limit {
            self.evict_oldest(self.evict_batch);
        }
        self.entries.insert(key, resp);
    }

    /// Attempt to serve a response for . Returns 
    /// where  is  when the entry was served past its TTL.
    /// Returns  when no matching entry exists or the max-stale window
    /// has been exceeded.
    pub fn serve_stale(&self, query: &str) -> Option<(CachedResponse, bool)> {
        let key = normalise_key(query);
        let entry = self.entries.get(&key)?;
        let now = Instant::now();
        if now < entry.expires_at {
            // Fresh.
            return Some((entry.clone(), false));
        }
        if now.duration_since(entry.expires_at) <= self.max_stale {
            // Stale but within max-stale window.
            return Some((entry.clone(), true));
        }
        None
    }

    /// Returns the current number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Reports whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes the entry for .
    pub fn evict(&mut self, query: &str) {
        let key = normalise_key(query);
        self.entries.remove(&key);
    }

    /// Clears all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the configured max-stale window.
    pub fn max_stale(&self) -> Duration {
        self.max_stale
    }

    /// Updates the max-stale window.
    pub fn set_max_stale(&mut self, d: Duration) {
        self.max_stale = d;
    }

    /// Evicts all entries that have exceeded the max-stale window.
    fn evict_stale(&mut self) {
        let deadline = Instant::now().checked_sub(self.max_stale).unwrap_or(Instant::now());
        self.entries.retain(|_, entry| entry.expires_at > deadline);
    }

    /// Evicts the  entries with the oldest expiry times.
    fn evict_oldest(&mut self, n: usize) {
        if n == 0 || self.entries.is_empty() {
            return;
        }
        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by_key(|(_, e)| e.expires_at);
        let to_remove: Vec<_> = entries.into_iter().take(n).map(|(k, _)| k.clone()).collect();
        for key in to_remove {
            self.entries.remove(&key);
        }
    }
}

/// Normalises a domain name: lowercase, strip trailing dot.
fn normalise_key(name: &str) -> String {
    let mut s = name.to_lowercase();
    if s.ends_with('.') {
        s.pop();
    }
    s
}

/// Thread-safe wrapper around StaleCache.
#[derive(Debug, Default, Clone)]
pub struct SharedStaleCache {
    inner: Arc<RwLock<StaleCache>>,
}

impl SharedStaleCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(StaleCache::new())),
        }
    }

    pub fn with_config(max_stale: Duration, entry_limit: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StaleCache::with_config(
                max_stale,
                entry_limit,
                100,
            ))),
        }
    }

    /// Stores a response. Clones the inner lock.
    pub fn set(&self, query: &str, resp: CachedResponse) {
        self.inner.write().unwrap().set(query, resp);
    }

    /// Attempts to serve a stale response.
    pub fn serve_stale(&self, query: &str) -> Option<(CachedResponse, bool)> {
        self.inner.read().unwrap().serve_stale(query)
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn clear(&self) {
        self.inner.write().unwrap().clear();
    }

    pub fn evict(&self, query: &str) {
        self.inner.write().unwrap().evict(query);
    }

    pub fn max_stale(&self) -> Duration {
        self.inner.read().unwrap().max_stale()
    }

    pub fn set_max_stale(&self, d: Duration) {
        self.inner.write().unwrap().set_max_stale(d);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_resp(query: &str, ttl_secs: u32) -> CachedResponse {
        CachedResponse {
            query: query.to_string(),
            wire: b"response".to_vec(),
            expires_at: Instant::now() + Duration::from_secs(ttl_secs as u64),
            min_ttl: ttl_secs,
            upstream: "test".to_string(),
        }
    }

    fn stale_resp(query: &str, stale_secs: u32) -> CachedResponse {
        CachedResponse {
            query: query.to_string(),
            wire: b"stale-response".to_vec(),
            expires_at: Instant::now() - Duration::from_secs(stale_secs as u64),
            min_ttl: 300,
            upstream: "test".to_string(),
        }
    }

    #[test]
    fn test_set_and_serve_fresh() {
        let mut cache = StaleCache::new();
        cache.set("example.com", fresh_resp("example.com", 300));
        let (resp, is_stale) = cache.serve_stale("example.com").unwrap();
        assert!(!is_stale);
        assert_eq!(resp.wire, b"response");
    }

    #[test]
    fn test_serve_stale_within_window() {
        let mut cache = StaleCache::with_config(Duration::from_secs(3600), 100, 10);
        cache.set("example.com", stale_resp("example.com", 300)); // 5 min stale
        let (resp, is_stale) = cache.serve_stale("example.com").unwrap();
        assert!(is_stale);
        assert_eq!(resp.wire, b"stale-response");
    }

    #[test]
    fn test_rejects_beyond_max_stale() {
        let mut cache = StaleCache::with_config(Duration::from_secs(60), 100, 10);
        cache.set("example.com", stale_resp("example.com", 120)); // 2 min stale > 60s max
        assert!(cache.serve_stale("example.com").is_none());
    }

    #[test]
    fn test_normalise_key() {
        assert_eq!(normalise_key("Example.COM."), "example.com");
        assert_eq!(normalise_key("lowercase"), "lowercase");
        assert_eq!(normalise_key("trailing."), "trailing");
    }

    #[test]
    fn test_evict() {
        let mut cache = StaleCache::new();
        cache.set("example.com", fresh_resp("example.com", 300));
        assert_eq!(cache.len(), 1);
        cache.evict("example.com");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_clear() {
        let mut cache = StaleCache::new();
        for i in 0..10 {
            cache.set(&format!("host{}.com", i), fresh_resp(&format!("host{}.com", i), 300));
        }
        assert_eq!(cache.len(), 10);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_entry_limit_eviction() {
        let mut cache = StaleCache::with_config(Duration::from_secs(3600), 5, 2);
        for i in 0..10 {
            cache.set(&format!("host{}.com", i), fresh_resp(&format!("host{}.com", i), 300));
        }
        assert!(cache.len() <= 5);
    }

    #[test]
    fn test_shared_cache() {
        let cache = SharedStaleCache::new();
        cache.set("example.com", fresh_resp("example.com", 300));
        let (resp, is_stale) = cache.serve_stale("example.com").unwrap();
        assert!(!is_stale);
        assert_eq!(resp.wire, b"response");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_shared_cache_set_max_stale() {
        let cache = SharedStaleCache::with_config(Duration::from_secs(30), 100);
        assert_eq!(cache.max_stale(), Duration::from_secs(30));
        cache.set_max_stale(Duration::from_secs(60));
        assert_eq!(cache.max_stale(), Duration::from_secs(60));
    }
}
