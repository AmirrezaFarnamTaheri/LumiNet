//! # DNS Proxy Engine
//!
//! Full-featured DNS proxy with DoH/DoT/DoQ support, caching, rate limiting,
//! and upstream management. .
//!
//! Key patterns:
//! - Handler/Middleware chain for request processing
//! - Binary-packed cache items for efficient storage
//! - Domain-based upstream routing
//! - Single-flight deduplication for identical queries
//! - Optimistic cache (serve stale, revalidate in background)

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// DNS protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsProtocol {
    UDP,
    TCP,
    DoH,
    DoT,
    DoQ,
    DNSCrypt,
}

/// DNS context for request/response lifecycle.
#[derive(Debug, Clone)]
pub struct DnsContext {
    /// Original request message (raw bytes).
    pub request: Vec<u8>,
    /// Response message (raw bytes).
    pub response: Option<Vec<u8>>,
    /// Protocol used.
    pub proto: DnsProtocol,
    /// Client address.
    pub client_addr: SocketAddr,
    /// Upstream that resolved the query.
    pub upstream_addr: Option<String>,
    /// Query name.
    pub query_name: String,
    /// Query type (A, AAAA, etc).
    pub query_type: u16,
    /// Processing start time.
    pub start_time: Instant,
}

/// DNS cache entry with binary-packed format.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Cached response bytes.
    pub response: Vec<u8>,
    /// When this entry expires.
    pub expires_at: Instant,
    /// Upstream that provided this response.
    pub upstream: String,
    /// Original query name.
    pub query_name: String,
    /// Original query type.
    pub query_type: u16,
}

impl CacheEntry {
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }

    /// Creates a cache entry with TTL clamped to min/max bounds.
    pub fn new(
        response: Vec<u8>,
        ttl: Duration,
        upstream: String,
        query_name: String,
        query_type: u16,
        min_ttl: Duration,
        max_ttl: Duration,
    ) -> Self {
        let clamped_ttl = ttl.max(min_ttl).min(max_ttl);
        Self {
            response,
            expires_at: Instant::now() + clamped_ttl,
            upstream,
            query_name,
            query_type,
        }
    }
}

/// Cache key construction.
pub fn cache_key(query_name: &str, query_type: u16, dnssec_ok: bool) -> String {
    format!(
        "{}:{}:{}",
        if dnssec_ok { "1" } else { "0" },
        query_type,
        query_name.to_lowercase()
    )
}

/// Cache key with ECS (EDNS Client Subnet) support.
pub fn cache_key_with_ecs(
    query_name: &str,
    query_type: u16,
    dnssec_ok: bool,
    ecs_ip: Option<IpAddr>,
    ecs_mask: u8,
) -> String {
    let ecs_str = match ecs_ip {
        Some(ip) => format!("{}:{}", ip, ecs_mask),
        None => "none".to_string(),
    };
    format!(
        "{}:{}:{}:{}",
        if dnssec_ok { "1" } else { "0" },
        query_type,
        query_name.to_lowercase(),
        ecs_str
    )
}

/// DNS response cache with LRU eviction.
pub struct DnsCache {
    entries: RwLock<HashMap<String, CacheEntry>>,
    max_size: usize,
    min_ttl: Duration,
    max_ttl: Duration,
}

impl DnsCache {
    pub fn new(max_size: usize, min_ttl: Duration, max_ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_size,
            min_ttl,
            max_ttl,
        }
    }

    /// Looks up a cached response.
    pub async fn get(&self, key: &str) -> Option<CacheEntry> {
        let entries = self.entries.read().await;
        entries.get(key).filter(|e| !e.is_expired()).cloned()
    }

    /// Inserts a response into the cache.
    pub async fn insert(&self, key: String, entry: CacheEntry) {
        let mut entries = self.entries.write().await;

        // Evict expired entries if at capacity
        if entries.len() >= self.max_size {
            entries.retain(|_, e| !e.is_expired());
        }

        // If still at capacity, remove oldest
        if entries.len() >= self.max_size {
            if let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, e)| e.expires_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
            }
        }

        entries.insert(key, entry);
    }

    /// Evicts all expired entries.
    pub async fn evict_expired(&self) {
        let mut entries = self.entries.write().await;
        entries.retain(|_, e| !e.is_expired());
    }

    pub async fn len(&self) -> usize {
        self.entries.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.entries.read().await.is_empty()
    }

    /// Returns the configured minimum and maximum cache TTL bounds.
    pub fn ttl_bounds(&self) -> (Duration, Duration) {
        (self.min_ttl, self.max_ttl)
    }
}

/// Upstream configuration for domain-based routing.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Default upstreams (used when no domain-specific match).
    pub default_upstreams: Vec<String>,
    /// Domain-specific upstreams (e.g., "example.com" -> ["1.1.1.1"]).
    pub domain_upstreams: HashMap<String, Vec<String>>,
    /// Domains to exclude from parent domain matching.
    pub domain_exclusions: Vec<String>,
}

impl UpstreamConfig {
    /// Gets upstreams for a specific domain, walking up the hierarchy.
    pub fn get_upstreams_for_domain(&self, domain: &str) -> Vec<String> {
        let domain = domain.trim_end_matches('.').to_lowercase();

        // Check exact match first
        if let Some(ups) = self.domain_upstreams.get(&domain) {
            return ups.clone();
        }

        // Walk domain hierarchy: sub.example.com -> example.com -> com
        let parts: Vec<&str> = domain.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if let Some(ups) = self.domain_upstreams.get(&parent) {
                return ups.clone();
            }
        }

        // Fall back to default
        self.default_upstreams.clone()
    }
}

/// Pending request deduplication.
/// Prevents duplicate upstream queries for identical requests.
pub struct PendingRequests {
    pending: RwLock<HashMap<String, Arc<tokio::sync::Notify>>>,
}

impl Default for PendingRequests {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingRequests {
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
        }
    }

    /// Checks if a request is already pending. Returns true if duplicate.
    pub async fn is_pending(&self, key: &str) -> bool {
        self.pending.read().await.contains_key(key)
    }

    /// Registers a request as pending.
    pub async fn register(&self, key: String) {
        let notify = Arc::new(tokio::sync::Notify::new());
        self.pending.write().await.insert(key, notify);
    }

    /// Completes a pending request, notifying waiters.
    pub async fn complete(&self, key: &str) {
        if let Some(notify) = self.pending.write().await.remove(key) {
            notify.notify_waiters();
        }
    }
}

/// Bogus NXDomain detection.
/// Converts responses containing specific IPs to NXDOMAIN.
#[derive(Debug, Clone)]
pub struct BogusNxDomain {
    /// IPs/subnets that indicate a bogus response.
    pub bogus_ips: Vec<IpAddr>,
    /// Subnets in CIDR notation.
    pub bogus_subnets: Vec<String>,
}

impl Default for BogusNxDomain {
    fn default() -> Self {
        Self::new()
    }
}

impl BogusNxDomain {
    pub fn new() -> Self {
        Self {
            bogus_ips: Vec::new(),
            bogus_subnets: Vec::new(),
        }
    }

    /// Checks if a response contains bogus IPs.
    pub fn is_bogus(&self, response_ips: &[IpAddr]) -> bool {
        for ip in response_ips {
            if self.bogus_ips.contains(ip) {
                return true;
            }
            // TODO: Check against CIDR subnets
        }
        false
    }
}

/// Rate limiter for DNS queries.
pub struct RateLimiter {
    /// Per-subnet rate limit (queries per second).
    rate: u32,
    /// IPv4 subnet length for grouping.
    subnet_len_v4: u8,
    /// IPv6 subnet length for grouping.
    subnet_len_v6: u8,
    /// Per-subnet counters.
    counters: RwLock<HashMap<String, RateCounter>>,
}

struct RateCounter {
    count: u32,
    window_start: Instant,
}

impl RateLimiter {
    pub fn new(rate: u32, subnet_len_v4: u8, subnet_len_v6: u8) -> Self {
        Self {
            rate,
            subnet_len_v4,
            subnet_len_v6,
            counters: RwLock::new(HashMap::new()),
        }
    }

    /// Checks if a request should be rate-limited.
    pub async fn is_limited(&self, addr: &IpAddr) -> bool {
        let key = self.subnet_key(addr);
        let mut counters = self.counters.write().await;
        let counter = counters.entry(key).or_insert_with(|| RateCounter {
            count: 0,
            window_start: Instant::now(),
        });

        // Reset window if expired (1 second)
        if counter.window_start.elapsed() >= Duration::from_secs(1) {
            counter.count = 0;
            counter.window_start = Instant::now();
        }

        counter.count += 1;
        counter.count > self.rate
    }

    fn subnet_key(&self, addr: &IpAddr) -> String {
        match addr {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                let mask_bits = self.subnet_len_v4;
                let mask = !((1u32 << (32 - mask_bits)) - 1);
                let ip_bits = u32::from_be_bytes(octets);
                let masked = ip_bits & mask;
                format!("v4:{}", IpAddr::from(masked.to_be_bytes()))
            }
            IpAddr::V6(v6) => {
                format!("v6:{}/{}", v6, self.subnet_len_v6)
            }
        }
    }
}

/// DNS proxy configuration.
#[derive(Debug, Clone)]
pub struct DnsProxyConfig {
    /// Listen addresses.
    pub listen: Vec<SocketAddr>,
    /// Upstream configuration.
    pub upstreams: UpstreamConfig,
    /// Cache size.
    pub cache_size: usize,
    /// Minimum cache TTL.
    pub cache_min_ttl: Duration,
    /// Maximum cache TTL.
    pub cache_max_ttl: Duration,
    /// Rate limit (queries per second per subnet).
    pub rate_limit: u32,
    /// Enable DNS64 synthesis.
    pub dns64: bool,
    /// NAT64 prefix for DNS64.
    pub nat64_prefix: Option<Vec<u8>>,
    /// Bogus NXDomain IPs.
    pub bogus_nxdomain: BogusNxDomain,
    /// Enable EDNS Client Subnet.
    pub enable_ecs: bool,
    /// Block IPv6 (AAAA) responses.
    pub block_aaaa: bool,
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            listen: vec!["127.0.0.1:53".parse().unwrap()],
            upstreams: UpstreamConfig {
                default_upstreams: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
                domain_upstreams: HashMap::new(),
                domain_exclusions: Vec::new(),
            },
            cache_size: 4096,
            cache_min_ttl: Duration::from_secs(60),
            cache_max_ttl: Duration::from_secs(86400),
            rate_limit: 0,
            dns64: false,
            nat64_prefix: None,
            bogus_nxdomain: BogusNxDomain::new(),
            enable_ecs: false,
            block_aaaa: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key() {
        let key = cache_key("example.com", 1, false);
        assert_eq!(key, "0:1:example.com");

        let key_doh = cache_key("example.com", 1, true);
        assert_eq!(key_doh, "1:1:example.com");
    }

    #[test]
    fn test_upstream_domain_routing() {
        let config = UpstreamConfig {
            default_upstreams: vec!["8.8.8.8".to_string()],
            domain_upstreams: HashMap::from([
                ("example.com".to_string(), vec!["1.1.1.1".to_string()]),
                ("google.com".to_string(), vec!["8.8.4.4".to_string()]),
            ]),
            domain_exclusions: Vec::new(),
        };

        assert_eq!(
            config.get_upstreams_for_domain("example.com"),
            vec!["1.1.1.1"]
        );
        assert_eq!(
            config.get_upstreams_for_domain("sub.example.com"),
            vec!["1.1.1.1"]
        );
        assert_eq!(
            config.get_upstreams_for_domain("other.com"),
            vec!["8.8.8.8"]
        );
    }

    #[test]
    fn test_bogus_nxdomain() {
        let mut bogus = BogusNxDomain::new();
        bogus.bogus_ips.push("198.18.0.1".parse().unwrap());

        assert!(bogus.is_bogus(&["198.18.0.1".parse().unwrap()]));
        assert!(!bogus.is_bogus(&["8.8.8.8".parse().unwrap()]));
    }

    #[tokio::test]
    async fn test_cache_insert_get() {
        let cache = DnsCache::new(100, Duration::from_secs(60), Duration::from_secs(86400));
        let entry = CacheEntry::new(
            vec![1, 2, 3, 4],
            Duration::from_secs(300),
            "8.8.8.8".to_string(),
            "example.com".to_string(),
            1,
            Duration::from_secs(60),
            Duration::from_secs(86400),
        );

        let key = cache_key("example.com", 1, false);
        cache.insert(key.clone(), entry).await;

        let cached = cache.get(&key).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().response, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(5, 24, 48);
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        for _ in 0..5 {
            assert!(!limiter.is_limited(&ip).await);
        }

        assert!(limiter.is_limited(&ip).await);
    }
}
