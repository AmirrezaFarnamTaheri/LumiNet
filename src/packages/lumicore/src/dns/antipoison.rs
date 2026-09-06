//! # DNS Anti-Poisoning
//!
//! DNS response validation to detect and filter poisoned/censored DNS responses.
//!
//! Core algorithm: Compare responses from multiple DNS servers, detect when a
//! Chinese DNS returns an IP that's NOT in the China IP range (likely poisoned),
//! and prefer the trusted DNS response in that case.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::routing::IpRoutingTrie;

/// DNS response validation result.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsValidation {
    /// Response is valid and trustworthy.
    Valid,
    /// Response is suspected poisoned (IP doesn't match expected region).
    SuspectedPoisoned { reason: String },
    /// Response is definitely bogus (known poison pattern).
    Bogus { reason: String },
    /// Inconclusive - unable to determine.
    Inconclusive,
}

/// Bogus NX domain detection.
/// Some ISPs return fake A records pointing to specific IP ranges for blocked domains.
pub fn is_bogus_nxdomain(response_ips: &[IpAddr], bogus_subnets: &[&str]) -> bool {
    if bogus_subnets.is_empty() || response_ips.is_empty() {
        return false;
    }

    for ip in response_ips {
        for subnet in bogus_subnets {
            if let Some((network, prefix_len)) = parse_cidr(subnet) {
                if ip_in_network(ip, &network, prefix_len) {
                    return true;
                }
            }
        }
    }
    false
}

/// Known ISP bogus IP ranges commonly returned by poisoned DNS.
/// These are well-known addresses that ISPs use for their block pages.
pub const KNOWN_BOGUS_IPS: &[&str] = &[
    // Common ISP block page IPs
    "1.1.1.1/32",       // Sometimes used as poison (legitimate Cloudflare)
    "211.94.68.0/23",   // China Telecom poison range
    "211.138.126.0/23", // China Mobile poison range
    "118.244.0.0/16",   // Common poison range
    "59.36.96.0/20",    // China poison range
    "123.125.81.0/24",  // Baidu poison
    "220.250.64.0/20",  // Japan ISP poison
    "203.119.0.0/16",   // Common redirect range
    "198.18.0.0/15",    // Benchmarking (should never appear in real DNS)
];

/// Validates a DNS response against known patterns.
pub fn validate_dns_response(
    response_ips: &[IpAddr],
    query_name: &str,
    chnroute_trie: Option<&IpRoutingTrie<bool>>,
) -> DnsValidation {
    if response_ips.is_empty() {
        return DnsValidation::Inconclusive;
    }

    // Check against known bogus IPs
    if is_bogus_nxdomain(response_ips, KNOWN_BOGUS_IPS) {
        return DnsValidation::Bogus {
            reason: format!("Response for {} contains known bogus IP", query_name),
        };
    }

    // Check for private IPs in public DNS responses (always suspicious)
    for ip in response_ips {
        if is_private_ip(ip) {
            return DnsValidation::SuspectedPoisoned {
                reason: format!(
                    "Response for {} contains private IP {} from public DNS",
                    query_name, ip
                ),
            };
        }
    }

    // If we have a chnroute trie, validate regional consistency
    if let Some(trie) = chnroute_trie {
        // Check if any response IP is in China ranges
        let has_chn_ip = response_ips
            .iter()
            .any(|ip| trie.longest_match(ip).is_some());
        let has_non_chn_ip = response_ips
            .iter()
            .any(|ip| trie.longest_match(ip).is_none());

        // Mixed China + non-China IPs for the same domain is suspicious
        if has_chn_ip && has_non_chn_ip {
            return DnsValidation::SuspectedPoisoned {
                reason: format!(
                    "Response for {} has mixed regional IPs (possible injection)",
                    query_name
                ),
            };
        }
    }

    DnsValidation::Valid
}

/// Compares responses from a trusted DNS and an untrusted DNS.
/// Returns the best response based on regional consistency.
/// This is the core ChinaDNS algorithm.
pub fn select_best_response(
    trusted_ips: &[IpAddr],
    untrusted_ips: &[IpAddr],
    chnroute_trie: &IpRoutingTrie<bool>,
) -> Vec<IpAddr> {
    if trusted_ips.is_empty() {
        return untrusted_ips.to_vec();
    }
    if untrusted_ips.is_empty() {
        return trusted_ips.to_vec();
    }

    // Check if untrusted response has China IPs
    let untrusted_in_chn: Vec<IpAddr> = untrusted_ips
        .iter()
        .filter(|ip| chnroute_trie.longest_match(ip).is_some())
        .copied()
        .collect();

    // If untrusted response has China IPs, it's likely legitimate for China domains
    if !untrusted_in_chn.is_empty() {
        return untrusted_in_chn;
    }

    // Otherwise, use trusted response
    trusted_ips.to_vec()
}

/// Fast DNS cache entry with TTL.
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub ips: Vec<IpAddr>,
    pub ttl: Duration,
    pub inserted_at: Instant,
}

impl DnsCacheEntry {
    pub fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

/// DNS cache with TTL-based expiration.
pub struct DnsCache {
    entries: std::collections::HashMap<String, DnsCacheEntry>,
    max_size: usize,
    default_ttl: Duration,
}

impl DnsCache {
    pub fn new(max_size: usize, default_ttl: Duration) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            max_size,
            default_ttl,
        }
    }

    pub fn get(&self, domain: &str) -> Option<&DnsCacheEntry> {
        self.entries.get(domain).filter(|e| !e.is_expired())
    }

    pub fn insert(&mut self, domain: String, ips: Vec<IpAddr>, ttl: Option<Duration>) {
        if self.entries.len() >= self.max_size {
            self.evict_expired();
            if self.entries.len() >= self.max_size {
                // Remove oldest entry
                if let Some(oldest_key) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, e)| e.inserted_at)
                    .map(|(k, _)| k.clone())
                {
                    self.entries.remove(&oldest_key);
                }
            }
        }

        self.entries.insert(
            domain,
            DnsCacheEntry {
                ips,
                ttl: ttl.unwrap_or(self.default_ttl),
                inserted_at: Instant::now(),
            },
        );
    }

    fn evict_expired(&mut self) {
        self.entries.retain(|_, e| !e.is_expired());
    }
}

// Helper functions - delegate to netutil where possible
fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip: IpAddr = parts[0].parse().ok()?;
    let prefix: u8 = parts[1].parse().ok()?;
    Some((ip, prefix))
}

fn ip_in_network(ip: &IpAddr, network: &IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let ip_bits = u32::from_be_bytes(ip.octets());
            let net_bits = u32::from_be_bytes(net.octets());
            let mask = !((1u32 << (32 - prefix_len)) - 1);
            (ip_bits & mask) == (net_bits & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let ip_bits = u128::from_be_bytes(ip.octets());
            let net_bits = u128::from_be_bytes(net.octets());
            let mask = !((1u128 << (128 - prefix_len)) - 1);
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false,
    }
}

/// Checks if IP is private - delegates to netutil for consistency.
fn is_private_ip(ip: &IpAddr) -> bool {
    crate::netutil::is_private_address(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bogus_nxdomain() {
        let ips: Vec<IpAddr> = vec!["198.18.0.1".parse().unwrap()];
        assert!(is_bogus_nxdomain(&ips, KNOWN_BOGUS_IPS));

        let clean_ips: Vec<IpAddr> = vec!["8.8.8.8".parse().unwrap()];
        assert!(!is_bogus_nxdomain(&clean_ips, KNOWN_BOGUS_IPS));
    }

    #[test]
    fn test_validate_private_ip() {
        let ips: Vec<IpAddr> = vec!["192.168.1.1".parse().unwrap()];
        let result = validate_dns_response(&ips, "example.com", None);
        assert!(matches!(result, DnsValidation::SuspectedPoisoned { .. }));
    }

    #[test]
    fn test_validate_clean_response() {
        let ips: Vec<IpAddr> = vec!["93.184.216.34".parse().unwrap()];
        let result = validate_dns_response(&ips, "example.com", None);
        assert_eq!(result, DnsValidation::Valid);
    }

    #[test]
    fn test_dns_cache() {
        let mut cache = DnsCache::new(100, Duration::from_secs(300));
        let ips = vec!["1.2.3.4".parse().unwrap()];
        cache.insert("example.com".to_string(), ips.clone(), None);

        let entry = cache.get("example.com").unwrap();
        assert_eq!(entry.ips, ips);
    }
}
