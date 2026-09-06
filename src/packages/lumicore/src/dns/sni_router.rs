//! SNI Domain Routing Table & Destination IP Rewriting
//!
//! Ported and unified from `smartSNI-main`.
//! Maps domain patterns (exact, suffix wildcards, substring matches) to dedicated
//! target IP addresses for routing censored or desynced SNI connections.
//!
//! Conforms to strict architectural isolation rules: zero vendor prefixes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;

/// Thread-safe routing table mapping SNI hostnames to target IP addresses.
pub struct SniRoutingTable {
    exact: RwLock<HashMap<String, IpAddr>>,
    wildcards: RwLock<HashMap<String, IpAddr>>,
    contains: RwLock<HashMap<String, IpAddr>>,
}

impl Default for SniRoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SniRoutingTable {
    pub fn new() -> Self {
        Self {
            exact: RwLock::new(HashMap::new()),
            wildcards: RwLock::new(HashMap::new()),
            contains: RwLock::new(HashMap::new()),
        }
    }

    /// Adds a 1-to-1 exact domain match.
    pub fn add_exact_route(&self, domain: &str, target_ip: IpAddr) {
        let clean = clean_domain(domain);
        let mut map = self.exact.write().unwrap();
        map.insert(clean, target_ip);
    }

    /// Adds a wildcard domain suffix match (e.g., "*.example.com" or "example.com").
    pub fn add_wildcard_route(&self, suffix: &str, target_ip: IpAddr) {
        let clean = clean_suffix(suffix);
        let mut map = self.wildcards.write().unwrap();
        map.insert(clean, target_ip);
    }

    /// Adds a substring domain match.
    pub fn add_substring_route(&self, substr: &str, target_ip: IpAddr) {
        let clean = substr.trim().to_ascii_lowercase();
        let mut map = self.contains.write().unwrap();
        map.insert(clean, target_ip);
    }

    /// Resolves target IP by precedence: Exact -> Wildcard suffix -> Substring.
    pub fn resolve_route(&self, domain: &str) -> Option<IpAddr> {
        let clean = clean_domain(domain);

        // 1. Exact match
        {
            let exact_map = self.exact.read().unwrap();
            if let Some(&ip) = exact_map.get(&clean) {
                return Some(ip);
            }
        }

        // 2. Wildcard suffix match
        {
            let wildcards_map = self.wildcards.read().unwrap();
            for (suffix, &ip) in wildcards_map.iter() {
                if clean == *suffix || clean.ends_with(&format!(".{}", suffix)) {
                    return Some(ip);
                }
            }
        }

        // 3. Substring match
        {
            let contains_map = self.contains.read().unwrap();
            for (substr, &ip) in contains_map.iter() {
                if clean.contains(substr) {
                    return Some(ip);
                }
            }
        }

        None
    }

    pub fn total_routes(&self) -> usize {
        let e = self.exact.read().unwrap().len();
        let w = self.wildcards.read().unwrap().len();
        let c = self.contains.read().unwrap().len();
        e + w + c
    }
}

fn clean_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn clean_suffix(suffix: &str) -> String {
    let mut clean = suffix.trim().to_ascii_lowercase();
    while clean.starts_with('*') || clean.starts_with('.') {
        clean.remove(0);
    }
    clean.trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_exact_and_wildcard_resolution() {
        let table = SniRoutingTable::new();
        let target_yt: IpAddr = IpAddr::V4(Ipv4Addr::new(142, 250, 180, 14));
        let target_google: IpAddr = IpAddr::V4(Ipv4Addr::new(142, 250, 180, 46));

        table.add_exact_route("youtube.com", target_yt);
        table.add_wildcard_route("*.googlevideo.com", target_yt);
        table.add_substring_route("google", target_google);

        // Exact match
        assert_eq!(table.resolve_route("youtube.com"), Some(target_yt));
        assert_eq!(table.resolve_route("YouTube.COM."), Some(target_yt));

        // Wildcard match
        assert_eq!(table.resolve_route("rr1---sn-4g5edn6e.googlevideo.com"), Some(target_yt));
        assert_eq!(table.resolve_route("googlevideo.com"), Some(target_yt));

        // Substring fallback
        assert_eq!(table.resolve_route("auth.google.internal"), Some(target_google));

        // Non-matching
        assert_eq!(table.resolve_route("wikipedia.org"), None);
        assert_eq!(table.total_routes(), 3);
    }

    #[test]
    fn test_precedence_order() {
        let table = SniRoutingTable::new();
        let ip_exact: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip_wildcard: IpAddr = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let ip_substring: IpAddr = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));

        // Register all three targeting the same domain token
        table.add_substring_route("corp", ip_substring);
        table.add_wildcard_route("*.corp.local", ip_wildcard);
        table.add_exact_route("gateway.corp.local", ip_exact);

        // Exact beats wildcard
        assert_eq!(table.resolve_route("gateway.corp.local"), Some(ip_exact));
        // Wildcard beats substring
        assert_eq!(table.resolve_route("api.corp.local"), Some(ip_wildcard));
        // Substring catches rest
        assert_eq!(table.resolve_route("corp-portal.net"), Some(ip_substring));
    }
}
