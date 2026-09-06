//! # Virtual DNS (Fake-IP)
//!
//! Maps domain names to virtual IPs from a fake pool (198.18.0.0/15).
//! When a connection targets a virtual IP, the real domain name is sent
//! to the proxy instead. This enables domain-based proxy routing without
//! requiring the proxy to support DNS resolution.
//!

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Virtual DNS pool range: 198.18.0.0/15
/// This range is reserved for benchmarking and not routable on the public internet.
const VIRTUAL_POOL_START: u32 = (198 << 24) | (18 << 16); // 198.18.0.0
const VIRTUAL_POOL_SIZE: u32 = 1 << 17; // 131072 addresses (covers /15)

/// Default TTL for virtual DNS entries.
const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Virtual DNS entry.
#[derive(Debug, Clone)]
struct VirtualEntry {
    domain: String,
    ip: Ipv4Addr,
    created: Instant,
    ttl: Duration,
}

impl VirtualEntry {
    fn is_expired(&self) -> bool {
        self.created.elapsed() > self.ttl
    }
}

/// Virtual DNS server that maps domains to fake IPs.
#[derive(Clone)]
pub struct VirtualDns {
    /// domain → VirtualEntry
    domain_map: Arc<RwLock<HashMap<String, VirtualEntry>>>,
    /// IP (as u32) → VirtualEntry
    ip_map: Arc<RwLock<HashMap<u32, VirtualEntry>>>,
    /// Next available IP index.
    next_index: Arc<RwLock<u32>>,
    /// TTL for entries.
    ttl: Duration,
}

impl VirtualDns {
    /// Creates a new Virtual DNS server.
    pub fn new(ttl: Option<Duration>) -> Self {
        Self {
            domain_map: Arc::new(RwLock::new(HashMap::new())),
            ip_map: Arc::new(RwLock::new(HashMap::new())),
            next_index: Arc::new(RwLock::new(0)),
            ttl: ttl.unwrap_or(DEFAULT_TTL),
        }
    }

    /// Resolves a domain to a virtual IP, creating a new mapping if needed.
    pub fn resolve(&self, domain: &str) -> Option<Ipv4Addr> {
        let domain = domain.trim_end_matches('.').to_lowercase();

        // Check existing mapping
        {
            let domain_map = self.domain_map.read().unwrap();
            if let Some(entry) = domain_map.get(&domain) {
                if !entry.is_expired() {
                    return Some(entry.ip);
                }
            }
        }

        // Create new mapping
        let ip = self.allocate_ip()?;
        let entry = VirtualEntry {
            domain: domain.clone(),
            ip,
            created: Instant::now(),
            ttl: self.ttl,
        };

        let mut domain_map = self.domain_map.write().unwrap();
        let mut ip_map = self.ip_map.write().unwrap();

        // Check for race condition
        if let Some(existing) = domain_map.get(&domain) {
            if !existing.is_expired() {
                return Some(existing.ip);
            }
        }

        domain_map.insert(domain, entry.clone());
        ip_map.insert(ip_to_u32(ip), entry);

        Some(ip)
    }

    /// Reverse-resolves a virtual IP to its domain name.
    pub fn reverse_resolve(&self, ip: &Ipv4Addr) -> Option<String> {
        let ip_map = self.ip_map.read().unwrap();
        let key = ip_to_u32(*ip);
        ip_map.get(&key).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.domain.clone())
            }
        })
    }

    /// Checks if an IP is from the virtual pool.
    pub fn is_virtual_ip(ip: &Ipv4Addr) -> bool {
        let ip_u32 = ip_to_u32(*ip);
        (VIRTUAL_POOL_START..VIRTUAL_POOL_START + VIRTUAL_POOL_SIZE).contains(&ip_u32)
    }

    /// Evicts expired entries.
    pub fn evict_expired(&self) {
        let mut domain_map = self.domain_map.write().unwrap();
        let mut ip_map = self.ip_map.write().unwrap();

        let expired_domains: Vec<String> = domain_map
            .iter()
            .filter(|(_, e)| e.is_expired())
            .map(|(d, _)| d.clone())
            .collect();

        for domain in &expired_domains {
            if let Some(entry) = domain_map.remove(domain) {
                ip_map.remove(&ip_to_u32(entry.ip));
            }
        }
    }

    /// Returns the number of active mappings.
    pub fn len(&self) -> usize {
        self.domain_map.read().unwrap().len()
    }

    /// Returns true if there are no active mappings.
    pub fn is_empty(&self) -> bool {
        self.domain_map.read().unwrap().is_empty()
    }

    fn allocate_ip(&self) -> Option<Ipv4Addr> {
        let mut index = self.next_index.write().unwrap();
        let ip_map = self.ip_map.read().unwrap();

        // Try to find an unused or expired slot
        for _ in 0..VIRTUAL_POOL_SIZE {
            let ip_u32 = VIRTUAL_POOL_START + *index;
            *index = (*index + 1) % VIRTUAL_POOL_SIZE;

            if let Some(entry) = ip_map.get(&ip_u32) {
                if entry.is_expired() {
                    return Some(u32_to_ip(ip_u32));
                }
            } else {
                return Some(u32_to_ip(ip_u32));
            }
        }

        None // Pool exhausted
    }
}

fn ip_to_u32(ip: Ipv4Addr) -> u32 {
    let octets = ip.octets();
    u32::from_be_bytes(octets)
}

fn u32_to_ip(n: u32) -> Ipv4Addr {
    Ipv4Addr::from(n.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_and_reverse() {
        let vdns = VirtualDns::new(None);
        let ip = vdns.resolve("example.com").unwrap();
        assert!(VirtualDns::is_virtual_ip(&ip));

        let domain = vdns.reverse_resolve(&ip).unwrap();
        assert_eq!(domain, "example.com");
    }

    #[test]
    fn test_same_domain_same_ip() {
        let vdns = VirtualDns::new(None);
        let ip1 = vdns.resolve("test.com").unwrap();
        let ip2 = vdns.resolve("test.com").unwrap();
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_different_domains_different_ips() {
        let vdns = VirtualDns::new(None);
        let ip1 = vdns.resolve("a.com").unwrap();
        let ip2 = vdns.resolve("b.com").unwrap();
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_is_virtual_ip() {
        assert!(VirtualDns::is_virtual_ip(&Ipv4Addr::new(198, 18, 0, 1)));
        assert!(VirtualDns::is_virtual_ip(&Ipv4Addr::new(198, 19, 255, 255)));
        assert!(!VirtualDns::is_virtual_ip(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!VirtualDns::is_virtual_ip(&Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_expired_entry() {
        let vdns = VirtualDns::new(Some(Duration::from_millis(1)));
        let ip = vdns.resolve("expired.com").unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert!(vdns.reverse_resolve(&ip).is_none());
    }
}
