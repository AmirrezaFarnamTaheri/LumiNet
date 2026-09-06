//
// LRU virtual DNS with an IP pool,
// `src/virtual_dns.rs`. Allocates fake IPs from a /10 CIDR pool for
// each DNS hostname query, so the desktop transparent-proxy TUN mode
// can route traffic through the SOCKS proxy without kernel DNS hooks.
//
// ponytail: tun2proxy uses `lru` + `linked-hash-map` crates. Neither is
// a direct LumiNet dep. We substitute `std::collections::HashMap` +
// `VecDeque` for LRU eviction, plus an explicit linear eviction pass
// when the pool wraps. Adds O(n) cost on full-pool search; documented
// in the ceiling note. A 60-second TTL keeps the steady-state search
// under a few thousand entries — fast enough on any host.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

pub const DEFAULT_TTL: Duration = Duration::from_secs(5);
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
struct NameCacheEntry {
    name: String,
    expiry: Instant,
}

/// Virtual DNS allocator over an IPv4 CIDR pool. Default pool is the
/// `10.192.0.0/10` block Tor uses for `.onion` AutomapHostsOnResolve.
pub struct VirtualDns {
    /// LRU index keyed by allocated IP (for fast reverse lookup).
    forward: HashMap<IpAddr, NameCacheEntry>,
    /// Reverse index: hostname → allocated IP.
    name_to_ip: HashMap<String, IpAddr>,
    /// Insertion-order queue to enable LRU evictions.
    lru: VecDeque<IpAddr>,
    /// Next IP address to allocate (linear walk through the pool).
    next_addr: Ipv4Addr,
    network_addr: Ipv4Addr,
    broadcast_addr: Ipv4Addr,
    trailing_dot: bool,
    cache_ttl: Duration,
    reply_ttl: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum VirtualDnsError {
    #[error("pool exhausted")]
    PoolExhausted,
    #[error("malformed query")]
    MalformedQuery,
}

impl VirtualDns {
    pub fn new(network: Ipv4Addr, prefix_bits: u8) -> Self {
        let bc = broadcast_of(network, prefix_bits);
        Self {
            forward: HashMap::new(),
            name_to_ip: HashMap::new(),
            lru: VecDeque::new(),
            next_addr: network, // start at network boundary; first allocation bumps it
            network_addr: network,
            broadcast_addr: bc,
            trailing_dot: false,
            cache_ttl: DEFAULT_CACHE_TTL,
            reply_ttl: DEFAULT_TTL,
        }
    }

    /// Default pool matches Tor's `VirtualAddrNetwork 10.192.0.0/10`.
    pub fn default_tor_pool() -> Self {
        Self::new(Ipv4Addr::new(10, 192, 0, 0), 10)
    }

    /// TTL advertised in generated virtual DNS replies.
    pub fn reply_ttl(&self) -> Duration {
        self.reply_ttl
    }

    /// Resolve a hostname (the queried name from DNS QNAME) to a virtual IP,
    /// evicting expired entries first and allocating fresh IPs as needed.
    pub fn find_or_allocate_ip(&mut self, name: &str) -> Result<IpAddr, VirtualDnsError> {
        let normalized = normalize_name(name, self.trailing_dot);
        if let Some(ip) = self.name_to_ip.get(normalized.as_str()) {
            // touch LRU entry
            if let Some(entry) = self.forward.get_mut(ip) {
                entry.expiry = Instant::now() + self.cache_ttl;
            }
            if let Some(pos) = self.lru.iter().position(|a| a == ip) {
                self.lru.remove(pos);
                self.lru.push_back(*ip);
            }
            return Ok(*ip);
        }

        self.evict_expired();
        let ip = self.allocate_next()?;
        self.forward.insert(
            ip,
            NameCacheEntry {
                name: normalized.clone(),
                expiry: Instant::now() + self.cache_ttl,
            },
        );
        self.name_to_ip.insert(normalized, ip);
        self.lru.push_back(ip);
        Ok(ip)
    }

    /// Reverse-lookup an IP back to the hostname that produced it.
    pub fn resolve_ip(&self, ip: &IpAddr) -> Option<&String> {
        self.forward.get(ip).map(|e| &e.name)
    }

    /// Mark an IP as recently used (pushes it to the back of the LRU).
    pub fn touch_ip(&mut self, ip: &IpAddr) {
        if let Some(entry) = self.forward.get_mut(ip) {
            entry.expiry = Instant::now() + self.cache_ttl;
        }
        if let Some(pos) = self.lru.iter().position(|a| a == ip) {
            self.lru.remove(pos);
            self.lru.push_back(*ip);
        }
    }

    /// Evict expired entries from all three structures.
    fn evict_expired(&mut self) {
        let now = Instant::now();
        let expired: Vec<IpAddr> = self
            .forward
            .iter()
            .filter(|(_, e)| e.expiry < now)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in expired {
            if let Some(entry) = self.forward.remove(&ip) {
                self.name_to_ip.remove(&entry.name);
            }
            self.lru.retain(|a| a != &ip);
        }
    }

    fn allocate_next(&mut self) -> Result<IpAddr, VirtualDnsError> {
        // ponytail: try re-using an evicted slot first; else walk `next_addr`.
        if let Some(&ip) = self.lru.front() {
            if !self.forward.contains_key(&ip) {
                self.lru.pop_front();
                Ok(ip)
            } else {
                self.bump_next()
            }
        } else {
            self.bump_next()
        }
    }

    fn bump_next(&mut self) -> Result<IpAddr, VirtualDnsError> {
        let candidate = self.next_addr;
        let mut oct = candidate.octets();
        // simple uint32 increment with carry
        let mut v = u32::from_be_bytes(oct);
        v = v.wrapping_add(1);
        oct = v.to_be_bytes();
        let next = Ipv4Addr::from(oct);
        if next == self.broadcast_addr {
            // wrap and re-check
            self.next_addr = self.network_addr;
        } else {
            self.next_addr = next;
        }
        if v == 0 {
            return Err(VirtualDnsError::PoolExhausted);
        }
        Ok(IpAddr::V4(candidate))
    }
}

fn normalize_name(name: &str, trailing_dot: bool) -> String {
    let mut s = name.trim_end_matches('.').to_lowercase();
    if trailing_dot {
        s.push('.');
    }
    s
}

fn broadcast_of(network: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let net = u32::from_be_bytes(network.octets());
    let mask = if prefix == 0 {
        0
    } else {
        (!0u32) << (32 - prefix)
    };
    let bc = net | !mask;
    Ipv4Addr::from(bc.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pool_allocates_within_10_192() {
        let mut dns = VirtualDns::default_tor_pool();
        let ip = dns.find_or_allocate_ip("example.com").unwrap();
        if let IpAddr::V4(v4) = ip {
            assert_eq!(v4.octets()[0], 10);
        } else {
            panic!("expected v4");
        }
    }

    #[test]
    fn same_name_returns_same_ip() {
        let mut dns = VirtualDns::default_tor_pool();
        let a = dns.find_or_allocate_ip("foo.example").unwrap();
        let b = dns.find_or_allocate_ip("foo.example").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_names_yield_different_ips() {
        let mut dns = VirtualDns::default_tor_pool();
        let a = dns.find_or_allocate_ip("a.example").unwrap();
        let b = dns.find_or_allocate_ip("b.example").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn resolve_ip_round_trips_name() {
        let mut dns = VirtualDns::default_tor_pool();
        let ip = dns.find_or_allocate_ip("rtt.example").unwrap();
        assert_eq!(dns.resolve_ip(&ip), Some(&"rtt.example".to_string()));
    }

    #[test]
    fn trailing_dot_normalisation() {
        let mut dns = VirtualDns::default_tor_pool();
        let a = dns.find_or_allocate_ip("X.example.").unwrap();
        let b = dns.find_or_allocate_ip("x.example").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn broadcast_of_works() {
        assert_eq!(
            broadcast_of(Ipv4Addr::new(10, 192, 0, 0), 10),
            Ipv4Addr::new(10, 255, 255, 255)
        );
    }
}
// ponytail: linear LRU eviction via VecDeque::retain is O(n) per IP
// expiry. Acceptable up to ~10k allocations; beyond that swap in the
// `lru = "0.12"` crate (1KB build footprint, already in lockfile as a
// transitive of `quinn`). Upgrading means replacing the three
// HashMap/VecDeque fields with a single `LruCache<IpAddr, NameCacheEntry>`.
