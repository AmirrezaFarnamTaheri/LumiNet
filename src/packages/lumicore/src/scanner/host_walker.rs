//! # High-Performance IPv4 Subnet Host Walker & Target Normalizer
//!
//! Ported and elevated from `IP-Range-Scout-Android-main`.
//! Provides high-speed bitwise CIDR host enumeration, RFC 3021 /31 point-to-point support,
//! /32 host preservation, and strict input target parsing with comment/BOM stripping.

use std::net::Ipv4Addr;
use std::str::FromStr;

/// A parsed IPv4 CIDR prefix or host entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixEntry {
    pub prefix: String,
    pub network: Ipv4Addr,
    pub prefix_len: u8,
    pub total_addresses: u64,
    pub scan_hosts: u64,
}

impl PrefixEntry {
    /// Constructs a PrefixEntry from an IPv4 address and prefix length.
    pub fn new(ip: Ipv4Addr, prefix_len: u8) -> Self {
        let ip_u32 = u32::from(ip);
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let net_u32 = ip_u32 & mask;
        let network = Ipv4Addr::from(net_u32);
        let total = 1u64 << (32 - prefix_len);

        let scan_hosts = match prefix_len {
            32 => 1,
            31 => 2, // RFC 3021 point-to-point links have two host addresses
            _ => {
                if total > 2 {
                    total - 2 // Exclude network and broadcast
                } else {
                    total
                }
            }
        };

        Self {
            prefix: format!("{}/{}", network, prefix_len),
            network,
            prefix_len,
            total_addresses: total,
            scan_hosts,
        }
    }
}

/// Parses and normalizes raw user target inputs (comma/newline separated, BOM, comments).
pub struct TargetNormalizer;

impl TargetNormalizer {
    /// Normalizes raw target strings by splitting commas, trimming whitespace, and stripping UTF-8 BOM.
    pub fn normalize(raw: &str) -> Vec<String> {
        let clean = raw.trim_start_matches('\u{feff}');
        clean
            .lines()
            .flat_map(|l| l.split(','))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .map(|s| s.to_string())
            .collect()
    }

    /// Parses a slice of normalized target strings into unique `PrefixEntry` objects.
    pub fn parse_targets(targets: &[String]) -> Vec<PrefixEntry> {
        let mut entries = Vec::new();
        for target in targets {
            let parts: Vec<&str> = target.split('/').collect();
            if parts.is_empty() {
                continue;
            }

            if let Ok(ip) = Ipv4Addr::from_str(parts[0].trim()) {
                let prefix_len = if parts.len() > 1 {
                    parts[1].trim().parse::<u8>().unwrap_or(32).min(32)
                } else {
                    32
                };
                let entry = PrefixEntry::new(ip, prefix_len);
                if !entries.iter().any(|e: &PrefixEntry| e.prefix == entry.prefix) {
                    entries.push(entry);
                }
            }
        }
        entries
    }
}

/// Sequential or batched host walker over IPv4 CIDR prefixes.
pub struct HostWalker;

impl HostWalker {
    /// Enumerates all scan-eligible IPv4 host addresses for a given prefix.
    ///
    /// Respects RFC 3021 for /31 and /32, and skips network and broadcast addresses for <= /30.
    pub fn walk_prefix(entry: &PrefixEntry) -> Vec<Ipv4Addr> {
        let net_u32 = u32::from(entry.network);
        let total = entry.total_addresses;

        match entry.prefix_len {
            32 => vec![entry.network],
            31 => vec![Ipv4Addr::from(net_u32), Ipv4Addr::from(net_u32 + 1)],
            _ => {
                let mut hosts = Vec::with_capacity(entry.scan_hosts as usize);
                // Start at net_u32 + 1 (skip network address)
                // Stop before net_u32 + total - 1 (skip broadcast address)
                for offset in 1..(total - 1) {
                    hosts.push(Ipv4Addr::from(net_u32 + offset as u32));
                }
                hosts
            }
        }
    }

    /// Iterates across multiple prefixes and returns the flattened list of all scannable IPs.
    pub fn walk_all(entries: &[PrefixEntry]) -> Vec<Ipv4Addr> {
        let mut all_hosts = Vec::new();
        for entry in entries {
            all_hosts.extend(Self::walk_prefix(entry));
        }
        all_hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_normalizer() {
        let raw = "\u{feff}\n# comment\n192.168.1.1, 10.0.0.0/30\n\n172.16.0.1\n# another comment\n";
        let norm = TargetNormalizer::normalize(raw);
        assert_eq!(norm, vec!["192.168.1.1", "10.0.0.0/30", "172.16.0.1"]);

        let entries = TargetNormalizer::parse_targets(&norm);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1].prefix, "10.0.0.0/30");
        assert_eq!(entries[1].scan_hosts, 2);
    }

    #[test]
    fn test_host_walker_rfc3021_and_subnets() {
        // /30: 4 total, 2 usable (skips .0 and .3)
        let entry_30 = PrefixEntry::new(Ipv4Addr::new(192, 168, 1, 0), 30);
        let hosts_30 = HostWalker::walk_prefix(&entry_30);
        assert_eq!(hosts_30, vec![
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 2),
        ]);

        // /31: 2 total, 2 usable (RFC 3021, none skipped)
        let entry_31 = PrefixEntry::new(Ipv4Addr::new(10, 0, 0, 0), 31);
        let hosts_31 = HostWalker::walk_prefix(&entry_31);
        assert_eq!(hosts_31, vec![
            Ipv4Addr::new(10, 0, 0, 0),
            Ipv4Addr::new(10, 0, 0, 1),
        ]);

        // /32: single host
        let entry_32 = PrefixEntry::new(Ipv4Addr::new(8, 8, 8, 8), 32);
        let hosts_32 = HostWalker::walk_prefix(&entry_32);
        assert_eq!(hosts_32, vec![Ipv4Addr::new(8, 8, 8, 8)]);
    }
}
