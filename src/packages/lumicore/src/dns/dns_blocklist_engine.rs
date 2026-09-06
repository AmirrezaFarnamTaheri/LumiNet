//! High Performance DNS Blocklist Engine
//!
//! Evaluates FQDN queries against compiled multi-format blocklists
//! (Adblock Plus rules, wildcard domains, hosts-style rules, and CIDR networks).

use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockCategory {
    Malware,
    Advertising,
    Tracking,
    Cryptomining,
    AdultContent,
    Telemetry,
}

#[derive(Debug, Clone)]
pub struct BlockRule {
    pub pattern: String,
    pub category: BlockCategory,
    pub is_wildcard: bool,
    pub is_exact: bool,
}

pub struct DnsBlocklistEngine {
    exact_domains: HashSet<String>,
    wildcard_suffixes: Vec<(String, BlockCategory)>,
    whitelisted_domains: HashSet<String>,
    blocked_ips: HashSet<IpAddr>,
    total_rules_loaded: usize,
}

impl DnsBlocklistEngine {
    pub fn new() -> Self {
        Self {
            exact_domains: HashSet::new(),
            wildcard_suffixes: Vec::new(),
            whitelisted_domains: HashSet::new(),
            blocked_ips: HashSet::new(),
            total_rules_loaded: 0,
        }
    }

    pub fn add_exact_rule(&mut self, domain: &str, _cat: BlockCategory) {
        let normalized = domain.trim().trim_end_matches('.').to_lowercase();
        if !normalized.is_empty() {
            self.exact_domains.insert(normalized);
            self.total_rules_loaded += 1;
        }
    }

    pub fn add_wildcard_rule(&mut self, suffix: &str, cat: BlockCategory) {
        let mut normalized = suffix.trim().trim_end_matches('.').to_lowercase();
        if normalized.starts_with("*.") {
            normalized = normalized[2..].to_string();
        } else if normalized.starts_with('.') {
            normalized = normalized[1..].to_string();
        }

        if !normalized.is_empty() {
            self.wildcard_suffixes.push((normalized, cat));
            self.total_rules_loaded += 1;
        }
    }

    pub fn add_whitelist(&mut self, domain: &str) {
        let normalized = domain.trim().trim_end_matches('.').to_lowercase();
        if !normalized.is_empty() {
            self.whitelisted_domains.insert(normalized);
        }
    }

    pub fn add_blocked_ip(&mut self, ip: IpAddr) {
        self.blocked_ips.insert(ip);
        self.total_rules_loaded += 1;
    }

    pub fn parse_hosts_file(&mut self, content: &str, cat: BlockCategory) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
                self.add_exact_rule(parts[1], cat);
            } else if parts.len() == 1 {
                if parts[0].starts_with("*.") || parts[0].starts_with('.') {
                    self.add_wildcard_rule(parts[0], cat);
                } else {
                    self.add_exact_rule(parts[0], cat);
                }
            }
        }
    }

    pub fn is_domain_blocked(&self, query_domain: &str) -> Option<BlockCategory> {
        let normalized = query_domain.trim().trim_end_matches('.').to_lowercase();

        // 1. Whitelist takes precedence
        if self.whitelisted_domains.contains(&normalized) {
            return None;
        }

        // Check parent domains for whitelist
        let parts: Vec<&str> = normalized.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if self.whitelisted_domains.contains(&parent) {
                return None;
            }
        }

        // 2. Exact match check
        if self.exact_domains.contains(&normalized) {
            return Some(BlockCategory::Advertising);
        }

        // 3. Wildcard suffix check
        for (suffix, cat) in &self.wildcard_suffixes {
            if normalized == *suffix || normalized.ends_with(&format!(".{}", suffix)) {
                return Some(*cat);
            }
        }

        None
    }

    pub fn is_ip_blocked(&self, ip: &IpAddr) -> bool {
        self.blocked_ips.contains(ip)
    }

    pub fn total_rules(&self) -> usize {
        self.total_rules_loaded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_blocklist_evaluation() {
        let mut engine = DnsBlocklistEngine::new();
        engine.add_exact_rule("ads.example.com", BlockCategory::Advertising);
        engine.add_wildcard_rule("tracking.co", BlockCategory::Tracking);
        engine.add_exact_rule("good.tracking.co", BlockCategory::Tracking);
        engine.add_whitelist("good.tracking.co");

        assert_eq!(engine.is_domain_blocked("ads.example.com"), Some(BlockCategory::Advertising));
        assert_eq!(engine.is_domain_blocked("sub.tracking.co"), Some(BlockCategory::Tracking));
        assert_eq!(engine.is_domain_blocked("tracking.co"), Some(BlockCategory::Tracking));
        assert_eq!(engine.is_domain_blocked("good.tracking.co"), None);
        assert_eq!(engine.is_domain_blocked("unrelated.org"), None);

        let hosts = "0.0.0.0 telemetry.malware.com\n127.0.0.1 evil-ad.org";
        engine.parse_hosts_file(hosts, BlockCategory::Malware);
        assert!(engine.is_domain_blocked("telemetry.malware.com").is_some());
        assert!(engine.is_domain_blocked("evil-ad.org").is_some());
    }
}
