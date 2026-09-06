//! # Domain Blocklist Engine
//!
//! High-performance domain blocking for DNS filtering.
//! Supports multiple blocklist formats and whitelist overlays.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read};
use std::sync::Arc;

/// Blocklist format types.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlocklistFormat {
    /// Plain domain list (one per line)
    Plain,
    /// Hosts file format (0.0.0.0 domain or 127.0.0.1 domain)
    Hosts,
    /// Adblock Plus syntax (||domain^)
    Adblock,
}

/// Domain blocklist engine with fast lookup.
#[derive(Clone)]
pub struct DomainBlocklist {
    blocked: Arc<HashSet<String>>,
    whitelist: Arc<HashSet<String>>,
    stats: BlocklistStats,
}

#[derive(Debug, Clone, Default)]
pub struct BlocklistStats {
    pub total_blocked: usize,
    pub total_whitelisted: usize,
    pub sources_loaded: usize,
}

impl Default for DomainBlocklist {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainBlocklist {
    /// Creates a new empty blocklist.
    pub fn new() -> Self {
        Self {
            blocked: Arc::new(HashSet::new()),
            whitelist: Arc::new(HashSet::new()),
            stats: BlocklistStats::default(),
        }
    }

    /// Loads domains from a reader, auto-detecting format.
    pub fn load_from_reader<R: Read>(&mut self, reader: R, format: BlocklistFormat) -> usize {
        let buf = BufReader::new(reader);
        let mut count = 0;

        for line in buf.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let line = line.trim().to_lowercase();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }

            if let Some(domain) = parse_domain(&line, format) {
                if !domain.is_empty() && is_valid_domain(&domain) {
                    // Check whitelist before adding
                    if !self.whitelist.contains(&domain) {
                        Arc::make_mut(&mut self.blocked).insert(domain);
                        count += 1;
                    }
                }
            }
        }

        self.stats.total_blocked = self.blocked.len();
        self.stats.sources_loaded += 1;
        count
    }

    /// Loads a whitelist from a reader.
    pub fn load_whitelist<R: Read>(&mut self, reader: R) -> usize {
        let buf = BufReader::new(reader);
        let mut count = 0;

        for line in buf.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let line = line.trim().to_lowercase();

            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }

            if let Some(domain) = parse_domain(&line, BlocklistFormat::Plain) {
                if !domain.is_empty() {
                    Arc::make_mut(&mut self.whitelist).insert(domain);
                    count += 1;
                }
            }
        }

        // Remove whitelisted domains from blocked set
        let whitelist = self.whitelist.clone();
        let blocked = Arc::make_mut(&mut self.blocked);
        blocked.retain(|d| !whitelist.contains(d));

        self.stats.total_whitelisted = self.whitelist.len();
        self.stats.total_blocked = self.blocked.len();
        count
    }

    /// Checks if a domain is blocked.
    pub fn is_blocked(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_lowercase();

        // Check whitelist first
        if self.whitelist.contains(&domain) {
            return false;
        }

        // Check exact match
        if self.blocked.contains(&domain) {
            return true;
        }

        // Check parent domains (e.g., ads.example.com matches block on example.com)
        // This is intentionally not done for performance - use exact matches
        false
    }

    /// Returns blocklist statistics.
    pub fn stats(&self) -> &BlocklistStats {
        &self.stats
    }

    /// Returns the number of blocked domains.
    pub fn len(&self) -> usize {
        self.blocked.len()
    }

    /// Returns true if the blocklist is empty.
    pub fn is_empty(&self) -> bool {
        self.blocked.is_empty()
    }
}

/// Parses a domain from a line based on format.
fn parse_domain(line: &str, format: BlocklistFormat) -> Option<String> {
    match format {
        BlocklistFormat::Plain => {
            let domain = line.trim();
            if domain.is_empty() {
                None
            } else {
                Some(domain.to_string())
            }
        }
        BlocklistFormat::Hosts => {
            // "0.0.0.0 domain" or "127.0.0.1 domain"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                Some(parts[1].to_string())
            } else {
                None
            }
        }
        BlocklistFormat::Adblock => {
            // "||domain^"
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("||") {
                let domain = rest.trim_end_matches('^');
                Some(domain.to_string())
            } else {
                None
            }
        }
    }
}

/// Validates that a string looks like a domain name.
fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    // Must contain at least one dot
    if !domain.contains('.') {
        return false;
    }
    // Must not start or end with hyphen or dot
    if domain.starts_with('-') || domain.ends_with('-') {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    // Each label must be valid
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        // Only alphanumeric and hyphen
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_plain() {
        assert_eq!(
            parse_domain("example.com", BlocklistFormat::Plain),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_parse_hosts() {
        assert_eq!(
            parse_domain("0.0.0.0 ads.example.com", BlocklistFormat::Hosts),
            Some("ads.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_adblock() {
        assert_eq!(
            parse_domain("||ads.example.com^", BlocklistFormat::Adblock),
            Some("ads.example.com".to_string())
        );
    }

    #[test]
    fn test_valid_domain() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.domain.example.com"));
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("nodot"));
        assert!(!is_valid_domain("-bad.com"));
        assert!(!is_valid_domain("bad-.com"));
    }

    #[test]
    fn test_blocklist_lookup() {
        let mut bl = DomainBlocklist::new();
        let data = "ads.example.com\ntracker.other.com\n# comment\n\n";
        bl.load_from_reader(data.as_bytes(), BlocklistFormat::Plain);

        assert!(bl.is_blocked("ads.example.com"));
        assert!(bl.is_blocked("tracker.other.com"));
        assert!(!bl.is_blocked("safe.example.com"));
    }

    #[test]
    fn test_whitelist_override() {
        let mut bl = DomainBlocklist::new();
        let blocklist = "ads.example.com\ntracker.other.com\n";
        bl.load_from_reader(blocklist.as_bytes(), BlocklistFormat::Plain);

        let whitelist = "ads.example.com\n";
        bl.load_whitelist(whitelist.as_bytes());

        assert!(!bl.is_blocked("ads.example.com"));
        assert!(bl.is_blocked("tracker.other.com"));
    }

    #[test]
    fn test_hosts_format() {
        let mut bl = DomainBlocklist::new();
        let data = "0.0.0.0 ads.example.com\n127.0.0.1 tracker.com\n";
        bl.load_from_reader(data.as_bytes(), BlocklistFormat::Hosts);

        assert!(bl.is_blocked("ads.example.com"));
        assert!(bl.is_blocked("tracker.com"));
    }
}
