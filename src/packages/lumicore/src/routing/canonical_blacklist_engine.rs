//! Canonical Blacklist Matching Engine
//!
//! Parses and evaluates canonical base64 and plaintext blacklist rule files
//! including Adblock/AutoProxy syntax (`||domain`, `|http://`, `@@whitelist`, `/regex/`).

use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchResult {
    Blocked(String),
    Whitelisted(String),
    DefaultDirect,
}

pub struct CanonicalBlacklistEngine {
    exact_blocked: HashSet<String>,
    domain_suffixes: HashSet<String>,
    whitelist_exact: HashSet<String>,
    whitelist_suffixes: HashSet<String>,
    keyword_matches: Vec<String>,
    total_rules: usize,
}

impl CanonicalBlacklistEngine {
    pub fn new() -> Self {
        Self {
            exact_blocked: HashSet::new(),
            domain_suffixes: HashSet::new(),
            whitelist_exact: HashSet::new(),
            whitelist_suffixes: HashSet::new(),
            keyword_matches: Vec::new(),
            total_rules: 0,
        }
    }

    pub fn parse_raw_rule(&mut self, line: &str) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('[') {
            return;
        }

        self.total_rules += 1;

        // Whitelist syntax: @@...
        if let Some(rule) = trimmed.strip_prefix("@@") {
            if let Some(dom) = rule.strip_prefix("||") {
                let clean = dom.trim_start_matches('.').to_lowercase();
                self.whitelist_suffixes.insert(clean);
            } else if let Some(dom) = rule.strip_prefix('|') {
                let clean = dom.trim_start_matches("http://").trim_start_matches("https://").to_lowercase();
                self.whitelist_exact.insert(clean);
            } else {
                let clean = rule.trim_start_matches('.').to_lowercase();
                self.whitelist_suffixes.insert(clean);
            }
            return;
        }

        // Domain suffix syntax: ||domain.com
        if let Some(dom) = trimmed.strip_prefix("||") {
            let clean = dom.trim_start_matches('.').to_lowercase();
            self.domain_suffixes.insert(clean);
            return;
        }

        // Exact url prefix: |http://...
        if let Some(dom) = trimmed.strip_prefix('|') {
            let clean = dom.trim_start_matches("http://").trim_start_matches("https://").to_lowercase();
            self.exact_blocked.insert(clean);
            return;
        }

        // Keyword rule
        if !trimmed.starts_with('/') {
            let clean = trimmed.trim_start_matches('.').to_lowercase();
            self.keyword_matches.push(clean);
        }
    }

    pub fn load_base64_ruleset(&mut self, base64_content: &str) -> Result<usize, &'static str> {
        let cleaned: String = base64_content.chars().filter(|c| !c.is_whitespace()).collect();
        let decoded_bytes = match base64_decode_internal(&cleaned) {
            Some(b) => b,
            None => return Err("Invalid base64 encoding in blacklist ruleset"),
        };

        let decoded_str = String::from_utf8_lossy(&decoded_bytes);
        let count_before = self.total_rules;
        for line in decoded_str.lines() {
            self.parse_raw_rule(line);
        }
        Ok(self.total_rules - count_before)
    }

    pub fn evaluate_target(&self, host: &str) -> MatchResult {
        let host_lower = host.trim().trim_end_matches('.').to_lowercase();

        // 1. Whitelist checks first
        if self.whitelist_exact.contains(&host_lower) {
            return MatchResult::Whitelisted(host_lower);
        }
        for wl_suffix in &self.whitelist_suffixes {
            if host_lower == *wl_suffix || host_lower.ends_with(&format!(".{}", wl_suffix)) {
                return MatchResult::Whitelisted(wl_suffix.clone());
            }
        }

        // 2. Exact block check
        if self.exact_blocked.contains(&host_lower) {
            return MatchResult::Blocked(host_lower);
        }

        // 3. Domain suffix check
        for bl_suffix in &self.domain_suffixes {
            if host_lower == *bl_suffix || host_lower.ends_with(&format!(".{}", bl_suffix)) {
                return MatchResult::Blocked(bl_suffix.clone());
            }
        }

        // 4. Keyword containment
        for kw in &self.keyword_matches {
            if host_lower.contains(kw) {
                return MatchResult::Blocked(kw.clone());
            }
        }

        MatchResult::DefaultDirect
    }

    pub fn total_rules_loaded(&self) -> usize {
        self.total_rules
    }
}

fn base64_decode_internal(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut buffer = 0u32;
    let mut bits = 0u32;
    let mut output = Vec::new();

    for &b in input.as_bytes() {
        if b == b'=' {
            break;
        }
        let val = match TABLE.iter().position(|&c| c == b) {
            Some(idx) => idx as u32,
            None => continue,
        };
        buffer = (buffer << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_blacklist_evaluation() {
        let mut engine = CanonicalBlacklistEngine::new();
        engine.parse_raw_rule("! Comment line");
        engine.parse_raw_rule("||blocked-site.com");
        engine.parse_raw_rule("|https://specific.com/login");
        engine.parse_raw_rule("@@||allowed.blocked-site.com");
        engine.parse_raw_rule("forbidden-kw");

        assert_eq!(
            engine.evaluate_target("blocked-site.com"),
            MatchResult::Blocked("blocked-site.com".to_string())
        );
        assert_eq!(
            engine.evaluate_target("sub.blocked-site.com"),
            MatchResult::Blocked("blocked-site.com".to_string())
        );
        assert_eq!(
            engine.evaluate_target("allowed.blocked-site.com"),
            MatchResult::Whitelisted("allowed.blocked-site.com".to_string())
        );
        assert_eq!(
            engine.evaluate_target("news-forbidden-kw-portal.org"),
            MatchResult::Blocked("forbidden-kw".to_string())
        );
        assert_eq!(
            engine.evaluate_target("innocent-site.net"),
            MatchResult::DefaultDirect
        );
    }
}
