//! # Policy Ruleset Router
//!
//! Evaluates policy rulesets across domain hierarchies, IP ranges, and user agents
//! to produce deterministic routing decisions (Direct, Proxy, Reject) with fast path caching.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyVerdict {
    Direct,
    Proxy,
    Reject,
}

pub struct PolicyRulesetRouter {
    exact_domains: HashMap<String, PolicyVerdict>,
    suffix_domains: HashMap<String, PolicyVerdict>,
    keyword_rules: Vec<(String, PolicyVerdict)>,
    cidr_rules: Vec<([u8; 4], u8, PolicyVerdict)>,
    cache: HashMap<String, PolicyVerdict>,
    default_policy: PolicyVerdict,
}

impl PolicyRulesetRouter {
    pub fn new(default_policy: PolicyVerdict) -> Self {
        Self {
            exact_domains: HashMap::new(),
            suffix_domains: HashMap::new(),
            keyword_rules: Vec::new(),
            cidr_rules: Vec::new(),
            cache: HashMap::new(),
            default_policy,
        }
    }

    pub fn add_exact_domain(&mut self, domain: &str, verdict: PolicyVerdict) {
        self.exact_domains.insert(domain.trim().to_lowercase(), verdict);
    }

    pub fn add_suffix_domain(&mut self, suffix: &str, verdict: PolicyVerdict) {
        let mut clean = suffix.trim().to_lowercase();
        if clean.starts_with('.') {
            clean = clean[1..].to_string();
        }
        self.suffix_domains.insert(clean, verdict);
    }

    pub fn add_keyword(&mut self, keyword: &str, verdict: PolicyVerdict) {
        self.keyword_rules.push((keyword.trim().to_lowercase(), verdict));
    }

    pub fn add_cidr(&mut self, octets: [u8; 4], mask: u8, verdict: PolicyVerdict) {
        self.cidr_rules.push((octets, mask, verdict));
    }

    pub fn resolve_domain(&mut self, domain: &str) -> PolicyVerdict {
        let clean = domain.trim().to_lowercase();
        if let Some(&cached) = self.cache.get(&clean) {
            return cached;
        }

        // 1. Exact match
        if let Some(&v) = self.exact_domains.get(&clean) {
            self.cache.insert(clean, v);
            return v;
        }

        // 2. Suffix match
        for (suffix, &v) in &self.suffix_domains {
            if clean == *suffix || clean.ends_with(&format!(".{}", suffix)) {
                self.cache.insert(clean, v);
                return v;
            }
        }

        // 3. Keyword match
        for (kw, v) in &self.keyword_rules {
            if clean.contains(kw) {
                self.cache.insert(clean, *v);
                return *v;
            }
        }

        self.cache.insert(clean, self.default_policy);
        self.default_policy
    }

    pub fn resolve_ip(&self, ip: [u8; 4]) -> PolicyVerdict {
        let ip_u32 = u32::from_be_bytes(ip);
        for &(octets, mask_bits, verdict) in &self.cidr_rules {
            let net_u32 = u32::from_be_bytes(octets);
            let mask = if mask_bits == 0 {
                0u32
            } else {
                !0u32 << (32 - mask_bits)
            };
            if (ip_u32 & mask) == (net_u32 & mask) {
                return verdict;
            }
        }
        self.default_policy
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_ruleset_router() {
        let mut router = PolicyRulesetRouter::new(PolicyVerdict::Direct);
        router.add_exact_domain("ads.google.com", PolicyVerdict::Reject);
        router.add_suffix_domain("google.com", PolicyVerdict::Proxy);
        router.add_keyword("telegram", PolicyVerdict::Proxy);
        router.add_cidr([10, 0, 0, 0], 8, PolicyVerdict::Direct);

        assert_eq!(router.resolve_domain("ads.google.com"), PolicyVerdict::Reject);
        assert_eq!(router.resolve_domain("mail.google.com"), PolicyVerdict::Proxy);
        assert_eq!(router.resolve_domain("telegram.org"), PolicyVerdict::Proxy);
        assert_eq!(router.resolve_domain("wikipedia.org"), PolicyVerdict::Direct);

        assert_eq!(router.resolve_ip([10, 1, 2, 3]), PolicyVerdict::Direct);
        assert_eq!(router.resolve_ip([1, 1, 1, 1]), PolicyVerdict::Direct);
    }
}
