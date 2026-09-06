//! # Multi-Outbound Transparent Router & Dispatcher
//!
//! Evaluates inbound traffic against rule routing tables and dispatches across
//! named outbounds (direct, proxy, block, custom tag) with round-robin or hash balancing.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundPolicy {
    Direct,
    Proxy(String), // outbound tag
    Reject,
}

#[derive(Debug, Clone)]
pub struct OutboundRouteRule {
    pub pattern: String,
    pub is_suffix: bool,
    pub policy: OutboundPolicy,
}

pub struct MultiOutboundRouter {
    rules: Vec<OutboundRouteRule>,
    default_policy: OutboundPolicy,
    outbound_weights: HashMap<String, u32>,
    rr_counter: usize,
}

impl MultiOutboundRouter {
    pub fn new(default_policy: OutboundPolicy) -> Self {
        Self {
            rules: Vec::new(),
            default_policy,
            outbound_weights: HashMap::new(),
            rr_counter: 0,
        }
    }

    pub fn add_rule(&mut self, pattern: &str, is_suffix: bool, policy: OutboundPolicy) {
        self.rules.push(OutboundRouteRule {
            pattern: pattern.trim().to_lowercase(),
            is_suffix,
            policy,
        });
    }

    pub fn register_outbound(&mut self, tag: &str, weight: u32) {
        self.outbound_weights.insert(tag.to_string(), weight.max(1));
    }

    pub fn match_target(&self, host: &str) -> OutboundPolicy {
        let clean = host.trim().to_lowercase();
        for r in &self.rules {
            if r.is_suffix {
                if clean == r.pattern || clean.ends_with(&format!(".{}", r.pattern)) {
                    return r.policy.clone();
                }
            } else if clean == r.pattern {
                return r.policy.clone();
            }
        }
        self.default_policy.clone()
    }

    pub fn select_balanced_outbound<'a>(&mut self, outbounds: &'a [&'a str]) -> Option<&'a str> {
        if outbounds.is_empty() {
            return None;
        }
        let chosen = outbounds[self.rr_counter % outbounds.len()];
        self.rr_counter += 1;
        Some(chosen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_outbound_routing() {
        let mut router = MultiOutboundRouter::new(OutboundPolicy::Direct);
        router.add_rule("internal.corp", true, OutboundPolicy::Direct);
        router.add_rule("blocked-site.com", false, OutboundPolicy::Proxy("us-node-1".to_string()));
        router.add_rule("malware.net", true, OutboundPolicy::Reject);

        assert_eq!(router.match_target("app.internal.corp"), OutboundPolicy::Direct);
        assert_eq!(
            router.match_target("blocked-site.com"),
            OutboundPolicy::Proxy("us-node-1".to_string())
        );
        assert_eq!(router.match_target("sub.malware.net"), OutboundPolicy::Reject);
        assert_eq!(router.match_target("random-domain.io"), OutboundPolicy::Direct);

        let outbounds = ["node-a", "node-b", "node-c"];
        let sel1 = router.select_balanced_outbound(&outbounds).unwrap();
        let sel2 = router.select_balanced_outbound(&outbounds).unwrap();
        assert_ne!(sel1, sel2);
    }
}
