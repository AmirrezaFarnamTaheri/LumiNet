//! # Autonomous Ingest & Ruleset Pipeline (Convergence Pass 2)
//!
//! Synthesizes Subscription Node Extraction (92), Node Deduplication (102),
//! Enhanced GeoIP Lookup (97), Composite Rule Snippet Compilation (96), and
//! Policy Ruleset Routing (105) into an automated node onboarding and traffic steering system.

use crate::proxy::node_ingest_deduplicator::{NodeIngestDeduplicator, ScrapedNode};
use crate::proxy::subscription_node_extractor::SubscriptionNodeExtractor;
use crate::routing::composite_rule_compiler::{CompositeRuleCompiler, RuleAction};
use crate::routing::enhanced_geoip_lookup::EnhancedGeoIpLookup;
use crate::routing::policy_ruleset_router::{PolicyRulesetRouter, PolicyVerdict};

pub struct AutonomousIngestPipeline {
    pub deduplicator: NodeIngestDeduplicator,
    pub geoip: EnhancedGeoIpLookup,
    pub rule_compiler: CompositeRuleCompiler,
    pub policy_router: PolicyRulesetRouter,
    pub total_ingested: usize,
}

impl AutonomousIngestPipeline {
    pub fn new(default_policy: PolicyVerdict) -> Self {
        Self {
            deduplicator: NodeIngestDeduplicator::new(),
            geoip: EnhancedGeoIpLookup::new(),
            rule_compiler: CompositeRuleCompiler::new(),
            policy_router: PolicyRulesetRouter::new(default_policy),
            total_ingested: 0,
        }
    }

    pub fn ingest_subscription_manifest(&mut self, source_name: &str, b64_manifest: &str) -> usize {
        let nodes = SubscriptionNodeExtractor::decode_subscription(b64_manifest);
        let mut added = 0;
        for node in nodes {
            let scraped = ScrapedNode {
                host: node.address,
                port: node.port,
                protocol: format!("{:?}", node.node_type).to_lowercase(),
                source: source_name.to_string(),
                ping_ms: 100, // default baseline
                is_alive: true,
            };
            if self.deduplicator.ingest_node(scraped) {
                added += 1;
            }
        }
        self.total_ingested += added;
        added
    }

    pub fn evaluate_egress(
        &mut self,
        target_domain: &str,
        dest_ip: Option<[u8; 4]>,
    ) -> PolicyVerdict {
        // 1. Composite rule check (highest specificity)
        if let Some(action) = self.rule_compiler.evaluate_domain(target_domain) {
            return match action {
                RuleAction::Direct => PolicyVerdict::Direct,
                RuleAction::Proxy => PolicyVerdict::Proxy,
                RuleAction::Reject => PolicyVerdict::Reject,
            };
        }

        // 2. IP GeoIP rule check if IP provided
        if let Some(ip) = dest_ip {
            if let Some(action) = self.rule_compiler.evaluate_ip(ip) {
                return match action {
                    RuleAction::Direct => PolicyVerdict::Direct,
                    RuleAction::Proxy => PolicyVerdict::Proxy,
                    RuleAction::Reject => PolicyVerdict::Reject,
                };
            }
            if let Some(cc) = self.geoip.lookup(ip) {
                if cc == "CN" {
                    return PolicyVerdict::Direct;
                }
            }
        }

        // 3. Fallback to policy router
        self.policy_router.resolve_domain(target_domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autonomous_ingest_pipeline() {
        let mut pipeline = AutonomousIngestPipeline::new(PolicyVerdict::Direct);

        pipeline.geoip.add_cidr([223, 5, 5, 0], 24, "CN");
        pipeline.rule_compiler.parse_line("DOMAIN-SUFFIX,google.com,PROXY");
        pipeline.rule_compiler.parse_line("DOMAIN-SUFFIX,ads.evil.com,REJECT");

        // Direct because CN GeoIP
        assert_eq!(
            pipeline.evaluate_egress("some-cn-site.cn", Some([223, 5, 5, 5])),
            PolicyVerdict::Direct
        );

        // Proxy because domain rule
        assert_eq!(
            pipeline.evaluate_egress("mail.google.com", None),
            PolicyVerdict::Proxy
        );

        // Reject because domain rule
        assert_eq!(
            pipeline.evaluate_egress("tracker.ads.evil.com", None),
            PolicyVerdict::Reject
        );
    }
}
