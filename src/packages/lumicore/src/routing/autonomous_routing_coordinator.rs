//! # Autonomous Routing Coordinator (Second-Order Convergence)
//!
//! Synthesizes PAC compilers, AutoProxy rule engines, Sing-Box rule sets,
//! RouterOS tables, and dynamic gateway routing into a unified high-order
//! decision pipeline.

use crate::routing::autoproxy_ruleset_matcher::{AutoProxyAction, AutoProxyRulesetMatcher};
use crate::routing::pac_script_compiler::{PacMatchResult, PacProxyMode, PacScriptCompiler};
use crate::routing::singbox_ruleset_compiler::{SingboxAction, SingboxRulesetCompiler};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingVerdict {
    Direct,
    Proxy(String),
    Block,
}

#[derive(Debug, Clone)]
pub struct AutonomousRoutingCoordinator {
    pac: PacScriptCompiler,
    autoproxy: AutoProxyRulesetMatcher,
    singbox: SingboxRulesetCompiler,
    default_proxy_tag: String,
}

impl AutonomousRoutingCoordinator {
    pub fn new(default_proxy_tag: &str) -> Self {
        Self {
            pac: PacScriptCompiler::new(PacProxyMode::Proxy(default_proxy_tag.to_string())),
            autoproxy: AutoProxyRulesetMatcher::new(),
            singbox: SingboxRulesetCompiler::new(),
            default_proxy_tag: default_proxy_tag.to_string(),
        }
    }

    pub fn pac_mut(&mut self) -> &mut PacScriptCompiler {
        &mut self.pac
    }

    pub fn autoproxy_mut(&mut self) -> &mut AutoProxyRulesetMatcher {
        &mut self.autoproxy
    }

    pub fn singbox_mut(&mut self) -> &mut SingboxRulesetCompiler {
        &mut self.singbox
    }

    /// Evaluates target URL or hostname through the multi-tiered decision hierarchy:
    /// Tier 1: AutoProxy rules (whitelist or explicit bypass rules)
    /// Tier 2: Sing-Box rules (GeoIP/GeoSite/keyword)
    /// Tier 3: PAC rules (prefix CIDR / suffix match)
    /// Tier 4: Fallback to default proxy tag
    pub fn evaluate(&self, target: &str) -> RoutingVerdict {
        // Tier 1: AutoProxy
        if let Some(action) = self.autoproxy.match_url(target) {
            return match action {
                AutoProxyAction::Direct => RoutingVerdict::Direct,
                AutoProxyAction::Proxy => RoutingVerdict::Proxy(self.default_proxy_tag.clone()),
            };
        }

        // Tier 2: Sing-box rules
        if let Some(sb_action) = self.singbox.match_domain(target) {
            return match sb_action {
                SingboxAction::Direct => RoutingVerdict::Direct,
                SingboxAction::Proxy(tag) => RoutingVerdict::Proxy(tag),
                SingboxAction::Block => RoutingVerdict::Block,
            };
        }

        // Tier 3: PAC
        match self.pac.evaluate_domain(target) {
            PacMatchResult::Direct => RoutingVerdict::Direct,
            PacMatchResult::Proxy(p) => RoutingVerdict::Proxy(p),
            PacMatchResult::DefaultAction => RoutingVerdict::Proxy(self.default_proxy_tag.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::singbox_ruleset_compiler::SingboxRuleType;

    #[test]
    fn test_autonomous_routing_coordinator_hierarchy() {
        let mut coord = AutonomousRoutingCoordinator::new("US-Node-01");

        // Add AutoProxy whitelist rule
        coord.autoproxy_mut().parse_line("@@||internal.corp");

        // Add Sing-box rule
        coord.singbox_mut().add_rule(
            SingboxRuleType::DomainSuffix("ad-tracker.com".to_string()),
            SingboxAction::Block,
        );

        // Add PAC rule
        coord.pac_mut().add_direct_domain("qq.com");

        // Verification
        assert_eq!(coord.evaluate("https://internal.corp/app"), RoutingVerdict::Direct);
        assert_eq!(coord.evaluate("ad-tracker.com"), RoutingVerdict::Block);
        assert_eq!(coord.evaluate("qq.com"), RoutingVerdict::Direct);
        assert_eq!(coord.evaluate("random-unknown.com"), RoutingVerdict::Proxy("US-Node-01".to_string()));
    }
}
