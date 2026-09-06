// Pure Rust implementation: Asynchronous Multi-Criteria Routing Rule Evaluator

use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr(Ipv4Addr, u8),
    Port(u16),
    PortRange(u16, u16),
    ProcessName(String),
    Match,
}

#[derive(Debug, Clone)]
pub struct EvaluatorRule {
    pub rule_type: RuleType,
    pub target_outbound: String,
    pub priority: u32,
}

#[derive(Debug, Clone, Default)]
pub struct TrafficContext {
    pub domain: Option<String>,
    pub destination_ip: Option<Ipv4Addr>,
    pub destination_port: u16,
    pub process_name: Option<String>,
}

pub struct AsyncRuleEvaluator {
    pub rules: Vec<EvaluatorRule>,
    pub default_outbound: String,
}

impl AsyncRuleEvaluator {
    pub fn new(default_outbound: impl Into<String>) -> Self {
        Self {
            rules: Vec::new(),
            default_outbound: default_outbound.into(),
        }
    }

    pub fn add_rule(&mut self, rule_type: RuleType, target_outbound: impl Into<String>, priority: u32) {
        self.rules.push(EvaluatorRule {
            rule_type,
            target_outbound: target_outbound.into(),
            priority,
        });

        // Sort descending by priority
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    pub fn evaluate(&self, ctx: &TrafficContext) -> String {
        for rule in &self.rules {
            if self.matches_rule(&rule.rule_type, ctx) {
                return rule.target_outbound.clone();
            }
        }
        self.default_outbound.clone()
    }

    fn matches_rule(&self, rule: &RuleType, ctx: &TrafficContext) -> bool {
        match rule {
            RuleType::Domain(exact) => {
                ctx.domain.as_ref().map(|d| d.eq_ignore_ascii_case(exact)).unwrap_or(false)
            }
            RuleType::DomainSuffix(suffix) => {
                ctx.domain.as_ref().map(|d| {
                    let d_lower = d.to_ascii_lowercase();
                    let s_lower = suffix.to_ascii_lowercase();
                    d_lower == s_lower || d_lower.ends_with(&format!(".{}", s_lower))
                }).unwrap_or(false)
            }
            RuleType::DomainKeyword(keyword) => {
                ctx.domain.as_ref().map(|d| {
                    d.to_ascii_lowercase().contains(&keyword.to_ascii_lowercase())
                }).unwrap_or(false)
            }
            RuleType::IpCidr(net, prefix) => {
                if let Some(dest_ip) = ctx.destination_ip {
                    let ip_u32 = u32::from(dest_ip);
                    let net_u32 = u32::from(*net);
                    let mask = if *prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
                    (ip_u32 & mask) == (net_u32 & mask)
                } else {
                    false
                }
            }
            RuleType::Port(port) => ctx.destination_port == *port,
            RuleType::PortRange(start, end) => {
                ctx.destination_port >= *start && ctx.destination_port <= *end
            }
            RuleType::ProcessName(proc) => {
                ctx.process_name.as_ref().map(|p| p.eq_ignore_ascii_case(proc)).unwrap_or(false)
            }
            RuleType::Match => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_and_suffix_evaluation() {
        let mut evaluator = AsyncRuleEvaluator::new("DIRECT");
        evaluator.add_rule(RuleType::DomainSuffix("google.com".to_string()), "PROXY", 100);
        evaluator.add_rule(RuleType::Domain("api.internal".to_string()), "LAN", 150);

        let mut ctx = TrafficContext::default();
        ctx.domain = Some("mail.google.com".to_string());
        assert_eq!(evaluator.evaluate(&ctx), "PROXY");

        ctx.domain = Some("api.internal".to_string());
        assert_eq!(evaluator.evaluate(&ctx), "LAN");

        ctx.domain = Some("wikipedia.org".to_string());
        assert_eq!(evaluator.evaluate(&ctx), "DIRECT");
    }

    #[test]
    fn test_ip_cidr_and_port_range() {
        let mut evaluator = AsyncRuleEvaluator::new("DIRECT");
        evaluator.add_rule(
            RuleType::IpCidr(Ipv4Addr::new(10, 0, 0, 0), 8),
            "INTERNAL_VPN",
            80,
        );
        evaluator.add_rule(RuleType::PortRange(8000, 9000), "DEV_CLUSTER", 50);

        let mut ctx = TrafficContext::default();
        ctx.destination_ip = Some(Ipv4Addr::new(10, 200, 1, 5));
        ctx.destination_port = 80;
        assert_eq!(evaluator.evaluate(&ctx), "INTERNAL_VPN");

        ctx.destination_ip = Some(Ipv4Addr::new(1, 1, 1, 1));
        ctx.destination_port = 8080;
        assert_eq!(evaluator.evaluate(&ctx), "DEV_CLUSTER");
    }
}
