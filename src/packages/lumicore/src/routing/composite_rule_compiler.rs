//! # Composite Rule Snippet Compiler
//!
//! Parses and compiles ruleset snippets containing DOMAIN, DOMAIN-SUFFIX,
//! DOMAIN-KEYWORD, IP-CIDR, and USER-AGENT matching directives into an optimized evaluator.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    Direct,
    Proxy,
    Reject,
}

#[derive(Debug, Clone)]
pub enum RuleCriterion {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr { ip_octets: [u8; 4], mask_bits: u8 },
    UserAgent(String),
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub criterion: RuleCriterion,
    pub action: RuleAction,
}

pub struct CompositeRuleCompiler {
    rules: Vec<CompiledRule>,
}

impl CompositeRuleCompiler {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn parse_line(&mut self, line: &str) -> bool {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            return false;
        }

        let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim()).collect();
        if parts.len() < 3 {
            return false;
        }

        let r_type = parts[0].to_uppercase();
        let pattern = parts[1];
        let action = match parts[2].to_uppercase().as_str() {
            "DIRECT" => RuleAction::Direct,
            "PROXY" => RuleAction::Proxy,
            "REJECT" => RuleAction::Reject,
            _ => return false,
        };

        let criterion = match r_type.as_str() {
            "DOMAIN" => RuleCriterion::Domain(pattern.to_lowercase()),
            "DOMAIN-SUFFIX" => RuleCriterion::DomainSuffix(pattern.to_lowercase()),
            "DOMAIN-KEYWORD" => RuleCriterion::DomainKeyword(pattern.to_lowercase()),
            "IP-CIDR" => {
                let (ip_str, mask_str) = match pattern.split_once('/') {
                    Some((i, m)) => (i, m),
                    None => (pattern, "32"),
                };
                let octets = match parse_ipv4(ip_str) {
                    Some(o) => o,
                    None => return false,
                };
                let mask = match mask_str.parse::<u8>() {
                    Ok(m) => m,
                    Err(_) => return false,
                };
                RuleCriterion::IpCidr {
                    ip_octets: octets,
                    mask_bits: mask,
                }
            }
            "USER-AGENT" => RuleCriterion::UserAgent(pattern.to_string()),
            _ => return false,
        };

        self.rules.push(CompiledRule { criterion, action });
        true
    }

    pub fn evaluate_domain(&self, domain: &str) -> Option<RuleAction> {
        let clean = domain.trim().to_lowercase();
        for r in &self.rules {
            match &r.criterion {
                RuleCriterion::Domain(d) => {
                    if clean == *d {
                        return Some(r.action.clone());
                    }
                }
                RuleCriterion::DomainSuffix(suf) => {
                    if clean == *suf || clean.ends_with(&format!(".{}", suf)) {
                        return Some(r.action.clone());
                    }
                }
                RuleCriterion::DomainKeyword(kw) => {
                    if clean.contains(kw) {
                        return Some(r.action.clone());
                    }
                }
                _ => {}
            }
        }
        None
    }

    pub fn evaluate_ip(&self, ip_octets: [u8; 4]) -> Option<RuleAction> {
        let ip_u32 = u32::from_be_bytes(ip_octets);
        for r in &self.rules {
            if let RuleCriterion::IpCidr { ip_octets: net_octets, mask_bits } = &r.criterion {
                let net_u32 = u32::from_be_bytes(*net_octets);
                let mask = if *mask_bits == 0 {
                    0u32
                } else {
                    !0u32 << (32 - mask_bits)
                };
                if (ip_u32 & mask) == (net_u32 & mask) {
                    return Some(r.action.clone());
                }
            }
        }
        None
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    Some([
        parts[0].parse::<u8>().ok()?,
        parts[1].parse::<u8>().ok()?,
        parts[2].parse::<u8>().ok()?,
        parts[3].parse::<u8>().ok()?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_composite_rule_compiler() {
        let mut compiler = CompositeRuleCompiler::new();
        assert!(compiler.parse_line("DOMAIN-SUFFIX,apple.com,DIRECT"));
        assert!(compiler.parse_line("DOMAIN-KEYWORD,google,PROXY"));
        assert!(compiler.parse_line("IP-CIDR,192.168.0.0/16,DIRECT"));
        assert!(compiler.parse_line("IP-CIDR,10.0.0.0/8,REJECT"));

        assert_eq!(compiler.evaluate_domain("music.apple.com"), Some(RuleAction::Direct));
        assert_eq!(compiler.evaluate_domain("www.google.com.hk"), Some(RuleAction::Proxy));
        assert_eq!(compiler.evaluate_domain("unrelated.org"), None);

        assert_eq!(compiler.evaluate_ip([192, 168, 1, 100]), Some(RuleAction::Direct));
        assert_eq!(compiler.evaluate_ip([10, 5, 0, 1]), Some(RuleAction::Reject));
        assert_eq!(compiler.evaluate_ip([8, 8, 8, 8]), None);
    }
}
