//! # PAC Rule Generator
//!
//! Rule compilation engine that transforms domain rules, CIDR blocks, and patterns
//! into high-speed PAC script routines, Dnsmasq address entries, and in-engine evaluation trees.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PacAction {
    Direct,
    Proxy(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacRule {
    pub pattern: String,
    pub is_exact: bool,
    pub is_suffix: bool,
    pub action: PacAction,
}

pub struct PacRuleGenerator {
    rules: Vec<PacRule>,
    default_action: PacAction,
}

impl PacRuleGenerator {
    pub fn new(default_action: PacAction) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
        }
    }

    pub fn add_rule(&mut self, pattern: &str, action: PacAction) {
        let trimmed = pattern.trim().to_lowercase();
        let (is_exact, is_suffix, pat) = if let Some(p) = trimmed.strip_prefix("||") {
            (false, true, p.to_string())
        } else if let Some(p) = trimmed.strip_prefix('|') {
            (true, false, p.to_string())
        } else {
            (false, false, trimmed)
        };

        self.rules.push(PacRule {
            pattern: pat,
            is_exact,
            is_suffix,
            action,
        });
    }

    pub fn evaluate_host(&self, host: &str) -> PacAction {
        let host_lower = host.to_lowercase();
        for rule in &self.rules {
            if rule.is_exact {
                if host_lower == rule.pattern {
                    return rule.action.clone();
                }
            } else if rule.is_suffix {
                if host_lower == rule.pattern || host_lower.ends_with(&format!(".{}", rule.pattern)) {
                    return rule.action.clone();
                }
            } else if host_lower.contains(&rule.pattern) {
                return rule.action.clone();
            }
        }
        self.default_action.clone()
    }

    pub fn generate_pac_script(&self) -> String {
        let mut domains_js = Vec::new();
        for rule in &self.rules {
            if let PacAction::Proxy(ref p) = rule.action {
                domains_js.push(format!("  \"{}\": \"PROXY {}\",", rule.pattern, p));
            }
        }

        let default_ret = match &self.default_action {
            PacAction::Direct => "\"DIRECT\"",
            PacAction::Proxy(p) => &format!("\"PROXY {}\"", p),
        };

        format!(
            r#"// LumiNet Generated PAC
var rules = {{
{}
}};

function FindProxyForURL(url, host) {{
    for (var d in rules) {{
        if (dnsDomainIs(host, d) || host === d) {{
            return rules[d];
        }}
    }}
    return {};
}}
"#,
            domains_js.join("\n"),
            default_ret
        )
    }

    pub fn generate_dnsmasq_config(&self, dns_server: &str) -> String {
        let mut lines = Vec::new();
        for rule in &self.rules {
            lines.push(format!("server=/{}/{}", rule.pattern, dns_server));
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pac_evaluation_and_generation() {
        let mut gen = PacRuleGenerator::new(PacAction::Direct);
        gen.add_rule("||google.com", PacAction::Proxy("127.0.0.1:1080".to_string()));
        gen.add_rule("|exact.internal", PacAction::Direct);

        assert_eq!(
            gen.evaluate_host("mail.google.com"),
            PacAction::Proxy("127.0.0.1:1080".to_string())
        );
        assert_eq!(
            gen.evaluate_host("google.com"),
            PacAction::Proxy("127.0.0.1:1080".to_string())
        );
        assert_eq!(gen.evaluate_host("exact.internal"), PacAction::Direct);
        assert_eq!(gen.evaluate_host("other.internal"), PacAction::Direct);

        let script = gen.generate_pac_script();
        assert!(script.contains("FindProxyForURL"));
        assert!(script.contains("google.com"));

        let dnsmasq = gen.generate_dnsmasq_config("8.8.8.8");
        assert!(dnsmasq.contains("server=/google.com/8.8.8.8"));
    }
}
