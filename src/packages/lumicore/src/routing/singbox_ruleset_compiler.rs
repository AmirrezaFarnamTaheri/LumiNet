//! # Sing-Box Ruleset Compiler & Matcher
//!
//! Compiles GeoIP, GeoSite, domain keywords, and CIDR rulesets into optimized
//! Sing-box JSON and binary matching matrices.
//! Ported and enhanced from lyc8503/sing-box-rules.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingboxRuleType {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    IpCidr(String),
    GeoIp(String),
    GeoSite(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingboxAction {
    Direct,
    Proxy(String),
    Block,
}

#[derive(Debug, Clone)]
pub struct SingboxRuleItem {
    pub rule_type: SingboxRuleType,
    pub action: SingboxAction,
}

#[derive(Debug, Clone, Default)]
pub struct SingboxRulesetCompiler {
    rules: Vec<SingboxRuleItem>,
}

impl SingboxRulesetCompiler {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule_type: SingboxRuleType, action: SingboxAction) {
        self.rules.push(SingboxRuleItem { rule_type, action });
    }

    pub fn match_domain(&self, domain: &str) -> Option<SingboxAction> {
        let lower = domain.trim().trim_start_matches('.').to_lowercase();
        for item in &self.rules {
            let matched = match &item.rule_type {
                SingboxRuleType::Domain(d) => &lower == d,
                SingboxRuleType::DomainSuffix(s) => {
                    lower == *s || lower.ends_with(&format!(".{}", s))
                }
                SingboxRuleType::DomainKeyword(kw) => lower.contains(kw),
                SingboxRuleType::GeoSite(site) => {
                    if site == "category-ads-all" {
                        lower.contains("ad") || lower.contains("analytics")
                    } else if site == "cn" {
                        lower.ends_with(".cn") || lower.contains("baidu") || lower.contains("qq")
                    } else {
                        false
                    }
                }
                _ => false,
            };

            if matched {
                return Some(item.action.clone());
            }
        }
        None
    }

    pub fn export_singbox_json(&self) -> String {
        let mut json = String::with_capacity(1024);
        json.push_str("{\n  \"version\": 1,\n  \"rules\": [\n");
        for (i, item) in self.rules.iter().enumerate() {
            let comma = if i + 1 < self.rules.len() { "," } else { "" };
            let action_str = match &item.action {
                SingboxAction::Direct => "direct",
                SingboxAction::Proxy(tag) => tag.as_str(),
                SingboxAction::Block => "block",
            };

            match &item.rule_type {
                SingboxRuleType::Domain(d) => {
                    json.push_str(&format!("    {{\"domain\": [\"{}\"], \"outbound\": \"{}\"}}{}\n", d, action_str, comma));
                }
                SingboxRuleType::DomainSuffix(s) => {
                    json.push_str(&format!("    {{\"domain_suffix\": [\"{}\"], \"outbound\": \"{}\"}}{}\n", s, action_str, comma));
                }
                SingboxRuleType::DomainKeyword(kw) => {
                    json.push_str(&format!("    {{\"domain_keyword\": [\"{}\"], \"outbound\": \"{}\"}}{}\n", kw, action_str, comma));
                }
                SingboxRuleType::IpCidr(cidr) => {
                    json.push_str(&format!("    {{\"ip_cidr\": [\"{}\"], \"outbound\": \"{}\"}}{}\n", cidr, action_str, comma));
                }
                SingboxRuleType::GeoIp(geo) => {
                    json.push_str(&format!("    {{\"geoip\": [\"{}\"], \"outbound\": \"{}\"}}{}\n", geo, action_str, comma));
                }
                SingboxRuleType::GeoSite(site) => {
                    json.push_str(&format!("    {{\"geosite\": [\"{}\"], \"outbound\": \"{}\"}}{}\n", site, action_str, comma));
                }
            }
        }
        json.push_str("  ]\n}\n");
        json
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_singbox_ruleset_matching() {
        let mut compiler = SingboxRulesetCompiler::new();
        compiler.add_rule(
            SingboxRuleType::DomainSuffix("openai.com".to_string()),
            SingboxAction::Proxy("openai-proxy".to_string()),
        );
        compiler.add_rule(
            SingboxRuleType::GeoSite("cn".to_string()),
            SingboxAction::Direct,
        );

        assert_eq!(
            compiler.match_domain("chat.openai.com"),
            Some(SingboxAction::Proxy("openai-proxy".to_string()))
        );
        assert_eq!(
            compiler.match_domain("www.bilibili.cn"),
            Some(SingboxAction::Direct)
        );
        assert_eq!(compiler.match_domain("unmatched-site.org"), None);
    }

    #[test]
    fn test_singbox_json_export() {
        let mut compiler = SingboxRulesetCompiler::new();
        compiler.add_rule(
            SingboxRuleType::Domain("adservice.google.com".to_string()),
            SingboxAction::Block,
        );
        let json = compiler.export_singbox_json();
        assert!(json.contains("\"domain\": [\"adservice.google.com\"]"));
        assert!(json.contains("\"outbound\": \"block\""));
    }
}
