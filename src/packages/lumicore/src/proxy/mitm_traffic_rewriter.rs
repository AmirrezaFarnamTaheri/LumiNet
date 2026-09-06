//! MITM Traffic Rewriting and Inspection Engine
//!
//! Provides granular request and response mutation, header injection, URL rewriting,
//! body replacement, and synthetic mock response generation for traffic debugging.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum RewriteAction {
    RedirectUrl { new_url: String },
    SetHeader { name: String, value: String },
    RemoveHeader { name: String },
    ReplaceBody { pattern: String, replacement: String },
    MockResponse { status: u16, content_type: String, body: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct RewriteRule {
    pub rule_id: String,
    pub domain_pattern: String,
    pub path_prefix: String,
    pub is_active: bool,
    pub action: RewriteAction,
}

pub struct MitmTrafficRewriter {
    rules: Vec<RewriteRule>,
    total_mutations: u64,
}

impl MitmTrafficRewriter {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            total_mutations: 0,
        }
    }

    pub fn add_rule(&mut self, rule: RewriteRule) {
        self.rules.push(rule);
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let initial_len = self.rules.len();
        self.rules.retain(|r| r.rule_id != rule_id);
        self.rules.len() < initial_len
    }

    pub fn match_rule(&self, domain: &str, path: &str) -> Option<&RewriteRule> {
        let domain_lower = domain.to_lowercase();
        for rule in &self.rules {
            if !rule.is_active {
                continue;
            }

            let domain_matched = if rule.domain_pattern == "*" {
                true
            } else if rule.domain_pattern.starts_with("*.") {
                let suffix = &rule.domain_pattern[2..];
                domain_lower.ends_with(suffix)
            } else {
                domain_lower == rule.domain_pattern
            };

            if domain_matched && path.starts_with(&rule.path_prefix) {
                return Some(rule);
            }
        }
        None
    }

    pub fn rewrite_request(
        &mut self,
        domain: &str,
        path: &mut String,
        headers: &mut HashMap<String, String>,
    ) -> Option<RewriteAction> {
        let matched = self.match_rule(domain, path).cloned();
        if let Some(rule) = matched {
            match &rule.action {
                RewriteAction::RedirectUrl { new_url } => {
                    *path = new_url.clone();
                    self.total_mutations += 1;
                    Some(rule.action)
                }
                RewriteAction::SetHeader { name, value } => {
                    headers.insert(name.clone(), value.clone());
                    self.total_mutations += 1;
                    Some(rule.action)
                }
                RewriteAction::RemoveHeader { name } => {
                    headers.remove(name);
                    self.total_mutations += 1;
                    Some(rule.action)
                }
                RewriteAction::MockResponse { .. } => {
                    self.total_mutations += 1;
                    Some(rule.action)
                }
                _ => None,
            }
        } else {
            None
        }
    }

    pub fn rewrite_response_body(&mut self, domain: &str, path: &str, body: &[u8]) -> Vec<u8> {
        let matched = self.match_rule(domain, path).cloned();
        if let Some(rule) = matched {
            if let RewriteAction::ReplaceBody { pattern, replacement } = &rule.action {
                if let Ok(body_str) = std::str::from_utf8(body) {
                    if body_str.contains(pattern) {
                        self.total_mutations += 1;
                        return body_str.replace(pattern, replacement).into_bytes();
                    }
                }
            }
        }
        body.to_vec()
    }

    pub fn total_mutations_applied(&self) -> u64 {
        self.total_mutations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mitm_traffic_rewriter() {
        let mut rewriter = MitmTrafficRewriter::new();

        rewriter.add_rule(RewriteRule {
            rule_id: "rule-1".to_string(),
            domain_pattern: "api.target.com".to_string(),
            path_prefix: "/v1/auth".to_string(),
            is_active: true,
            action: RewriteAction::SetHeader {
                name: "X-Forwarded-Lumi".to_string(),
                value: "Injected".to_string(),
            },
        });

        rewriter.add_rule(RewriteRule {
            rule_id: "rule-2".to_string(),
            domain_pattern: "*.target.com".to_string(),
            path_prefix: "/index.html".to_string(),
            is_active: true,
            action: RewriteAction::ReplaceBody {
                pattern: "Blocked".to_string(),
                replacement: "Unblocked".to_string(),
            },
        });

        let mut headers = HashMap::new();
        let mut path = "/v1/auth/login".to_string();
        let action = rewriter.rewrite_request("api.target.com", &mut path, &mut headers);

        assert!(action.is_some());
        assert_eq!(headers.get("X-Forwarded-Lumi").map(|s| s.as_str()), Some("Injected"));

        let original_body = b"Status: Blocked By Filter";
        let mutated = rewriter.rewrite_response_body("sub.target.com", "/index.html", original_body);
        assert_eq!(mutated, b"Status: Unblocked By Filter");
        assert_eq!(rewriter.total_mutations_applied(), 2);
    }
}
