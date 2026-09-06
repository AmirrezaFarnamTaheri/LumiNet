//! SNI Hostname Rewriter and TLS Evasion Engine
//!
//! Mitigates SNI-based TCP RST censorship by substituting sensitive SNI domain names
//! in TLS ClientHello payloads with allowed CDN hosts while enforcing legitimate SAN certificate verification.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SniRewriteRule {
    pub original_domain: String,
    pub altered_sni: String,
    pub valid_san_names: Vec<String>,
    pub skip_cert_verify: bool,
}

pub struct SniHostnameRewriter {
    rewrite_rules: HashMap<String, SniRewriteRule>,
    http_redirects: HashMap<String, String>,
    total_rewrites: u64,
}

impl SniHostnameRewriter {
    pub fn new() -> Self {
        Self {
            rewrite_rules: HashMap::new(),
            http_redirects: HashMap::new(),
            total_rewrites: 0,
        }
    }

    pub fn add_sni_rule(&mut self, original: &str, altered: &str, sans: Vec<String>, skip_verify: bool) {
        let key = original.trim().to_lowercase();
        self.rewrite_rules.insert(
            key.clone(),
            SniRewriteRule {
                original_domain: key,
                altered_sni: altered.trim().to_lowercase(),
                valid_san_names: sans.into_iter().map(|s| s.to_lowercase()).collect(),
                skip_cert_verify: skip_verify,
            },
        );
    }

    pub fn add_http_redirect(&mut self, prefix: &str, target_url: &str) {
        self.http_redirects.insert(prefix.to_string(), target_url.to_string());
    }

    pub fn resolve_sni_for_domain(&mut self, domain: &str) -> (String, Option<SniRewriteRule>) {
        let key = domain.trim().to_lowercase();
        if let Some(rule) = self.rewrite_rules.get(&key) {
            self.total_rewrites += 1;
            (rule.altered_sni.clone(), Some(rule.clone()))
        } else {
            (domain.to_string(), None)
        }
    }

    pub fn check_san_validity(&self, rule: &SniRewriteRule, presented_sans: &[String]) -> bool {
        if rule.skip_cert_verify {
            return true;
        }

        for valid in &rule.valid_san_names {
            for presented in presented_sans {
                let p_lower = presented.to_lowercase();
                if valid.starts_with("*.") {
                    let suffix = &valid[2..];
                    if p_lower.ends_with(suffix) {
                        return true;
                    }
                } else if &p_lower == valid {
                    return true;
                }
            }
        }
        false
    }

    pub fn check_http_upgrade_redirect(&self, request_url: &str) -> Option<String> {
        for (prefix, redirect_to) in &self.http_redirects {
            if request_url.starts_with(prefix) {
                return Some(format!("https://{}", redirect_to));
            }
        }
        None
    }

    pub fn total_rewrites_count(&self) -> u64 {
        self.total_rewrites
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_hostname_rewriter() {
        let mut rewriter = SniHostnameRewriter::new();
        rewriter.add_sni_rule(
            "wikipedia.org",
            "upload.wikimedia.org",
            vec!["*.wikipedia.org".to_string(), "wikimedia.org".to_string()],
            false,
        );
        rewriter.add_http_redirect("pixiv.net/", "www.pixiv.net/");

        let (sni, rule_opt) = rewriter.resolve_sni_for_domain("wikipedia.org");
        assert_eq!(sni, "upload.wikimedia.org");
        assert!(rule_opt.is_some());

        let rule = rule_opt.unwrap();
        let presented_sans = vec!["en.wikipedia.org".to_string()];
        assert!(rewriter.check_san_validity(&rule, &presented_sans));

        let upgrade = rewriter.check_http_upgrade_redirect("pixiv.net/artworks/123");
        assert_eq!(upgrade, Some("https://www.pixiv.net/".to_string()));
    }
}
