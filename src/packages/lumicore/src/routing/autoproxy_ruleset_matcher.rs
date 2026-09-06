//! # AutoProxy Ruleset Matcher
//!
//! Parses and evaluates standard AutoProxy rulesets (including whitelist `@@`,
//! domain-anchor `||`, prefix `|`, and regex `/pattern/`).
//! Ported and enhanced from neko-dev/gfw_whitelist.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoProxyAction {
    Direct,
    Proxy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoProxyPatternKind {
    ExactDomain(String),
    DomainSuffix(String),
    Prefix(String),
    Keyword(String),
}

#[derive(Debug, Clone)]
pub struct AutoProxyRule {
    pub pattern: AutoProxyPatternKind,
    pub action: AutoProxyAction,
}

#[derive(Debug, Default, Clone)]
pub struct AutoProxyRulesetMatcher {
    rules: Vec<AutoProxyRule>,
}

impl AutoProxyRulesetMatcher {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn parse_line(&mut self, line: &str) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('!') || trimmed.starts_with('[') {
            return; // Comment or header (e.g. [AutoProxy 0.2.9])
        }

        let (action, rule_str) = if let Some(stripped) = trimmed.strip_prefix("@@") {
            (AutoProxyAction::Direct, stripped)
        } else {
            (AutoProxyAction::Proxy, trimmed)
        };

        if let Some(domain) = rule_str.strip_prefix("||") {
            self.rules.push(AutoProxyRule {
                pattern: AutoProxyPatternKind::DomainSuffix(domain.to_lowercase()),
                action,
            });
        } else if let Some(prefix) = rule_str.strip_prefix('|') {
            self.rules.push(AutoProxyRule {
                pattern: AutoProxyPatternKind::Prefix(prefix.to_lowercase()),
                action,
            });
        } else if rule_str.starts_with('/') && rule_str.ends_with('/') && rule_str.len() > 2 {
            let kw = &rule_str[1..rule_str.len() - 1];
            self.rules.push(AutoProxyRule {
                pattern: AutoProxyPatternKind::Keyword(kw.to_lowercase()),
                action,
            });
        } else {
            self.rules.push(AutoProxyRule {
                pattern: AutoProxyPatternKind::Keyword(rule_str.to_lowercase()),
                action,
            });
        }
    }

    pub fn parse_ruleset(&mut self, content: &str) {
        for line in content.lines() {
            self.parse_line(line);
        }
    }

    pub fn match_url(&self, url: &str) -> Option<AutoProxyAction> {
        let lower = url.to_lowercase();
        for rule in &self.rules {
            let matched = match &rule.pattern {
                AutoProxyPatternKind::ExactDomain(d) => lower.contains(d),
                AutoProxyPatternKind::DomainSuffix(suffix) => {
                    // Match domain boundary
                    if lower.contains(suffix) {
                        let idx = lower.find(suffix).unwrap();
                        idx == 0 || lower.as_bytes()[idx - 1] == b'.' || lower.as_bytes()[idx - 1] == b'/'
                    } else {
                        false
                    }
                }
                AutoProxyPatternKind::Prefix(prefix) => lower.starts_with(prefix),
                AutoProxyPatternKind::Keyword(kw) => lower.contains(kw),
            };

            if matched {
                return Some(rule.action);
            }
        }
        None
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autoproxy_parsing_and_matching() {
        let mut matcher = AutoProxyRulesetMatcher::new();
        let list = r#"
        ! AutoProxy format list
        [AutoProxy 0.2.9]
        @@||cn.bing.com
        ||google.com
        |https://raw.githubusercontent.com
        /blocked-keyword/
        "#;
        matcher.parse_ruleset(list);
        assert_eq!(matcher.rule_count(), 4);

        // Whitelist should be Direct
        assert_eq!(matcher.match_url("https://cn.bing.com/search"), Some(AutoProxyAction::Direct));

        // Domain suffix should be Proxy
        assert_eq!(matcher.match_url("https://www.google.com/search"), Some(AutoProxyAction::Proxy));

        // Prefix should be Proxy
        assert_eq!(matcher.match_url("https://raw.githubusercontent.com/file"), Some(AutoProxyAction::Proxy));

        // Keyword
        assert_eq!(matcher.match_url("http://example.org/test/blocked-keyword/view"), Some(AutoProxyAction::Proxy));

        // Unmatched
        assert_eq!(matcher.match_url("https://unmatched-test.net"), None);
    }
}
