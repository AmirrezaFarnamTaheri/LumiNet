// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # Proxy Auto-Configuration (PAC) Script Engine & Rule Compiler
//!
//! Provides dynamic compilation and offline evaluation of Proxy Auto-Configuration (PAC) scripts,
//! domain/IP routing rules, and crash-resilient system proxy reset contracts.
//! Ported and extended from `oblivion-desktop-main`.

use std::fmt;
use std::str::FromStr;
use std::string::ToString;
use std::vec::Vec;
use std::string::String;
use thiserror::Error;

/// Errors produced during PAC rule compilation or evaluation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacError {
    #[error("Invalid rule syntax: {0}")]
    InvalidSyntax(String),
    #[error("Empty rule definition")]
    EmptyRule,
    #[error("Unsupported rule type: {0}")]
    UnsupportedType(String),
}

/// Target classification for a routing rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacRuleType {
    Domain,
    Ip,
    Range,
    App,
}

impl PacRuleType {
    pub fn as_str(&self) -> &str {
        match self {
            PacRuleType::Domain => "domain",
            PacRuleType::Ip => "ip",
            PacRuleType::Range => "range",
            PacRuleType::App => "app",
        }
    }
}

impl FromStr for PacRuleType {
    type Err = PacError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "domain" => Ok(PacRuleType::Domain),
            "ip" => Ok(PacRuleType::Ip),
            "range" => Ok(PacRuleType::Range),
            "app" => Ok(PacRuleType::App),
            other => Err(PacError::UnsupportedType(other.to_string())),
        }
    }
}

impl fmt::Display for PacRuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A parsed routing rule directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacRule {
    pub rule_type: PacRuleType,
    pub value: String,
    pub is_wildcard: bool,
    pub force_proxy: bool,
}

impl PacRule {
    pub fn new(rule_type: PacRuleType, value: impl Into<String>, is_wildcard: bool, force_proxy: bool) -> Self {
        Self {
            rule_type,
            value: value.into(),
            is_wildcard,
            force_proxy,
        }
    }
}

/// Decision returned by rule evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacDecision {
    /// Connect directly bypassing proxy.
    Direct,
    /// Force routing through the configured proxy.
    Proxy,
    /// Default proxy routing.
    DefaultProxy,
}

/// PAC script compiler and offline rule evaluation engine.
pub struct PacEngine;

impl PacEngine {
    /// Parses a comma-separated or newline-separated routing rules string into structured PacRules.
    ///
    /// Syntax:
    /// - `domain:example.com`: direct bypass for domain
    /// - `!domain:example.com`: forced proxy for domain (exception)
    /// - `*domain:google.com` or `domain:*.google.com`: wildcard domain
    /// - `ip:192.168.1.1`: direct bypass for IP
    /// - `range:10.0.*`: wildcard range bypass
    pub fn parse_rules(rules_str: &str) -> Vec<PacRule> {
        let mut rules = Vec::new();
        if rules_str.trim().is_empty() {
            return rules;
        }

        // Clean out HTML breaks and newlines
        let cleaned = rules_str
            .replace("<br>", ",")
            .replace('\n', ",")
            .replace('\r', "");

        for token in cleaned.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Skip application-level filtering rules for PAC scripts (app:chrome)
            if trimmed.starts_with("app:") {
                continue;
            }

            let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
            if parts.len() == 2 {
                let mut type_str = parts[0].trim();
                let mut raw_val = parts[1].trim();

                let mut force_proxy = false;
                if type_str.starts_with('!') {
                    force_proxy = true;
                    type_str = &type_str[1..];
                }
                if raw_val.starts_with('!') {
                    force_proxy = true;
                    raw_val = &raw_val[1..];
                }

                let is_wildcard = type_str.starts_with('*') || raw_val.starts_with('*') || raw_val.contains('*');
                type_str = type_str.trim_start_matches('*');
                let clean_value = raw_val.trim_start_matches('*').to_string();

                if let Ok(rule_type) = PacRuleType::from_str(type_str) {
                    rules.push(PacRule {
                        rule_type,
                        value: clean_value,
                        is_wildcard,
                        force_proxy,
                    });
                }
            } else {
                // Bare domain or IP token (default type = domain)
                let (force_proxy, val) = if trimmed.starts_with('!') {
                    (true, &trimmed[1..])
                } else {
                    (false, trimmed)
                };
                let is_wildcard = val.starts_with('*') || val.contains('*');
                let clean_val = val.trim_start_matches('*').to_string();

                rules.push(PacRule {
                    rule_type: PacRuleType::Domain,
                    value: clean_val,
                    is_wildcard,
                    force_proxy,
                });
            }
        }

        rules
    }

    /// Evaluates a hostname against the compiled rules offline in pure Rust.
    pub fn evaluate_host(host: &str, rules: &[PacRule]) -> PacDecision {
        let host_lower = host.trim().to_ascii_lowercase();

        // Local loopbacks are always direct
        if host_lower == "127.0.0.1" || host_lower == "::1" || host_lower == "localhost" {
            return PacDecision::Direct;
        }

        for rule in rules {
            let rule_val_lower = rule.value.to_ascii_lowercase();

            match rule.rule_type {
                PacRuleType::Domain => {
                    if rule.is_wildcard {
                        if host_lower.ends_with(&rule_val_lower) || host_lower == rule_val_lower {
                            return if rule.force_proxy {
                                PacDecision::Proxy
                            } else {
                                PacDecision::Direct
                            };
                        }
                    } else if host_lower == rule_val_lower {
                        return if rule.force_proxy {
                            PacDecision::Proxy
                        } else {
                            PacDecision::Direct
                        };
                    }
                }
                PacRuleType::Ip | PacRuleType::Range => {
                    if rule.is_wildcard {
                        let prefix = rule_val_lower.trim_end_matches('*');
                        if host_lower.starts_with(prefix) {
                            return if rule.force_proxy {
                                PacDecision::Proxy
                            } else {
                                PacDecision::Direct
                            };
                        }
                    } else if host_lower == rule_val_lower {
                        return if rule.force_proxy {
                            PacDecision::Proxy
                        } else {
                            PacDecision::Direct
                        };
                    }
                }
                PacRuleType::App => {}
            }
        }

        PacDecision::DefaultProxy
    }

    /// Compiles a standard JavaScript `FindProxyForURL` PAC script for system proxy deployment.
    pub fn compile_pac_script(
        proxy_host: &str,
        proxy_port: u16,
        is_socks5: bool,
        rules: &[PacRule],
    ) -> String {
        let proxy_directive = if is_socks5 {
            format!("SOCKS5 {proxy_host}:{proxy_port}; SOCKS {proxy_host}:{proxy_port}; DIRECT")
        } else {
            format!("PROXY {proxy_host}:{proxy_port}; DIRECT")
        };

        let mut js_rules = String::new();
        for rule in rules {
            let val = &rule.value;
            if rule.force_proxy && rule.rule_type == PacRuleType::Domain {
                if rule.is_wildcard {
                    js_rules.push_str(&format!(
                        "  if (shExpMatch(host, \"*{val}\")) return \"{proxy_directive}\";\n"
                    ));
                } else {
                    js_rules.push_str(&format!(
                        "  if (host === \"{val}\") return \"{proxy_directive}\";\n"
                    ));
                }
            } else if rule.rule_type == PacRuleType::Domain {
                if rule.is_wildcard {
                    js_rules.push_str(&format!(
                        "  if (shExpMatch(host, \"*{val}\")) return \"DIRECT\";\n"
                    ));
                } else {
                    js_rules.push_str(&format!(
                        "  if (host === \"{val}\") return \"DIRECT\";\n"
                    ));
                }
            } else if rule.rule_type == PacRuleType::Ip || rule.rule_type == PacRuleType::Range {
                if rule.is_wildcard {
                    let prefix = val.trim_end_matches('*');
                    js_rules.push_str(&format!(
                        "  if (host.indexOf(\"{prefix}\") === 0) return \"DIRECT\";\n"
                    ));
                } else {
                    js_rules.push_str(&format!(
                        "  if (host === \"{val}\") return \"DIRECT\";\n"
                    ));
                }
            }
        }

        format!(
            "function FindProxyForURL(url, host) {{\n\
             \"use strict\";\n\
             if (isPlainHostName(host) || /^127\\./.test(host) || /^10\\./.test(host) || /^172\\.(1[6-9]|2[0-9]|3[01])\\./.test(host) || /^192\\.168\\./.test(host) || host === \"localhost\" || host === \"::1\") {{\n\
             return \"DIRECT\";\n\
             }}\n\
             {js_rules}\
             return \"{proxy_directive}\";\n\
             }}\n"
        )
    }
}

/// Crash-resilient startup proxy reset contract builder.
pub struct StartupProxyReset;

impl StartupProxyReset {
    pub const REGISTRY_RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    pub const VALUE_NAME: &str = "LumiNetProxyReset";

    /// Generates the Windows command to clean up system proxy settings on startup.
    pub fn windows_reset_command() -> &'static str {
        "reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyEnable /t REG_DWORD /d 0 /f"
    }

    /// Generates macOS networksetup commands to reset all network interfaces to direct.
    pub fn macos_reset_command(service: &str) -> String {
        format!(
            "networksetup -setsocksfirewallproxystate \"{service}\" off && \
             networksetup -setwebproxystate \"{service}\" off && \
             networksetup -setsecurewebproxystate \"{service}\" off && \
             networksetup -setautoproxystate \"{service}\" off"
        )
    }

    /// Generates Linux GNOME gsettings command to revert proxy to direct/none.
    pub fn linux_reset_command() -> &'static str {
        "gsettings set org.gnome.system.proxy mode 'none'"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rules_syntax() {
        let input = "domain:example.com,!domain:force.com,*domain:wildcard.org,ip:192.168.1.1,range:10.0.*,app:ignoreme";
        let rules = PacEngine::parse_rules(input);

        assert_eq!(rules.len(), 5); // app: rule skipped

        assert_eq!(rules[0].rule_type, PacRuleType::Domain);
        assert_eq!(rules[0].value, "example.com");
        assert!(!rules[0].force_proxy);
        assert!(!rules[0].is_wildcard);

        assert_eq!(rules[1].rule_type, PacRuleType::Domain);
        assert_eq!(rules[1].value, "force.com");
        assert!(rules[1].force_proxy);

        assert_eq!(rules[2].rule_type, PacRuleType::Domain);
        assert_eq!(rules[2].value, "wildcard.org");
        assert!(rules[2].is_wildcard);

        assert_eq!(rules[3].rule_type, PacRuleType::Ip);
        assert_eq!(rules[3].value, "192.168.1.1");

        assert_eq!(rules[4].rule_type, PacRuleType::Range);
        assert_eq!(rules[4].value, "10.0.*");
        assert!(rules[4].is_wildcard);
    }

    #[test]
    fn test_evaluate_host_decisions() {
        let rules = vec![
            PacRule::new(PacRuleType::Domain, "direct.com", false, false),
            PacRule::new(PacRuleType::Domain, "forceproxy.com", false, true),
            PacRule::new(PacRuleType::Domain, "cdn.net", true, false),
        ];

        assert_eq!(PacEngine::evaluate_host("localhost", &rules), PacDecision::Direct);
        assert_eq!(PacEngine::evaluate_host("127.0.0.1", &rules), PacDecision::Direct);
        assert_eq!(PacEngine::evaluate_host("direct.com", &rules), PacDecision::Direct);
        assert_eq!(PacEngine::evaluate_host("forceproxy.com", &rules), PacDecision::Proxy);
        assert_eq!(PacEngine::evaluate_host("static.cdn.net", &rules), PacDecision::Direct);
        assert_eq!(PacEngine::evaluate_host("unknown.org", &rules), PacDecision::DefaultProxy);
    }

    #[test]
    fn test_compile_pac_script() {
        let rules = vec![
            PacRule::new(PacRuleType::Domain, "internal.corp", false, false),
            PacRule::new(PacRuleType::Domain, "blocked.com", false, true),
        ];

        let script = PacEngine::compile_pac_script("127.0.0.1", 1080, true, &rules);

        assert!(script.contains("function FindProxyForURL(url, host)"));
        assert!(script.contains("SOCKS5 127.0.0.1:1080"));
        assert!(script.contains("host === \"internal.corp\""));
        assert!(script.contains("host === \"blocked.com\""));
    }

    #[test]
    fn test_startup_reset_commands() {
        assert!(StartupProxyReset::windows_reset_command().contains("ProxyEnable /t REG_DWORD /d 0"));
        assert!(StartupProxyReset::linux_reset_command().contains("mode 'none'"));
        let mac = StartupProxyReset::macos_reset_command("Wi-Fi");
        assert!(mac.contains("networksetup -setsocksfirewallproxystate \"Wi-Fi\" off"));
    }
}
