//! # Multi-Criteria Policy Routing Engine
//!
//! Evaluates network traffic against configurable rule sets supporting domain
//! suffixes, full domain matching, keywords, regexes, IPv4/IPv6 CIDR ranges,
//! private IP classification (RFC 1918, CGNAT, ULA), port ranges, and INI configuration blocks.

use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Routing action applied to evaluated network traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Proxy,
    Direct,
    Block,
}

impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Action::Proxy => "proxy",
            Action::Direct => "direct",
            Action::Block => "block",
        }
    }
}

/// Destination host subject to routing evaluation.
#[derive(Debug, Clone, Copy)]
pub enum Host<'a> {
    Domain(&'a str),
    Ip(IpAddr),
}

/// IP CIDR representation for subnet matching without external dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpCidr {
    V4 { addr: Ipv4Addr, prefix: u8 },
    V6 { addr: Ipv6Addr, prefix: u8 },
}

impl IpCidr {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (IpCidr::V4 { addr, prefix }, IpAddr::V4(target)) => {
                if *prefix == 0 {
                    return true;
                }
                if *prefix > 32 {
                    return false;
                }
                let mask = if *prefix == 32 {
                    u32::MAX
                } else {
                    !((1u32 << (32 - *prefix)) - 1)
                };
                (u32::from_be_bytes(addr.octets()) & mask) == (u32::from_be_bytes(target.octets()) & mask)
            }
            (IpCidr::V6 { addr, prefix }, IpAddr::V6(target)) => {
                if *prefix == 0 {
                    return true;
                }
                if *prefix > 128 {
                    return false;
                }
                let mask = if *prefix == 128 {
                    u128::MAX
                } else {
                    !((1u128 << (128 - *prefix)) - 1)
                };
                (u128::from_be_bytes(addr.octets()) & mask) == (u128::from_be_bytes(target.octets()) & mask)
            }
            _ => false,
        }
    }
}

#[derive(Debug)]
pub enum Matcher {
    DomainSuffix(String),
    DomainFull(String),
    DomainKeyword(String),
    DomainRegex(Regex),
    Net(IpCidr),
    Ports(u16, u16),
    Private,
}

impl Matcher {
    pub fn parse(entry: &str) -> Option<Self> {
        let entry = entry.trim();
        if entry.is_empty() || entry.starts_with('#') {
            return None;
        }

        let (kind, value) = match entry.split_once(':') {
            Some((kind, value)) if !kind.contains('.') && !kind.contains('/') => {
                (kind.trim().to_lowercase(), value.trim())
            }
            _ => (String::new(), entry),
        };

        match kind.as_str() {
            "domain" | "suffix" => Some(Matcher::DomainSuffix(normalize_domain(value)?)),
            "full" | "exact" => Some(Matcher::DomainFull(normalize_domain(value)?)),
            "keyword" => {
                let needle = value.trim().to_lowercase();
                if needle.is_empty() {
                    None
                } else {
                    Some(Matcher::DomainKeyword(needle))
                }
            }
            "regexp" | "regex" => Regex::new(value).ok().map(Matcher::DomainRegex),
            "ip" | "cidr" => parse_net(value).map(Matcher::Net),
            "port" => parse_ports(value).map(|(lo, hi)| Matcher::Ports(lo, hi)),
            "geoip" | "geosite" => {
                if value.eq_ignore_ascii_case("private") {
                    Some(Matcher::Private)
                } else {
                    None
                }
            }
            "" => {
                if value.eq_ignore_ascii_case("private") {
                    return Some(Matcher::Private);
                }
                if let Some(net) = parse_net(value) {
                    return Some(Matcher::Net(net));
                }
                normalize_domain(value).map(Matcher::DomainSuffix)
            }
            _ => None,
        }
    }

    pub fn matches(&self, host: Host<'_>, port: u16) -> bool {
        match self {
            Matcher::Ports(lo, hi) => port >= *lo && port <= *hi,
            Matcher::Private => match host {
                Host::Ip(ip) => is_private_ip(ip),
                Host::Domain(name) => name.eq_ignore_ascii_case("localhost"),
            },
            Matcher::Net(net) => match host {
                Host::Ip(ip) => net.contains(&ip),
                Host::Domain(_) => false,
            },
            Matcher::DomainSuffix(suffix) => match host {
                Host::Domain(name) => {
                    let name = name.to_lowercase();
                    name == *suffix || name.ends_with(&format!(".{suffix}"))
                }
                Host::Ip(_) => false,
            },
            Matcher::DomainFull(full) => match host {
                Host::Domain(name) => name.eq_ignore_ascii_case(full),
                Host::Ip(_) => false,
            },
            Matcher::DomainKeyword(needle) => match host {
                Host::Domain(name) => name.to_lowercase().contains(needle),
                Host::Ip(_) => false,
            },
            Matcher::DomainRegex(pattern) => match host {
                Host::Domain(name) => pattern.is_match(name),
                Host::Ip(_) => false,
            },
        }
    }
}

fn normalize_domain(value: &str) -> Option<String> {
    let cleaned = value
        .trim()
        .trim_start_matches('*')
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_lowercase();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn parse_net(value: &str) -> Option<IpCidr> {
    let value = value.trim();
    if let Some((addr_str, prefix_str)) = value.split_once('/') {
        let prefix = prefix_str.trim().parse::<u8>().ok()?;
        if let Ok(v4) = addr_str.trim().parse::<Ipv4Addr>() {
            if prefix <= 32 {
                return Some(IpCidr::V4 { addr: v4, prefix });
            }
        } else if let Ok(v6) = addr_str.trim().parse::<Ipv6Addr>() {
            if prefix <= 128 {
                return Some(IpCidr::V6 { addr: v6, prefix });
            }
        }
        return None;
    }

    if let Ok(ip) = value.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => Some(IpCidr::V4 { addr: v4, prefix: 32 }),
            IpAddr::V6(v6) => Some(IpCidr::V6 { addr: v6, prefix: 128 }),
        };
    }

    None
}

fn parse_ports(value: &str) -> Option<(u16, u16)> {
    let value = value.trim();
    match value.split_once('-') {
        Some((lo, hi)) => {
            let lo = lo.trim().parse::<u16>().ok()?;
            let hi = hi.trim().parse::<u16>().ok()?;
            Some(if hi < lo { (hi, lo) } else { (lo, hi) })
        }
        None => {
            let single = value.parse::<u16>().ok()?;
            Some((single, single))
        }
    }
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])) // CGNAT 100.64.0.0/10
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // Link-Local
        }
    }
}

/// A comprehensive multi-criteria policy routing rule set.
#[derive(Debug, Default)]
pub struct PolicyRuleSet {
    pub block: Vec<Matcher>,
    pub direct: Vec<Matcher>,
    pub proxy: Vec<Matcher>,
}

impl PolicyRuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, matcher: Matcher, action: Action) {
        match action {
            Action::Block => self.block.push(matcher),
            Action::Direct => self.direct.push(matcher),
            Action::Proxy => self.proxy.push(matcher),
        }
    }

    pub fn parse(block_spec: &str, direct_spec: &str) -> Self {
        Self {
            block: parse_matcher_list(block_spec),
            direct: parse_matcher_list(direct_spec),
            proxy: Vec::new(),
        }
    }

    pub fn from_ini(text: &str) -> Self {
        Self::parse_ini_sections(text)
    }

    pub fn parse_ini_sections(text: &str) -> Self {
        let mut block = String::new();
        let mut direct = String::new();
        let mut current: Option<&mut String> = None;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let lowered = trimmed.to_lowercase();
            if lowered == "[block]" {
                current = Some(&mut block);
                continue;
            }
            if lowered == "[direct]" {
                current = Some(&mut direct);
                continue;
            }
            if lowered.starts_with('[') {
                current = None;
                continue;
            }

            if let Some(target) = current.as_deref_mut() {
                target.push_str(trimmed);
                target.push('\n');
            }
        }

        Self::parse(&block, &direct)
    }

    pub fn is_empty(&self) -> bool {
        self.block.is_empty() && self.direct.is_empty() && self.proxy.is_empty()
    }

    /// Evaluates traffic against the rule set. Block strictly takes precedence over Direct.
    pub fn decide(&self, host: Host<'_>, port: u16) -> Action {
        if self.block.iter().any(|rule| rule.matches(host, port)) {
            return Action::Block;
        }
        if self.direct.iter().any(|rule| rule.matches(host, port)) {
            return Action::Direct;
        }
        if self.proxy.iter().any(|rule| rule.matches(host, port)) {
            return Action::Proxy;
        }
        Action::Proxy
    }

    /// Flexible evaluation helper accepting optional domain, IP, and port.
    pub fn evaluate(&self, domain: Option<&str>, ip: Option<IpAddr>, port: Option<u16>) -> Action {
        let p = port.unwrap_or(443);

        if let Some(d) = domain {
            let action = self.decide(Host::Domain(d), p);
            if action != Action::Proxy {
                return action;
            }
        }

        if let Some(i) = ip {
            let action = self.decide(Host::Ip(i), p);
            if action != Action::Proxy {
                return action;
            }
        }

        // Check port or default rules
        if self.proxy.iter().any(|rule| {
            if let Some(d) = domain {
                rule.matches(Host::Domain(d), p)
            } else if let Some(i) = ip {
                rule.matches(Host::Ip(i), p)
            } else {
                false
            }
        }) {
            return Action::Proxy;
        }

        Action::Proxy
    }
}

fn parse_matcher_list(raw: &str) -> Vec<Matcher> {
    raw.split(['\n', ',', ';'])
        .filter_map(Matcher::parse)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_empty_is_proxy() {
        let set = PolicyRuleSet::new();
        assert_eq!(set.decide(Host::Domain("example.com"), 443), Action::Proxy);
    }

    #[test]
    fn test_domain_suffix_matching() {
        let set = PolicyRuleSet::parse("ads.example", "");
        assert_eq!(set.decide(Host::Domain("ads.example"), 443), Action::Block);
        assert_eq!(set.decide(Host::Domain("sub.ads.example"), 443), Action::Block);
        assert_eq!(set.decide(Host::Domain("notads.example"), 443), Action::Proxy);
    }

    #[test]
    fn test_full_domain_matching() {
        let set = PolicyRuleSet::parse("full:target.com", "");
        assert_eq!(set.decide(Host::Domain("target.com"), 443), Action::Block);
        assert_eq!(set.decide(Host::Domain("sub.target.com"), 443), Action::Proxy);
    }

    #[test]
    fn test_cidr_and_private_matching() {
        let set = PolicyRuleSet::parse("", "10.0.0.0/8, private");
        assert_eq!(set.decide(Host::Ip("10.1.2.3".parse().unwrap()), 80), Action::Direct);
        assert_eq!(set.decide(Host::Ip("192.168.1.1".parse().unwrap()), 80), Action::Direct);
        assert_eq!(set.decide(Host::Ip("100.64.0.1".parse().unwrap()), 80), Action::Direct);
        assert_eq!(set.decide(Host::Ip("8.8.8.8".parse().unwrap()), 80), Action::Proxy);
    }

    #[test]
    fn test_block_precedence_over_direct() {
        let set = PolicyRuleSet::parse("shared.com", "shared.com");
        assert_eq!(set.decide(Host::Domain("shared.com"), 443), Action::Block);
    }
}
