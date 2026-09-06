//! # PAC Script Compiler & Binary Prefix Matcher
//!
//! Generates Proxy Auto-Configuration (PAC) scripts and executes
//! high-speed in-memory binary prefix evaluation for domains and IP ranges.
//! Ported and enhanced from zhiyi7/gfw-pac.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacProxyMode {
    Direct,
    Proxy(String),
    Socks5(String),
    Http(String),
}

impl PacProxyMode {
    pub fn to_pac_return_string(&self) -> String {
        match self {
            PacProxyMode::Direct => "DIRECT".to_string(),
            PacProxyMode::Proxy(addr) => format!("PROXY {}", addr),
            PacProxyMode::Socks5(addr) => format!("SOCKS5 {}", addr),
            PacProxyMode::Http(addr) => format!("HTTP {}", addr),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacMatchResult {
    Direct,
    Proxy(String),
    DefaultAction,
}

#[derive(Debug, Clone)]
pub struct PacScriptCompiler {
    direct_domains: HashSet<String>,
    proxy_domains: HashSet<String>,
    cn_ipv4_prefixes: Vec<(u32, u32)>, // (network_u32, mask_u32)
    default_proxy: PacProxyMode,
}

impl PacScriptCompiler {
    pub fn new(default_proxy: PacProxyMode) -> Self {
        Self {
            direct_domains: HashSet::new(),
            proxy_domains: HashSet::new(),
            cn_ipv4_prefixes: Vec::new(),
            default_proxy,
        }
    }

    pub fn add_direct_domain(&mut self, domain: &str) {
        let clean = domain.trim().trim_start_matches('.').to_lowercase();
        if !clean.is_empty() {
            self.direct_domains.insert(clean);
        }
    }

    pub fn add_proxy_domain(&mut self, domain: &str) {
        let clean = domain.trim().trim_start_matches('.').to_lowercase();
        if !clean.is_empty() {
            self.proxy_domains.insert(clean);
        }
    }

    pub fn add_cn_cidr(&mut self, cidr: &str) -> Result<(), &'static str> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err("Invalid CIDR format");
        }
        let ip: Ipv4Addr = parts[0].parse().map_err(|_| "Invalid IPv4 address")?;
        let prefix_len: u32 = parts[1].parse().map_err(|_| "Invalid prefix length")?;
        if prefix_len > 32 {
            return Err("Prefix length exceeds 32");
        }

        let mask = if prefix_len == 0 {
            0u32
        } else {
            !0u32 << (32 - prefix_len)
        };
        let net = u32::from(ip) & mask;
        self.cn_ipv4_prefixes.push((net, mask));
        Ok(())
    }

    pub fn evaluate_domain(&self, domain: &str) -> PacMatchResult {
        let lower = domain.trim().trim_start_matches('.').to_lowercase();
        
        // Exact match or suffix match
        if self.proxy_domains.contains(&lower) {
            return match &self.default_proxy {
                PacProxyMode::Direct => PacMatchResult::Direct,
                other => PacMatchResult::Proxy(other.to_pac_return_string()),
            };
        }
        if self.direct_domains.contains(&lower) {
            return PacMatchResult::Direct;
        }

        // Check suffix domains (e.g., sub.example.com -> matches example.com)
        let mut parts = lower.as_str();
        while let Some(idx) = parts.find('.') {
            parts = &parts[idx + 1..];
            if self.proxy_domains.contains(parts) {
                return match &self.default_proxy {
                    PacProxyMode::Direct => PacMatchResult::Direct,
                    other => PacMatchResult::Proxy(other.to_pac_return_string()),
                };
            }
            if self.direct_domains.contains(parts) {
                return PacMatchResult::Direct;
            }
        }

        PacMatchResult::DefaultAction
    }

    pub fn evaluate_ip(&self, ip: IpAddr) -> PacMatchResult {
        match ip {
            IpAddr::V4(v4) => {
                let val = u32::from(v4);
                for &(net, mask) in &self.cn_ipv4_prefixes {
                    if (val & mask) == net {
                        return PacMatchResult::Direct;
                    }
                }
                match &self.default_proxy {
                    PacProxyMode::Direct => PacMatchResult::Direct,
                    other => PacMatchResult::Proxy(other.to_pac_return_string()),
                }
            }
            IpAddr::V6(_) => PacMatchResult::DefaultAction,
        }
    }

    pub fn compile_pac_script(&self) -> String {
        let mut script = String::with_capacity(4096);
        script.push_str("// LumiNet Autonomous PAC Script Engine\n");
        script.push_str("var direct = 'DIRECT';\n");
        script.push_str(&format!("var proxy = '{}';\n\n", self.default_proxy.to_pac_return_string()));
        
        script.push_str("var directDomains = {\n");
        for d in &self.direct_domains {
            script.push_str(&format!("  '{}': 1,\n", d));
        }
        script.push_str("};\n\n");

        script.push_str("var proxyDomains = {\n");
        for d in &self.proxy_domains {
            script.push_str(&format!("  '{}': 1,\n", d));
        }
        script.push_str("};\n\n");

        script.push_str("function FindProxyForURL(url, host) {\n");
        script.push_str("  if (isPlainHostName(host) || host === '127.0.0.1' || host === 'localhost') return direct;\n");
        script.push_str("  var pos = host.lastIndexOf('.');\n");
        script.push_str("  while (pos > 0) {\n");
        script.push_str("    var sub = host.substring(pos + 1);\n");
        script.push_str("    if (proxyDomains[host] || proxyDomains[sub]) return proxy;\n");
        script.push_str("    if (directDomains[host] || directDomains[sub]) return direct;\n");
        script.push_str("    pos = host.lastIndexOf('.', pos - 1);\n");
        script.push_str("  }\n");
        script.push_str("  if (proxyDomains[host]) return proxy;\n");
        script.push_str("  if (directDomains[host]) return direct;\n");
        script.push_str("  return direct;\n");
        script.push_str("}\n");

        script
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pac_domain_matching() {
        let mut compiler = PacScriptCompiler::new(PacProxyMode::Socks5("127.0.0.1:1080".to_string()));
        compiler.add_direct_domain("baidu.com");
        compiler.add_proxy_domain("google.com");
        compiler.add_proxy_domain("youtube.com");

        assert_eq!(compiler.evaluate_domain("google.com"), PacMatchResult::Proxy("SOCKS5 127.0.0.1:1080".to_string()));
        assert_eq!(compiler.evaluate_domain("sub.google.com"), PacMatchResult::Proxy("SOCKS5 127.0.0.1:1080".to_string()));
        assert_eq!(compiler.evaluate_domain("baidu.com"), PacMatchResult::Direct);
        assert_eq!(compiler.evaluate_domain("maps.baidu.com"), PacMatchResult::Direct);
        assert_eq!(compiler.evaluate_domain("unknown-domain.org"), PacMatchResult::DefaultAction);
    }

    #[test]
    fn test_pac_ip_cidr_matching() {
        let mut compiler = PacScriptCompiler::new(PacProxyMode::Http("127.0.0.1:8080".to_string()));
        compiler.add_cn_cidr("114.114.114.0/24").unwrap();

        let cn_ip: IpAddr = "114.114.114.114".parse().unwrap();
        let foreign_ip: IpAddr = "8.8.8.8".parse().unwrap();

        assert_eq!(compiler.evaluate_ip(cn_ip), PacMatchResult::Direct);
        assert_eq!(compiler.evaluate_ip(foreign_ip), PacMatchResult::Proxy("HTTP 127.0.0.1:8080".to_string()));
    }

    #[test]
    fn test_pac_script_generation() {
        let mut compiler = PacScriptCompiler::new(PacProxyMode::Proxy("10.0.0.1:8080".to_string()));
        compiler.add_direct_domain("qq.com");
        compiler.add_proxy_domain("wikipedia.org");
        let pac = compiler.compile_pac_script();
        assert!(pac.contains("PROXY 10.0.0.1:8080"));
        assert!(pac.contains("FindProxyForURL"));
    }
}
