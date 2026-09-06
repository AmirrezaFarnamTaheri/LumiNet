// Pure Rust implementation: Community Subscription Feed Parser

use std::collections::HashSet;
use base64::Engine;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedProxyNode {
    pub id: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub credentials: String,
    pub transport: String,
    pub sni: Option<String>,
    pub tag: String,
}

pub struct CommunityFeedParser {
    pub nodes: Vec<ParsedProxyNode>,
}

impl CommunityFeedParser {
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    pub fn decode_subscription_feed(raw_content: &str) -> Result<String, String> {
        let trimmed = raw_content.trim();
        // If content already starts with standard URI schemes, return as is
        if trimmed.starts_with("vless://")
            || trimmed.starts_with("vmess://")
            || trimmed.starts_with("trojan://")
            || trimmed.starts_with("ss://")
        {
            return Ok(trimmed.to_string());
        }

        // Otherwise attempt standard Base64 decoding
        let clean_b64: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
        match base64::engine::general_purpose::STANDARD.decode(clean_b64.as_bytes()) {
            Ok(bytes) => String::from_utf8(bytes).map_err(|e| e.to_string()),
            Err(_) => {
                // Try URL_SAFE
                base64::engine::general_purpose::URL_SAFE
                    .decode(clean_b64.as_bytes())
                    .map_err(|e| e.to_string())
                    .and_then(|bytes| String::from_utf8(bytes).map_err(|e| e.to_string()))
            }
        }
    }

    pub fn parse_uri(&mut self, uri: &str) -> Result<ParsedProxyNode, String> {
        let trimmed = uri.trim();
        if trimmed.starts_with("vless://") {
            self.parse_vless(trimmed)
        } else if trimmed.starts_with("trojan://") {
            self.parse_trojan(trimmed)
        } else if trimmed.starts_with("ss://") {
            self.parse_shadowsocks(trimmed)
        } else {
            Err(format!("Unsupported proxy protocol URI: {}", trimmed))
        }
    }

    fn parse_vless(&self, uri: &str) -> Result<ParsedProxyNode, String> {
        // format: vless://uuid@host:port?query#tag
        let rest = &uri["vless://".len()..];
        let (main_part, tag) = match rest.split_once('#') {
            Some((m, t)) => (m, t),
            None => (rest, "vless-node"),
        };

        let (authority, query) = match main_part.split_once('?') {
            Some((a, q)) => (a, q),
            None => (main_part, ""),
        };

        let (uuid, host_port) = authority
            .split_once('@')
            .ok_or_else(|| "Missing UUID in VLESS URI".to_string())?;

        let (host, port_str) = host_port
            .split_once(':')
            .ok_or_else(|| "Missing port in VLESS URI".to_string())?;

        let port = port_str.parse::<u16>().map_err(|e| e.to_string())?;

        let mut transport = "tcp".to_string();
        let mut sni = None;

        for param in query.split('&') {
            if let Some((k, v)) = param.split_once('=') {
                match k {
                    "type" => transport = v.to_string(),
                    "sni" => sni = Some(v.to_string()),
                    _ => {}
                }
            }
        }

        let node = ParsedProxyNode {
            id: format!("vless-{}:{}", host, port),
            protocol: "vless".to_string(),
            server: host.to_string(),
            port,
            credentials: uuid.to_string(),
            transport,
            sni,
            tag: tag.to_string(),
        };

        Ok(node)
    }

    fn parse_trojan(&self, uri: &str) -> Result<ParsedProxyNode, String> {
        // format: trojan://password@host:port?sni=...#tag
        let rest = &uri["trojan://".len()..];
        let (main_part, tag) = match rest.split_once('#') {
            Some((m, t)) => (m, t),
            None => (rest, "trojan-node"),
        };

        let (authority, query) = match main_part.split_once('?') {
            Some((a, q)) => (a, q),
            None => (main_part, ""),
        };

        let (password, host_port) = authority
            .split_once('@')
            .ok_or_else(|| "Missing password in Trojan URI".to_string())?;

        let (host, port_str) = host_port
            .split_once(':')
            .ok_or_else(|| "Missing port in Trojan URI".to_string())?;

        let port = port_str.parse::<u16>().map_err(|e| e.to_string())?;
        let mut sni = None;

        for param in query.split('&') {
            if let Some((k, v)) = param.split_once('=') {
                if k == "sni" {
                    sni = Some(v.to_string());
                }
            }
        }

        let node = ParsedProxyNode {
            id: format!("trojan-{}:{}", host, port),
            protocol: "trojan".to_string(),
            server: host.to_string(),
            port,
            credentials: password.to_string(),
            transport: "tcp".to_string(),
            sni,
            tag: tag.to_string(),
        };

        Ok(node)
    }

    fn parse_shadowsocks(&self, uri: &str) -> Result<ParsedProxyNode, String> {
        // format: ss://base64(method:pass)@host:port#tag
        let rest = &uri["ss://".len()..];
        let (main_part, tag) = match rest.split_once('#') {
            Some((m, t)) => (m, t),
            None => (rest, "ss-node"),
        };

        let (userinfo, host_port) = main_part
            .split_once('@')
            .ok_or_else(|| "Invalid Shadowsocks URI".to_string())?;

        let (host, port_str) = host_port
            .split_once(':')
            .ok_or_else(|| "Missing port in SS URI".to_string())?;

        let port = port_str.parse::<u16>().map_err(|e| e.to_string())?;

        let node = ParsedProxyNode {
            id: format!("ss-{}:{}", host, port),
            protocol: "shadowsocks".to_string(),
            server: host.to_string(),
            port,
            credentials: userinfo.to_string(),
            transport: "tcp".to_string(),
            sni: None,
            tag: tag.to_string(),
        };

        Ok(node)
    }

    pub fn parse_feed_content(&mut self, content: &str) -> usize {
        let decoded = match Self::decode_subscription_feed(content) {
            Ok(d) => d,
            Err(_) => return 0,
        };

        let mut added = 0;
        for line in decoded.lines() {
            let line_trimmed = line.trim();
            if !line_trimmed.is_empty() {
                if let Ok(node) = self.parse_uri(line_trimmed) {
                    self.nodes.push(node);
                    added += 1;
                }
            }
        }
        added
    }

    pub fn deduplicate(&mut self) -> usize {
        let mut seen = HashSet::new();
        let initial_len = self.nodes.len();
        self.nodes.retain(|n| seen.insert((n.protocol.clone(), n.server.clone(), n.port)));
        initial_len - self.nodes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vless_and_trojan() {
        let mut parser = CommunityFeedParser::new();
        let vless_uri = "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&sni=cdn.example.com#US-East";
        let node = parser.parse_uri(vless_uri).unwrap();
        assert_eq!(node.protocol, "vless");
        assert_eq!(node.server, "example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.sni, Some("cdn.example.com".to_string()));
        assert_eq!(node.tag, "US-East");

        let trojan_uri = "trojan://password123@node.relay.net:8443?sni=node.relay.net#DE-Frankfurt";
        let trojan_node = parser.parse_uri(trojan_uri).unwrap();
        assert_eq!(trojan_node.protocol, "trojan");
        assert_eq!(trojan_node.credentials, "password123");
    }

    #[test]
    fn test_feed_decode_and_deduplicate() {
        let mut parser = CommunityFeedParser::new();
        let plain_feed = "vless://u1@1.2.3.4:443\nvless://u1@1.2.3.4:443\ntrojan://p1@1.2.3.4:8443";
        let b64_feed = base64::engine::general_purpose::STANDARD.encode(plain_feed);

        let parsed_count = parser.parse_feed_content(&b64_feed);
        assert_eq!(parsed_count, 3);

        let removed = parser.deduplicate();
        assert_eq!(removed, 1);
        assert_eq!(parser.nodes.len(), 2);
    }
}
