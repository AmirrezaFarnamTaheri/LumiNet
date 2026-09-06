//! Unified Proxy URI Codec and Canonicalizer
//!
//! Parses and serializes vless://, trojan://, ss://, and hysteria2:// URIs,
//! enforcing canonical query parameter order and robust decoding.

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum ProxyUriError {
    InvalidScheme,
    MalformedAuthority,
    MissingField(&'static str),
    InvalidPort,
}

impl fmt::Display for ProxyUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScheme => write!(f, "Unsupported or missing proxy scheme"),
            Self::MalformedAuthority => write!(f, "Malformed authority component"),
            Self::MissingField(field) => write!(f, "Missing mandatory field: {}", field),
            Self::InvalidPort => write!(f, "Invalid port number"),
        }
    }
}

impl std::error::Error for ProxyUriError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalProxyNode {
    pub protocol: String,
    pub uuid_or_password: String,
    pub address: String,
    pub port: u16,
    pub remark: String,
    pub params: BTreeMap<String, String>,
}

pub struct ProxyUriCodec;

impl ProxyUriCodec {
    pub fn parse(uri: &str) -> Result<CanonicalProxyNode, ProxyUriError> {
        let trimmed = uri.trim();
        let (proto, rest) = trimmed.split_once("://").ok_or(ProxyUriError::InvalidScheme)?;
        let protocol = proto.to_lowercase();

        let (authority_and_query, remark) = if let Some((aq, rem)) = rest.split_once('#') {
            (aq, rem)
        } else {
            (rest, "")
        };

        let (authority, query) = if let Some((auth, q)) = authority_and_query.split_once('?') {
            (auth, Some(q))
        } else {
            (authority_and_query, None)
        };

        let (credentials, host_port) = authority.rsplit_once('@').ok_or(ProxyUriError::MalformedAuthority)?;
        let (host, port_str) = host_port.rsplit_once(':').ok_or(ProxyUriError::MalformedAuthority)?;
        let port: u16 = port_str.parse().map_err(|_| ProxyUriError::InvalidPort)?;

        let mut params = BTreeMap::new();
        if let Some(q) = query {
            for kv in q.split('&') {
                if let Some((k, v)) = kv.split_once('=') {
                    if !k.is_empty() {
                        params.insert(k.to_string(), v.to_string());
                    }
                }
            }
        }

        Ok(CanonicalProxyNode {
            protocol,
            uuid_or_password: credentials.to_string(),
            address: host.to_string(),
            port,
            remark: remark.to_string(),
            params,
        })
    }

    pub fn serialize(node: &CanonicalProxyNode) -> String {
        let mut query_parts = Vec::new();
        for (k, v) in &node.params {
            query_parts.push(format!("{}={}", k, v));
        }
        let query_str = if query_parts.is_empty() {
            String::new()
        } else {
            format!("?{}", query_parts.join("&"))
        };

        let remark_str = if node.remark.is_empty() {
            String::new()
        } else {
            format!("#{}", node.remark)
        };

        format!(
            "{}://{}@{}:{}{}{}",
            node.protocol, node.uuid_or_password, node.address, node.port, query_str, remark_str
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_serialize() {
        let uri = "vless://user-uuid-123@node1.net:443?encryption=none&security=tls&sni=node1.net#MyNode";
        let parsed = ProxyUriCodec::parse(uri).unwrap();
        assert_eq!(parsed.protocol, "vless");
        assert_eq!(parsed.uuid_or_password, "user-uuid-123");
        assert_eq!(parsed.address, "node1.net");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.remark, "MyNode");
        assert_eq!(parsed.params.get("security").map(|s| s.as_str()), Some("tls"));

        let reserialized = ProxyUriCodec::serialize(&parsed);
        let roundtrip = ProxyUriCodec::parse(&reserialized).unwrap();
        assert_eq!(parsed, roundtrip);
    }
}
