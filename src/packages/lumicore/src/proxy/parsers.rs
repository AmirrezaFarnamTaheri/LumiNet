//! # Proxy Protocol Parsers
//!
//! Parsers for common proxy protocol URIs: vmess, vless, ss, trojan, hysteria2, tuic.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported proxy protocol types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProxyProtocol {
    VMess,
    VLess,
    Shadowsocks,
    ShadowsocksR,
    Trojan,
    Hysteria,
    Hysteria2,
    Tuic,
    AnyTLS,
}

/// Transport layer type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum TransportType {
    TCP,
    WebSocket,
    HTTP2,
    GRPC,
    QUIC,
    MKCP,
}

/// TLS configuration extracted from proxy URI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    pub enabled: bool,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,
    pub insecure: bool,
    /// REALITY public key
    pub reality_pk: Option<String>,
    /// REALITY short ID
    pub reality_sid: Option<String>,
    /// XTLS flow control
    pub flow: Option<String>,
}

/// WebSocket transport configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WsConfig {
    pub path: String,
    pub host: Option<String>,
    pub max_early_data: Option<u32>,
    pub early_data_header: Option<String>,
}

/// Parsed proxy node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyNode {
    pub protocol: ProxyProtocol,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: Option<String>,
    pub uuid: Option<String>,
    pub method: Option<String>,
    pub transport: TransportType,
    pub tls: TlsConfig,
    pub ws: Option<WsConfig>,
    pub tags: Vec<String>,
    pub extra: HashMap<String, String>,
}

/// Parse error type.
#[derive(Debug)]
pub enum ParseError {
    InvalidScheme,
    InvalidUrl,
    InvalidBase64,
    InvalidJson,
    MissingField(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidScheme => write!(f, "invalid URI scheme"),
            Self::InvalidUrl => write!(f, "invalid URL format"),
            Self::InvalidBase64 => write!(f, "invalid base64 encoding"),
            Self::InvalidJson => write!(f, "invalid JSON"),
            Self::MissingField(field) => write!(f, "missing required field: {}", field),
        }
    }
}

/// Parse a proxy URI into a ProxyNode.
pub fn parse_proxy_uri(uri: &str) -> Result<ProxyNode, ParseError> {
    let uri = uri.trim();
    if uri.starts_with("vmess://") {
        parse_vmess(uri)
    } else if uri.starts_with("vless://") {
        parse_vless(uri)
    } else if uri.starts_with("ss://") {
        parse_shadowsocks(uri)
    } else if uri.starts_with("ssr://") {
        parse_shadowsocks_r(uri)
    } else if uri.starts_with("trojan://") {
        parse_trojan(uri)
    } else if uri.starts_with("hysteria2://") || uri.starts_with("hy2://") {
        parse_hysteria2(uri)
    } else if uri.starts_with("tuic://") {
        parse_tuic(uri)
    } else {
        Err(ParseError::InvalidScheme)
    }
}

/// Parse vmess:// URI (V2Ray VMess, often base64-encoded JSON).
fn parse_vmess(uri: &str) -> Result<ProxyNode, ParseError> {
    let b64 = uri
        .strip_prefix("vmess://")
        .ok_or(ParseError::InvalidScheme)?;
    let decoded = BASE64.decode(b64).map_err(|_| ParseError::InvalidBase64)?;
    let json: serde_json::Value =
        serde_json::from_slice(&decoded).map_err(|_| ParseError::InvalidJson)?;

    let server = json["add"]
        .as_str()
        .ok_or_else(|| ParseError::MissingField("add".into()))?;
    let port = json["port"]
        .as_u64()
        .ok_or_else(|| ParseError::MissingField("port".into()))? as u16;
    let uuid = json["id"]
        .as_str()
        .ok_or_else(|| ParseError::MissingField("id".into()))?;
    let net = json["net"].as_str().unwrap_or("tcp");
    let tls = json["tls"].as_str().unwrap_or("");

    let transport = match net {
        "ws" => TransportType::WebSocket,
        "h2" => TransportType::HTTP2,
        "grpc" => TransportType::GRPC,
        "kcp" | "mkcp" => TransportType::MKCP,
        _ => TransportType::TCP,
    };

    let ws_config = if transport == TransportType::WebSocket {
        Some(WsConfig {
            path: json["path"].as_str().unwrap_or("/").to_string(),
            host: json["host"].as_str().map(|s| s.to_string()),
            max_early_data: json["maxEarlyData"].as_u64().map(|v| v as u32),
            early_data_header: json["earlyDataHeaderName"].as_str().map(|s| s.to_string()),
        })
    } else {
        None
    };

    Ok(ProxyNode {
        protocol: ProxyProtocol::VMess,
        name: json["ps"].as_str().unwrap_or("").to_string(),
        server: server.to_string(),
        port,
        password: None,
        uuid: Some(uuid.to_string()),
        method: json["scy"].as_str().map(|s| s.to_string()),
        transport,
        tls: TlsConfig {
            enabled: tls == "tls",
            sni: json["sni"].as_str().map(|s| s.to_string()),
            alpn: json["alpn"]
                .as_str()
                .map(|s| s.split(',').map(|a| a.to_string()).collect())
                .unwrap_or_default(),
            fingerprint: json["fp"].as_str().map(|s| s.to_string()),
            insecure: json["allowInsecure"].as_bool().unwrap_or(false),
            ..Default::default()
        },
        ws: ws_config,
        tags: vec![],
        extra: HashMap::new(),
    })
}

/// Parse vless:// URI.
fn parse_vless(uri: &str) -> Result<ProxyNode, ParseError> {
    let rest = uri
        .strip_prefix("vless://")
        .ok_or(ParseError::InvalidScheme)?;
    let (userinfo, remainder) = rest.split_once('@').ok_or(ParseError::InvalidUrl)?;
    let uuid = userinfo.to_string();

    let (host_port, query_frag) = if let Some(q) = remainder.find('?') {
        (&remainder[..q], &remainder[q + 1..])
    } else {
        (remainder, "")
    };

    let (host, port) = parse_host_port(host_port)?;
    let params = parse_query_params(query_frag);

    let net = params.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    let transport = match net {
        "ws" => TransportType::WebSocket,
        "h2" => TransportType::HTTP2,
        "grpc" => TransportType::GRPC,
        "quic" => TransportType::QUIC,
        "kcp" => TransportType::MKCP,
        _ => TransportType::TCP,
    };

    let name = if let Some(frag) = query_frag.split('#').next_back() {
        urlencoding::decode(frag).unwrap_or_default().to_string()
    } else {
        String::new()
    };

    Ok(ProxyNode {
        protocol: ProxyProtocol::VLess,
        name,
        server: host,
        port,
        password: None,
        uuid: Some(uuid),
        method: None,
        transport,
        tls: TlsConfig {
            enabled: params.get("security").map(|s| s.as_str()) == Some("tls")
                || params.get("security").map(|s| s.as_str()) == Some("reality"),
            sni: params.get("sni").cloned(),
            alpn: params
                .get("alpn")
                .map(|s| s.split(',').map(|a| a.to_string()).collect())
                .unwrap_or_default(),
            fingerprint: params.get("fp").cloned(),
            insecure: params
                .get("allowInsecure")
                .map(|s| s == "1")
                .unwrap_or(false),
            reality_pk: params.get("pbk").cloned(),
            reality_sid: params.get("sid").cloned(),
            flow: params.get("flow").cloned(),
        },
        ws: if transport == TransportType::WebSocket {
            Some(WsConfig {
                path: params
                    .get("path")
                    .cloned()
                    .unwrap_or_else(|| "/".to_string()),
                host: params.get("host").cloned(),
                max_early_data: params.get("ed").and_then(|s| s.parse().ok()),
                early_data_header: params.get("eh").cloned(),
            })
        } else {
            None
        },
        tags: vec![],
        extra: params,
    })
}

/// Parse ss:// URI (Shadowsocks).
fn parse_shadowsocks(uri: &str) -> Result<ProxyNode, ParseError> {
    let rest = uri.strip_prefix("ss://").ok_or(ParseError::InvalidScheme)?;

    // Try SIP002 format: ss://base64(method:password)@server:port#name
    if let Some(at_pos) = rest.find('@') {
        let b64_part = &rest[..at_pos];
        let decoded = BASE64
            .decode(b64_part)
            .map_err(|_| ParseError::InvalidBase64)?;
        let userinfo = String::from_utf8_lossy(&decoded);
        let (method, password) = userinfo.split_once(':').ok_or(ParseError::InvalidUrl)?;

        let remainder = &rest[at_pos + 1..];
        let (host_port, _query_frag) = if let Some(q) = remainder.find('#') {
            (&remainder[..q], &remainder[q + 1..])
        } else {
            (remainder, "")
        };
        let (host, port) = parse_host_port(host_port)?;

        return Ok(ProxyNode {
            protocol: ProxyProtocol::Shadowsocks,
            name: String::new(),
            server: host,
            port,
            password: Some(password.to_string()),
            uuid: None,
            method: Some(method.to_string()),
            transport: TransportType::TCP,
            tls: TlsConfig::default(),
            ws: None,
            tags: vec![],
            extra: HashMap::new(),
        });
    }

    // Legacy format: ss://base64(method:password@server:port)
    let decoded = BASE64.decode(rest).map_err(|_| ParseError::InvalidBase64)?;
    let s = String::from_utf8_lossy(&decoded);
    let (userinfo, host_port) = s.split_once('@').ok_or(ParseError::InvalidUrl)?;
    let (method, password) = userinfo.split_once(':').ok_or(ParseError::InvalidUrl)?;
    let (host, port) = parse_host_port(host_port)?;

    Ok(ProxyNode {
        protocol: ProxyProtocol::Shadowsocks,
        name: String::new(),
        server: host,
        port,
        password: Some(password.to_string()),
        uuid: None,
        method: Some(method.to_string()),
        transport: TransportType::TCP,
        tls: TlsConfig::default(),
        ws: None,
        tags: vec![],
        extra: HashMap::new(),
    })
}

/// Parse ssr:// URI (ShadowsocksR).
fn parse_shadowsocks_r(uri: &str) -> Result<ProxyNode, ParseError> {
    let b64 = uri
        .strip_prefix("ssr://")
        .ok_or(ParseError::InvalidScheme)?;
    let decoded = BASE64.decode(b64).map_err(|_| ParseError::InvalidBase64)?;
    let s = String::from_utf8_lossy(&decoded);

    // Format: server:port:protocol:method:obfs:base64pass/?params
    let parts: Vec<&str> = s.splitn(6, ':').collect();
    if parts.len() < 6 {
        return Err(ParseError::InvalidUrl);
    }

    let server = parts[0].to_string();
    let port: u16 = parts[1].parse().map_err(|_| ParseError::InvalidUrl)?;
    let password_b64 = parts[5].split("/?").next().unwrap_or("");
    let password = BASE64
        .decode(password_b64)
        .map(|d| String::from_utf8_lossy(&d).to_string())
        .unwrap_or_default();

    Ok(ProxyNode {
        protocol: ProxyProtocol::ShadowsocksR,
        name: String::new(),
        server,
        port,
        password: Some(password),
        uuid: None,
        method: Some(parts[3].to_string()),
        transport: TransportType::TCP,
        tls: TlsConfig::default(),
        ws: None,
        tags: vec![],
        extra: HashMap::from([
            ("protocol".to_string(), parts[2].to_string()),
            ("obfs".to_string(), parts[4].to_string()),
        ]),
    })
}

/// Parse trojan:// URI.
fn parse_trojan(uri: &str) -> Result<ProxyNode, ParseError> {
    let rest = uri
        .strip_prefix("trojan://")
        .ok_or(ParseError::InvalidScheme)?;
    let (password, remainder) = rest.split_once('@').ok_or(ParseError::InvalidUrl)?;
    let (host_port, query_frag) = if let Some(q) = remainder.find('?') {
        (&remainder[..q], &remainder[q + 1..])
    } else {
        (remainder, "")
    };
    let (host, port) = parse_host_port(host_port)?;
    let params = parse_query_params(query_frag);

    let name = if let Some(frag) = query_frag.split('#').next_back() {
        urlencoding::decode(frag).unwrap_or_default().to_string()
    } else {
        String::new()
    };

    Ok(ProxyNode {
        protocol: ProxyProtocol::Trojan,
        name,
        server: host,
        port,
        password: Some(password.to_string()),
        uuid: None,
        method: None,
        transport: match params.get("type").map(|s| s.as_str()) {
            Some("ws") => TransportType::WebSocket,
            Some("grpc") => TransportType::GRPC,
            Some("h2") => TransportType::HTTP2,
            _ => TransportType::TCP,
        },
        tls: TlsConfig {
            enabled: true,
            sni: params.get("sni").cloned(),
            alpn: params
                .get("alpn")
                .map(|s| s.split(',').map(|a| a.to_string()).collect())
                .unwrap_or_default(),
            fingerprint: params.get("fp").cloned(),
            insecure: params
                .get("allowInsecure")
                .map(|s| s == "1")
                .unwrap_or(false),
            ..Default::default()
        },
        ws: None,
        tags: vec![],
        extra: params,
    })
}

/// Parse hysteria2:// or hy2:// URI.
fn parse_hysteria2(uri: &str) -> Result<ProxyNode, ParseError> {
    let rest = uri
        .strip_prefix("hysteria2://")
        .or_else(|| uri.strip_prefix("hy2://"))
        .ok_or(ParseError::InvalidScheme)?;

    let (auth, remainder) = rest.split_once('@').ok_or(ParseError::InvalidUrl)?;
    let (host_port, query_frag) = if let Some(q) = remainder.find('?') {
        (&remainder[..q], &remainder[q + 1..])
    } else {
        (remainder, "")
    };
    let (host, port) = parse_host_port(host_port)?;
    let params = parse_query_params(query_frag);

    let name = if let Some(frag) = query_frag.split('#').next_back() {
        urlencoding::decode(frag).unwrap_or_default().to_string()
    } else {
        String::new()
    };

    Ok(ProxyNode {
        protocol: ProxyProtocol::Hysteria2,
        name,
        server: host,
        port,
        password: Some(auth.to_string()),
        uuid: None,
        method: None,
        transport: TransportType::QUIC,
        tls: TlsConfig {
            enabled: true,
            sni: params.get("sni").cloned(),
            insecure: params.get("insecure").map(|s| s == "1").unwrap_or(false),
            ..Default::default()
        },
        ws: None,
        tags: vec![],
        extra: params,
    })
}

/// Parse tuic:// URI.
fn parse_tuic(uri: &str) -> Result<ProxyNode, ParseError> {
    let rest = uri
        .strip_prefix("tuic://")
        .ok_or(ParseError::InvalidScheme)?;
    let (userinfo, remainder) = rest.split_once('@').ok_or(ParseError::InvalidUrl)?;
    let (uuid, password) = userinfo.split_once(':').ok_or(ParseError::InvalidUrl)?;

    let (host_port, query_frag) = if let Some(q) = remainder.find('?') {
        (&remainder[..q], &remainder[q + 1..])
    } else {
        (remainder, "")
    };
    let (host, port) = parse_host_port(host_port)?;
    let params = parse_query_params(query_frag);

    let name = if let Some(frag) = query_frag.split('#').next_back() {
        urlencoding::decode(frag).unwrap_or_default().to_string()
    } else {
        String::new()
    };

    Ok(ProxyNode {
        protocol: ProxyProtocol::Tuic,
        name,
        server: host,
        port,
        password: Some(password.to_string()),
        uuid: Some(uuid.to_string()),
        method: None,
        transport: TransportType::QUIC,
        tls: TlsConfig {
            enabled: true,
            sni: params.get("sni").cloned(),
            alpn: params
                .get("alpn")
                .map(|s| s.split(',').map(|a| a.to_string()).collect())
                .unwrap_or_default(),
            insecure: params
                .get("allowInsecure")
                .map(|s| s == "1")
                .unwrap_or(false),
            ..Default::default()
        },
        ws: None,
        tags: vec![],
        extra: params,
    })
}

// ─── Helpers ──────────────────────────────────────────────────────

fn parse_host_port(s: &str) -> Result<(String, u16), ParseError> {
    // Handle IPv6: [::1]:port
    let (host, port_str) = if s.starts_with('[') {
        let end = s.find(']').ok_or(ParseError::InvalidUrl)?;
        (&s[1..end], &s[end + 2..]) // skip ]:
    } else {
        s.rsplit_once(':').ok_or(ParseError::InvalidUrl)?
    };
    let port: u16 = port_str.parse().map_err(|_| ParseError::InvalidUrl)?;
    Ok((host.to_string(), port))
}

fn parse_query_params(s: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    // Strip fragment
    let query = s.split('#').next().unwrap_or("");
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            params.insert(
                urlencoding::decode(k).unwrap_or_default().to_string(),
                urlencoding::decode(v).unwrap_or_default().to_string(),
            );
        }
    }
    params
}

/// Parse a base64-encoded subscription list (one URI per line).
pub fn parse_subscription(content: &str) -> Vec<ProxyNode> {
    let decoded = if let Ok(bytes) = BASE64.decode(content.trim()) {
        String::from_utf8_lossy(&bytes).to_string()
    } else {
        content.to_string()
    };

    decoded
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .filter_map(|l| parse_proxy_uri(l).ok())
        .collect()
}

/// Parse a Clash/Mihomo YAML file to extract proxy share-links.
///
/// It scans for the `proxies:` section and parses each block into a ProxyNode.
pub fn parse_clash_yaml_proxies(yaml_text: &str) -> Vec<ProxyNode> {
    let mut nodes = Vec::new();
    let mut current_proxy = HashMap::new();
    let mut in_proxies = false;
    let mut in_proxy_block = false;

    for line in yaml_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.starts_with("proxies:") {
            in_proxies = true;
            continue;
        }

        // If we hit another top-level key after proxies, stop
        if in_proxies && !line.starts_with(' ') && !line.starts_with('-') && trimmed.contains(':') {
            if !current_proxy.is_empty() {
                if let Some(node) = build_proxy_from_map(&current_proxy) {
                    nodes.push(node);
                }
                current_proxy.clear();
            }
            in_proxies = false;
            in_proxy_block = false;
            continue;
        }

        if in_proxies {
            let is_new_item = trimmed.starts_with('-');
            let clean_line = if is_new_item {
                trimmed.strip_prefix('-').unwrap_or(trimmed).trim()
            } else {
                trimmed
            };

            if is_new_item {
                if in_proxy_block && !current_proxy.is_empty() {
                    if let Some(node) = build_proxy_from_map(&current_proxy) {
                        nodes.push(node);
                    }
                    current_proxy.clear();
                }
                in_proxy_block = true;
            }

            if in_proxy_block {
                if let Some((key, value)) = clean_line.split_once(':') {
                    let k = key.trim().to_string();
                    let mut v = value.trim().to_string();
                    if ((v.starts_with('"') && v.ends_with('"'))
                        || (v.starts_with('\'') && v.ends_with('\'')))
                        && v.len() >= 2
                    {
                        v = v[1..v.len() - 1].to_string();
                    }
                    current_proxy.insert(k, v);
                }
            }
        }
    }

    if !current_proxy.is_empty() {
        if let Some(node) = build_proxy_from_map(&current_proxy) {
            nodes.push(node);
        }
    }

    nodes
}

fn build_proxy_from_map(map: &HashMap<String, String>) -> Option<ProxyNode> {
    let p_type = map.get("type")?;
    let server = map.get("server")?;
    let port_str = map.get("port")?;
    let port: u16 = port_str.parse().ok()?;
    let name = map
        .get("name")
        .cloned()
        .unwrap_or_else(|| format!("{}:{}", server, port));

    let protocol = match p_type.to_ascii_lowercase().as_str() {
        "vmess" => ProxyProtocol::VMess,
        "vless" => ProxyProtocol::VLess,
        "ss" => ProxyProtocol::Shadowsocks,
        "trojan" => ProxyProtocol::Trojan,
        "hysteria2" | "hy2" => ProxyProtocol::Hysteria2,
        "tuic" => ProxyProtocol::Tuic,
        _ => return None,
    };

    let mut tls = TlsConfig::default();
    let tls_enabled =
        map.get("tls").map(|v| v == "true").unwrap_or(false) || protocol == ProxyProtocol::Trojan;
    if tls_enabled {
        tls.enabled = true;
        tls.sni = map.get("servername").cloned();
        tls.fingerprint = map.get("client-fingerprint").cloned();
        tls.reality_pk = map.get("public-key").cloned();
        tls.reality_sid = map.get("short-id").cloned();
        tls.flow = map.get("flow").cloned();
        tls.insecure = map
            .get("skip-cert-verify")
            .map(|v| v == "true")
            .unwrap_or(false);
    }

    let network = map
        .get("network")
        .cloned()
        .unwrap_or_else(|| "tcp".to_string());
    let transport = match network.as_str() {
        "ws" => TransportType::WebSocket,
        "h2" => TransportType::HTTP2,
        "grpc" => TransportType::GRPC,
        _ => TransportType::TCP,
    };

    let ws = if transport == TransportType::WebSocket {
        Some(WsConfig {
            path: map.get("path").cloned().unwrap_or_else(|| "/".to_string()),
            host: map.get("host").cloned(),
            max_early_data: None,
            early_data_header: None,
        })
    } else {
        None
    };

    Some(ProxyNode {
        protocol,
        name,
        server: server.clone(),
        port,
        password: map.get("password").cloned(),
        uuid: map.get("uuid").cloned(),
        method: map.get("cipher").cloned(),
        transport,
        tls,
        ws,
        tags: Vec::new(),
        extra: HashMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_vless() {
        let uri =
            "vless://uuid@server.com:443?type=ws&security=tls&sni=example.com&path=/ws#TestNode";
        let node = parse_proxy_uri(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::VLess);
        assert_eq!(node.server, "server.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.name, "TestNode");
        assert!(node.tls.enabled);
    }

    #[test]
    fn test_parse_shadowsocks() {
        let uri = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@server.com:8388#TestSS";
        let node = parse_proxy_uri(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Shadowsocks);
        assert_eq!(node.method, Some("aes-256-gcm".to_string()));
    }

    #[test]
    fn test_parse_trojan() {
        let uri =
            "trojan://password@server.com:443?security=tls&type=ws&sni=example.com#TestTrojan";
        let node = parse_proxy_uri(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Trojan);
        assert_eq!(node.password, Some("password".to_string()));
    }

    #[test]
    fn test_parse_hysteria2() {
        let uri = "hy2://password@server.com:443?sni=example.com#TestHy2";
        let node = parse_proxy_uri(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Hysteria2);
        assert_eq!(node.transport, TransportType::QUIC);
    }

    #[test]
    fn test_parse_tuic() {
        let uri = "tuic://uuid:password@server.com:443?sni=example.com#TestTuic";
        let node = parse_proxy_uri(uri).unwrap();
        assert_eq!(node.protocol, ProxyProtocol::Tuic);
        assert_eq!(node.uuid, Some("uuid".to_string()));
    }

    #[test]
    fn test_parse_host_port_ipv6() {
        let (host, port) = parse_host_port("[2001:db8::1]:443").unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_query_params() {
        let params = parse_query_params("type=ws&security=tls&sni=example.com");
        assert_eq!(params.get("type").unwrap(), "ws");
        assert_eq!(params.get("security").unwrap(), "tls");
        assert_eq!(params.get("sni").unwrap(), "example.com");
    }

    #[test]
    fn test_parse_clash_yaml() {
        let yaml = r#"
proxies:
  - name: "TestVLess"
    type: vless
    server: vless.example.com
    port: 443
    uuid: test-uuid
    tls: true
    servername: sni.example.com
    network: ws
    path: /path
  - name: "TestTrojan"
    type: trojan
    server: trojan.example.com
    port: 443
    password: test-password
"#;
        let nodes = parse_clash_yaml_proxies(yaml);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "TestVLess");
        assert_eq!(nodes[0].protocol, ProxyProtocol::VLess);
        assert_eq!(nodes[0].server, "vless.example.com");
        assert_eq!(nodes[0].port, 443);
        assert_eq!(nodes[0].uuid, Some("test-uuid".to_string()));
        assert!(nodes[0].tls.enabled);
        assert_eq!(nodes[0].tls.sni, Some("sni.example.com".to_string()));
        assert_eq!(nodes[0].transport, TransportType::WebSocket);

        assert_eq!(nodes[1].name, "TestTrojan");
        assert_eq!(nodes[1].protocol, ProxyProtocol::Trojan);
        assert_eq!(nodes[1].server, "trojan.example.com");
        assert_eq!(nodes[1].port, 443);
        assert_eq!(nodes[1].password, Some("test-password".to_string()));
    }
}
