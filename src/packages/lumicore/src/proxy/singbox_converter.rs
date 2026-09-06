//! Multi-protocol proxy parser and sing-box client configuration generator.
//!

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unified proxy node descriptor across all major proxy protocols.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SingboxProxyNode {
    #[serde(rename = "type")]
    pub protocol_type: String,
    pub tag: String,
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub alter_id: u16,
    pub security: String,
    pub method: String,
    pub password: String,
    pub plugin: String,
    pub plugin_opts: String,
    pub flow: String,
    pub network: String,
    pub tls_enabled: bool,
    pub tls_server_name: String,
    pub tls_insecure: bool,
    pub tls_alpn: Vec<String>,
    pub tls_utls_fingerprint: String,
    pub tls_reality_enabled: bool,
    pub tls_reality_public_key: String,
    pub tls_reality_short_id: String,
    pub transport_type: String,
    pub transport_path: String,
    pub transport_host: Vec<String>,
    pub transport_service_name: String,
    pub obfs_type: String,
    pub obfs_password: String,
    pub congestion_control: String,
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub packet_encoding: String,
    pub server_ports: Vec<String>,
}

impl Default for SingboxProxyNode {
    fn default() -> Self {
        Self {
            protocol_type: String::new(),
            tag: String::new(),
            server: String::new(),
            port: 0,
            uuid: String::new(),
            alter_id: 0,
            security: "auto".to_string(),
            method: String::new(),
            password: String::new(),
            plugin: String::new(),
            plugin_opts: String::new(),
            flow: String::new(),
            network: "tcp".to_string(),
            tls_enabled: true,
            tls_server_name: String::new(),
            tls_insecure: false,
            tls_alpn: Vec::new(),
            tls_utls_fingerprint: String::new(),
            tls_reality_enabled: false,
            tls_reality_public_key: String::new(),
            tls_reality_short_id: String::new(),
            transport_type: String::new(),
            transport_path: String::new(),
            transport_host: Vec::new(),
            transport_service_name: String::new(),
            obfs_type: String::new(),
            obfs_password: String::new(),
            congestion_control: "cubic".to_string(),
            up_mbps: 0,
            down_mbps: 0,
            packet_encoding: "xudp".to_string(),
            server_ports: Vec::new(),
        }
    }
}

/// Helper function to decode standard or url-safe base64 strings with loose padding.
pub fn b64_decode_loose(s: &str) -> Result<String, String> {
    let clean = s.trim();
    let mut padded = clean.to_string();
    let pad_len = (4 - (padded.len() % 4)) % 4;
    for _ in 0..pad_len {
        padded.push('=');
    }

    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&padded) {
        return String::from_utf8(bytes).map_err(|e| e.to_string());
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE.decode(&padded) {
        return String::from_utf8(bytes).map_err(|e| e.to_string());
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(clean) {
        return String::from_utf8(bytes).map_err(|e| e.to_string());
    }
    if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(clean) {
        return String::from_utf8(bytes).map_err(|e| e.to_string());
    }
    Err("Failed to decode base64".to_string())
}

/// Parses URL query parameters into a HashMap.
fn parse_query_params(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in query.split('&') {
        if let Some((k, v)) = part.split_once('=') {
            let decoded_val = urlencoding::decode(v).unwrap_or_else(|_| v.into()).to_string();
            map.insert(k.to_string(), decoded_val);
        }
    }
    map
}

/// Parses a VMess URL in format: vmess://<base64-json>
pub fn parse_vmess(url: &str) -> Result<SingboxProxyNode, String> {
    let raw = url.strip_prefix("vmess://").ok_or("Not a vmess URL")?;
    let decoded = b64_decode_loose(raw)?;
    let val: serde_json::Value =
        serde_json::from_str(&decoded).map_err(|e| format!("Invalid VMess JSON: {}", e))?;

    let mut node = SingboxProxyNode {
        protocol_type: "vmess".to_string(),
        ..Default::default()
    };

    node.tag = val
        .get("ps")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| val.get("add").and_then(|v| v.as_str()))
        .unwrap_or("vmess")
        .to_string();

    node.server = val.get("add").and_then(|v| v.as_str()).unwrap_or("").to_string();
    node.port = val
        .get("port")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0) as u16;

    if node.port == 0 || node.server.is_empty() {
        return Err("Missing VMess server or port".to_string());
    }

    node.uuid = val.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    node.alter_id = val
        .get("aid")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0) as u16;
    node.security = val
        .get("scy")
        .and_then(|v| v.as_str())
        .unwrap_or("auto")
        .to_string();
    node.network = val.get("net").and_then(|v| v.as_str()).unwrap_or("tcp").to_string();

    let tls = val.get("tls").and_then(|v| v.as_str()).unwrap_or("");
    node.tls_enabled = tls == "tls";
    node.tls_server_name = val
        .get("sni")
        .and_then(|v| v.as_str())
        .or_else(|| val.get("host").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    let host = val.get("host").and_then(|v| v.as_str()).unwrap_or("");
    let path = val.get("path").and_then(|v| v.as_str()).unwrap_or("");

    match node.network.as_str() {
        "ws" => {
            node.transport_type = "ws".to_string();
            node.transport_path = path.to_string();
            if !host.is_empty() {
                node.transport_host = vec![host.to_string()];
            }
        }
        "grpc" => {
            node.transport_type = "grpc".to_string();
            node.transport_service_name = if path.is_empty() { "grpc".to_string() } else { path.to_string() };
        }
        "h2" | "http" => {
            node.transport_type = "http".to_string();
            node.transport_path = path.to_string();
            if !host.is_empty() {
                node.transport_host = vec![host.to_string()];
            }
        }
        "quic" => {
            node.transport_type = "quic".to_string();
        }
        _ => {}
    }

    if node.tls_server_name.is_empty() && !host.is_empty() {
        node.tls_server_name = host.to_string();
    }

    Ok(node)
}

/// Parses a VLESS URL in format: vless://<uuid>@<host>:<port>?<query>#<tag>
pub fn parse_vless(url: &str) -> Result<SingboxProxyNode, String> {
    let raw = url.strip_prefix("vless://").ok_or("Not a vless URL")?;
    let (main, fragment) = match raw.split_once('#') {
        Some((m, f)) => (m, urlencoding::decode(f).unwrap_or_else(|_| f.into()).to_string()),
        None => (raw, "vless".to_string()),
    };

    let (userinfo, hostinfo) = main.split_once('@').ok_or("Missing '@' in VLESS URL")?;
    let (hostport, query) = hostinfo.split_once('?').unwrap_or((hostinfo, ""));

    let (server, port_str) = hostport.rsplit_once(':').ok_or("Missing port in VLESS host")?;
    let port = port_str.parse::<u16>().map_err(|e| format!("Invalid port: {}", e))?;

    let params = parse_query_params(query);
    let mut node = SingboxProxyNode {
        protocol_type: "vless".to_string(),
        tag: fragment,
        server: server.to_string(),
        port,
        uuid: urlencoding::decode(userinfo).unwrap_or_else(|_| userinfo.into()).to_string(),
        flow: params.get("flow").cloned().unwrap_or_default(),
        network: params.get("type").cloned().unwrap_or_else(|| "tcp".to_string()),
        ..Default::default()
    };

    let security = params.get("security").map(|s| s.as_str()).unwrap_or("tls");
    node.security = security.to_string();
    node.tls_enabled = security == "tls" || security == "reality";
    node.tls_server_name = params
        .get("sni")
        .or_else(|| params.get("host"))
        .cloned()
        .unwrap_or_default();
    node.tls_insecure = params.get("allowInsecure").map(|v| v == "1").unwrap_or(false);

    if let Some(fp) = params.get("fp") {
        node.tls_utls_fingerprint = fp.clone();
    }

    if let Some(pbk) = params.get("pbk") {
        node.tls_reality_enabled = true;
        node.tls_reality_public_key = pbk.clone();
        node.tls_reality_short_id = params.get("sid").cloned().unwrap_or_default();
    }

    if let Some(alpn) = params.get("alpn") {
        node.tls_alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
    }

    let transport = params.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    match transport {
        "ws" => {
            node.transport_type = "ws".to_string();
            node.transport_path = params.get("path").cloned().unwrap_or_default();
            if let Some(host) = params.get("host") {
                node.transport_host = vec![host.clone()];
            }
        }
        "grpc" => {
            node.transport_type = "grpc".to_string();
            node.transport_service_name = params.get("serviceName").cloned().unwrap_or_else(|| "grpc".to_string());
        }
        "h2" | "http" => {
            node.transport_type = "http".to_string();
            node.transport_path = params.get("path").cloned().unwrap_or_default();
            if let Some(host) = params.get("host") {
                node.transport_host = host.split(',').map(|s| s.trim().to_string()).collect();
            }
        }
        "quic" => {
            node.transport_type = "quic".to_string();
        }
        _ => {}
    }

    node.packet_encoding = params.get("packetEncoding").cloned().unwrap_or_else(|| "xudp".to_string());

    if node.tls_server_name.is_empty() {
        if let Some(h) = params.get("host") {
            node.tls_server_name = h.clone();
        }
    }

    Ok(node)
}

/// Parses a Trojan URL in format: trojan://<password>@<host>:<port>?<query>#<tag>
pub fn parse_trojan(url: &str) -> Result<SingboxProxyNode, String> {
    let raw = url.strip_prefix("trojan://").ok_or("Not a trojan URL")?;
    let (main, fragment) = match raw.split_once('#') {
        Some((m, f)) => (m, urlencoding::decode(f).unwrap_or_else(|_| f.into()).to_string()),
        None => (raw, "trojan".to_string()),
    };

    let (userinfo, hostinfo) = main.split_once('@').ok_or("Missing '@' in Trojan URL")?;
    let (hostport, query) = hostinfo.split_once('?').unwrap_or((hostinfo, ""));

    let (server, port_str) = hostport.rsplit_once(':').ok_or("Missing port in Trojan host")?;
    let port = port_str.parse::<u16>().map_err(|e| format!("Invalid port: {}", e))?;

    let params = parse_query_params(query);
    let mut node = SingboxProxyNode {
        protocol_type: "trojan".to_string(),
        tag: fragment,
        server: server.to_string(),
        port,
        password: urlencoding::decode(userinfo).unwrap_or_else(|_| userinfo.into()).to_string(),
        network: params.get("type").cloned().unwrap_or_else(|| "tcp".to_string()),
        tls_enabled: true,
        ..Default::default()
    };

    node.tls_server_name = params.get("sni").or_else(|| params.get("host")).cloned().unwrap_or_default();
    node.tls_insecure = params.get("allowInsecure").map(|v| v == "1").unwrap_or(false);

    if let Some(fp) = params.get("fp") {
        node.tls_utls_fingerprint = fp.clone();
    }
    if let Some(alpn) = params.get("alpn") {
        node.tls_alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
    }

    let transport = params.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    match transport {
        "ws" => {
            node.transport_type = "ws".to_string();
            node.transport_path = params.get("path").cloned().unwrap_or_default();
            if let Some(host) = params.get("host") {
                node.transport_host = vec![host.clone()];
            }
        }
        "grpc" => {
            node.transport_type = "grpc".to_string();
            node.transport_service_name = params.get("serviceName").cloned().unwrap_or_else(|| "grpc".to_string());
        }
        "h2" | "http" => {
            node.transport_type = "http".to_string();
            node.transport_path = params.get("path").cloned().unwrap_or_default();
            if let Some(host) = params.get("host") {
                node.transport_host = vec![host.clone()];
            }
        }
        "httpupgrade" => {
            node.transport_type = "httpupgrade".to_string();
            node.transport_path = params.get("path").cloned().unwrap_or_default();
            if let Some(host) = params.get("host") {
                node.transport_host = vec![host.clone()];
            }
        }
        _ => {}
    }

    Ok(node)
}

/// Parses a Shadowsocks URL in format: ss://<base64>#<tag> or ss://<userinfo>@<host>:<port>#<tag>
pub fn parse_shadowsocks(url: &str) -> Result<SingboxProxyNode, String> {
    let raw = url.strip_prefix("ss://").ok_or("Not an ss URL")?;
    let (main, fragment) = match raw.split_once('#') {
        Some((m, f)) => (m, urlencoding::decode(f).unwrap_or_else(|_| f.into()).to_string()),
        None => (raw, "ss".to_string()),
    };

    let mut node = SingboxProxyNode {
        protocol_type: "shadowsocks".to_string(),
        tag: fragment,
        tls_enabled: false,
        ..Default::default()
    };

    if main.contains('@') {
        let (userinfo, hostinfo) = main.split_once('@').unwrap();
        let decoded_user = b64_decode_loose(userinfo).unwrap_or_else(|_| userinfo.to_string());
        if let Some((m, p)) = decoded_user.split_once(':') {
            node.method = m.to_string();
            node.password = p.to_string();
        } else {
            node.method = decoded_user;
        }

        let (hostport, query) = hostinfo.split_once('?').unwrap_or((hostinfo, ""));
        let (server, port_str) = hostport.rsplit_once(':').ok_or("Missing port in SS host")?;
        node.server = server.to_string();
        node.port = port_str.parse::<u16>().map_err(|e| format!("Invalid port: {}", e))?;

        let params = parse_query_params(query);
        if let Some(plugin) = params.get("plugin") {
            node.plugin = plugin.clone();
            node.plugin_opts = params.get("plugin-opts").cloned().unwrap_or_default();
        }
    } else {
        let decoded = b64_decode_loose(main)?;
        if let Some((userpart, hostpart)) = decoded.split_once('@') {
            if let Some((m, p)) = userpart.split_once(':') {
                node.method = m.to_string();
                node.password = p.to_string();
            }
            let (hostport, query) = hostpart.split_once('?').unwrap_or((hostpart, ""));
            let (server, port_str) = hostport.rsplit_once(':').ok_or("Missing port in decoded SS")?;
            node.server = server.to_string();
            node.port = port_str.parse::<u16>().map_err(|e| format!("Invalid port: {}", e))?;
            let params = parse_query_params(query);
            if let Some(plugin) = params.get("plugin") {
                node.plugin = plugin.clone();
            }
        } else if let Ok(val) = serde_json::from_str::<serde_json::Value>(&decoded) {
            node.server = val.get("server").and_then(|v| v.as_str()).unwrap_or("").to_string();
            node.port = val.get("server_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            node.method = val.get("method").and_then(|v| v.as_str()).unwrap_or("").to_string();
            node.password = val.get("password").and_then(|v| v.as_str()).unwrap_or("").to_string();
            node.plugin = val.get("plugin").and_then(|v| v.as_str()).unwrap_or("").to_string();
            node.plugin_opts = val.get("plugin_opts").and_then(|v| v.as_str()).unwrap_or("").to_string();
        } else {
            return Err("Unrecognized SS base64 format".to_string());
        }
    }

    Ok(node)
}

/// Parses Hysteria2 URL: hysteria2://<password>@<server>:<port>?<query>#<tag>
pub fn parse_hysteria2(url: &str) -> Result<SingboxProxyNode, String> {
    let raw = url
        .strip_prefix("hysteria2://")
        .or_else(|| url.strip_prefix("hy2://"))
        .ok_or("Not a hysteria2 URL")?;

    let (main, fragment) = match raw.split_once('#') {
        Some((m, f)) => (m, urlencoding::decode(f).unwrap_or_else(|_| f.into()).to_string()),
        None => (raw, "hy2".to_string()),
    };

    let (userinfo, hostinfo) = main.split_once('@').ok_or("Missing '@' in Hysteria2 URL")?;
    let (hostport, query) = hostinfo.split_once('?').unwrap_or((hostinfo, ""));

    let (server, port_str) = hostport.rsplit_once(':').ok_or("Missing port in Hysteria2 host")?;
    let port = port_str.parse::<u16>().map_err(|e| format!("Invalid port: {}", e))?;

    let params = parse_query_params(query);
    let mut node = SingboxProxyNode {
        protocol_type: "hysteria2".to_string(),
        tag: fragment,
        server: server.to_string(),
        port,
        password: urlencoding::decode(userinfo).unwrap_or_else(|_| userinfo.into()).to_string(),
        tls_enabled: true,
        tls_server_name: params.get("sni").cloned().unwrap_or_default(),
        tls_insecure: params.get("insecure").map(|v| v == "1").unwrap_or(false),
        ..Default::default()
    };

    if let Some(obfs) = params.get("obfs") {
        node.obfs_type = "salamander".to_string();
        node.obfs_password = obfs.clone();
    }
    if let Some(alpn) = params.get("alpn") {
        node.tls_alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
    }
    if let Some(up) = params.get("up_mbps").and_then(|s| s.parse().ok()) {
        node.up_mbps = up;
    }
    if let Some(down) = params.get("down_mbps").and_then(|s| s.parse().ok()) {
        node.down_mbps = down;
    }
    if let Some(mport) = params.get("mport").or_else(|| params.get("ports")) {
        node.server_ports = vec![mport.clone()];
    }

    Ok(node)
}

/// Parses TUIC URL: tuic://<uuid>:<pass>@<server>:<port>?<query>#<tag>
pub fn parse_tuic(url: &str) -> Result<SingboxProxyNode, String> {
    let raw = url.strip_prefix("tuic://").ok_or("Not a tuic URL")?;
    let (main, fragment) = match raw.split_once('#') {
        Some((m, f)) => (m, urlencoding::decode(f).unwrap_or_else(|_| f.into()).to_string()),
        None => (raw, "tuic".to_string()),
    };

    let (userinfo, hostinfo) = main.split_once('@').ok_or("Missing '@' in TUIC URL")?;
    let decoded_user = urlencoding::decode(userinfo).unwrap_or_else(|_| userinfo.into()).to_string();

    let (uuid, password) = match decoded_user.split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (decoded_user, String::new()),
    };

    let (hostport, query) = hostinfo.split_once('?').unwrap_or((hostinfo, ""));
    let (server, port_str) = hostport.rsplit_once(':').ok_or("Missing port in TUIC host")?;
    let port = port_str.parse::<u16>().map_err(|e| format!("Invalid port: {}", e))?;

    let params = parse_query_params(query);
    let pass = if password.is_empty() {
        params.get("password").cloned().unwrap_or_default()
    } else {
        password
    };

    let mut node = SingboxProxyNode {
        protocol_type: "tuic".to_string(),
        tag: fragment,
        server: server.to_string(),
        port,
        uuid,
        password: pass,
        congestion_control: params.get("congestion_control").cloned().unwrap_or_else(|| "cubic".to_string()),
        tls_enabled: true,
        tls_server_name: params.get("sni").cloned().unwrap_or_default(),
        tls_insecure: params.get("allowInsecure").map(|v| v == "1").unwrap_or(false),
        ..Default::default()
    };

    if let Some(alpn) = params.get("alpn") {
        node.tls_alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
    }

    Ok(node)
}

/// Parses WireGuard URL: wireguard://<private_key>@<server>:<port>?peerPublicKey=<peer_key>#<tag>
pub fn parse_wireguard(url: &str) -> Result<SingboxProxyNode, String> {
    let raw = url
        .strip_prefix("wireguard://")
        .or_else(|| url.strip_prefix("wg://"))
        .ok_or("Not a wireguard URL")?;

    let (main, fragment) = match raw.split_once('#') {
        Some((m, f)) => (m, urlencoding::decode(f).unwrap_or_else(|_| f.into()).to_string()),
        None => (raw, "wg".to_string()),
    };

    let (hostpart, query) = main.split_once('?').unwrap_or((main, ""));
    let params = parse_query_params(query);

    let mut node = SingboxProxyNode {
        protocol_type: "wireguard".to_string(),
        tag: fragment,
        tls_enabled: false,
        ..Default::default()
    };

    if hostpart.contains('@') {
        let (priv_part, hp) = hostpart.split_once('@').unwrap();
        node.password = priv_part.to_string(); // password stores privateKey
        if let Some((s, p)) = hp.rsplit_once(':') {
            node.server = s.to_string();
            node.port = p.parse().unwrap_or(51820);
        } else {
            node.server = hp.to_string();
            node.port = 51820;
        }
    }

    if let Some(pk) = params.get("privateKey") {
        node.password = pk.clone();
    }
    if let Some(pubk) = params.get("peerPublicKey") {
        node.uuid = pubk.clone(); // uuid stores peerPublicKey
    }

    Ok(node)
}

/// Universal URL parser detecting protocol prefix and dispatching to corresponding parser.
pub fn parse_proxy_url(url: &str) -> Result<SingboxProxyNode, String> {
    let trimmed = url.trim();
    if trimmed.starts_with("vmess://") {
        parse_vmess(trimmed)
    } else if trimmed.starts_with("vless://") {
        parse_vless(trimmed)
    } else if trimmed.starts_with("trojan://") {
        parse_trojan(trimmed)
    } else if trimmed.starts_with("ss://") {
        parse_shadowsocks(trimmed)
    } else if trimmed.starts_with("hysteria2://") || trimmed.starts_with("hy2://") {
        parse_hysteria2(trimmed)
    } else if trimmed.starts_with("tuic://") {
        parse_tuic(trimmed)
    } else if trimmed.starts_with("wireguard://") || trimmed.starts_with("wg://") {
        parse_wireguard(trimmed)
    } else {
        Err(format!("Unsupported proxy protocol URL: {}", trimmed))
    }
}

/// Converts a single SingboxProxyNode into a sing-box 1.10+ compatible outbound JSON Value.
pub fn build_singbox_outbound(node: &SingboxProxyNode) -> serde_json::Value {
    let mut ob = serde_json::Map::new();
    ob.insert("type".to_string(), serde_json::Value::String(node.protocol_type.clone()));
    ob.insert("tag".to_string(), serde_json::Value::String(node.tag.clone()));
    ob.insert("server".to_string(), serde_json::Value::String(node.server.clone()));
    ob.insert("server_port".to_string(), serde_json::Value::Number(node.port.into()));

    match node.protocol_type.as_str() {
        "vmess" => {
            ob.insert("uuid".to_string(), serde_json::Value::String(node.uuid.clone()));
            ob.insert("security".to_string(), serde_json::Value::String(node.security.clone()));
            ob.insert("alter_id".to_string(), serde_json::Value::Number(node.alter_id.into()));
            ob.insert("global_padding".to_string(), serde_json::Value::Bool(false));
            ob.insert("authenticated_length".to_string(), serde_json::Value::Bool(true));
            ob.insert("network".to_string(), serde_json::Value::String(node.network.clone()));
            if !node.packet_encoding.is_empty() {
                ob.insert("packet_encoding".to_string(), serde_json::Value::String(node.packet_encoding.clone()));
            }
        }
        "vless" => {
            ob.insert("uuid".to_string(), serde_json::Value::String(node.uuid.clone()));
            if !node.flow.is_empty() {
                ob.insert("flow".to_string(), serde_json::Value::String(node.flow.clone()));
            }
            ob.insert("network".to_string(), serde_json::Value::String(node.network.clone()));
            ob.insert("packet_encoding".to_string(), serde_json::Value::String(node.packet_encoding.clone()));
        }
        "trojan" => {
            ob.insert("password".to_string(), serde_json::Value::String(node.password.clone()));
            ob.insert("network".to_string(), serde_json::Value::String(node.network.clone()));
        }
        "shadowsocks" => {
            ob.insert("method".to_string(), serde_json::Value::String(node.method.clone()));
            ob.insert("password".to_string(), serde_json::Value::String(node.password.clone()));
            ob.insert("network".to_string(), serde_json::Value::String(node.network.clone()));
            if !node.plugin.is_empty() {
                ob.insert("plugin".to_string(), serde_json::Value::String(node.plugin.clone()));
                if !node.plugin_opts.is_empty() {
                    ob.insert("plugin_opts".to_string(), serde_json::Value::String(node.plugin_opts.clone()));
                }
            }
        }
        "hysteria2" => {
            ob.insert("password".to_string(), serde_json::Value::String(node.password.clone()));
            if node.up_mbps > 0 {
                ob.insert("up_mbps".to_string(), serde_json::Value::Number(node.up_mbps.into()));
            }
            if node.down_mbps > 0 {
                ob.insert("down_mbps".to_string(), serde_json::Value::Number(node.down_mbps.into()));
            }
            if !node.obfs_type.is_empty() {
                let mut obfs = serde_json::Map::new();
                obfs.insert("type".to_string(), serde_json::Value::String(node.obfs_type.clone()));
                obfs.insert("password".to_string(), serde_json::Value::String(node.obfs_password.clone()));
                ob.insert("obfs".to_string(), serde_json::Value::Object(obfs));
            }
            if !node.server_ports.is_empty() {
                ob.insert(
                    "server_ports".to_string(),
                    serde_json::Value::Array(
                        node.server_ports.iter().map(|p| serde_json::Value::String(p.clone())).collect(),
                    ),
                );
            }
        }
        "tuic" => {
            ob.insert("uuid".to_string(), serde_json::Value::String(node.uuid.clone()));
            if !node.password.is_empty() {
                ob.insert("password".to_string(), serde_json::Value::String(node.password.clone()));
            }
            ob.insert("congestion_control".to_string(), serde_json::Value::String(node.congestion_control.clone()));
            ob.insert("udp_relay_mode".to_string(), serde_json::Value::String("native".to_string()));
            ob.insert("zero_rtt_handshake".to_string(), serde_json::Value::Bool(false));
            ob.insert("heartbeat".to_string(), serde_json::Value::String("10s".to_string()));
        }
        "wireguard" => {
            ob.insert(
                "local_address".to_string(),
                serde_json::Value::Array(vec![serde_json::Value::String("10.0.0.2/32".to_string())]),
            );
            ob.insert("private_key".to_string(), serde_json::Value::String(node.password.clone()));
            ob.insert("peer_public_key".to_string(), serde_json::Value::String(node.uuid.clone()));
            ob.insert(
                "reserved".to_string(),
                serde_json::Value::Array(vec![
                    serde_json::Value::Number(0.into()),
                    serde_json::Value::Number(0.into()),
                    serde_json::Value::Number(0.into()),
                ]),
            );
            ob.insert("mtu".to_string(), serde_json::Value::Number(1408.into()));
        }
        _ => {}
    }

    if node.tls_enabled {
        let mut tls = serde_json::Map::new();
        tls.insert("enabled".to_string(), serde_json::Value::Bool(true));
        if !node.tls_server_name.is_empty() {
            tls.insert("server_name".to_string(), serde_json::Value::String(node.tls_server_name.clone()));
        }
        if node.tls_insecure {
            tls.insert("insecure".to_string(), serde_json::Value::Bool(true));
        }
        if !node.tls_alpn.is_empty() {
            tls.insert(
                "alpn".to_string(),
                serde_json::Value::Array(
                    node.tls_alpn.iter().map(|a| serde_json::Value::String(a.clone())).collect(),
                ),
            );
        }
        if !node.tls_utls_fingerprint.is_empty() {
            let mut utls = serde_json::Map::new();
            utls.insert("enabled".to_string(), serde_json::Value::Bool(true));
            utls.insert("fingerprint".to_string(), serde_json::Value::String(node.tls_utls_fingerprint.clone()));
            tls.insert("utls".to_string(), serde_json::Value::Object(utls));
        }
        if node.tls_reality_enabled {
            let mut reality = serde_json::Map::new();
            reality.insert("enabled".to_string(), serde_json::Value::Bool(true));
            reality.insert("public_key".to_string(), serde_json::Value::String(node.tls_reality_public_key.clone()));
            reality.insert("short_id".to_string(), serde_json::Value::String(node.tls_reality_short_id.clone()));
            tls.insert("reality".to_string(), serde_json::Value::Object(reality));
        }
        ob.insert("tls".to_string(), serde_json::Value::Object(tls));
    }

    if !node.transport_type.is_empty() && matches!(node.protocol_type.as_str(), "vmess" | "vless" | "trojan") {
        let mut transport = serde_json::Map::new();
        transport.insert("type".to_string(), serde_json::Value::String(node.transport_type.clone()));
        match node.transport_type.as_str() {
            "ws" => {
                if !node.transport_path.is_empty() {
                    transport.insert("path".to_string(), serde_json::Value::String(node.transport_path.clone()));
                }
                if let Some(host) = node.transport_host.first() {
                    let mut headers = serde_json::Map::new();
                    headers.insert("Host".to_string(), serde_json::Value::String(host.clone()));
                    transport.insert("headers".to_string(), serde_json::Value::Object(headers));
                }
            }
            "grpc" => {
                transport.insert(
                    "service_name".to_string(),
                    serde_json::Value::String(if node.transport_service_name.is_empty() {
                        "grpc".to_string()
                    } else {
                        node.transport_service_name.clone()
                    }),
                );
            }
            "http" => {
                if !node.transport_host.is_empty() {
                    transport.insert(
                        "host".to_string(),
                        serde_json::Value::Array(
                            node.transport_host.iter().map(|h| serde_json::Value::String(h.clone())).collect(),
                        ),
                    );
                }
                if !node.transport_path.is_empty() {
                    transport.insert("path".to_string(), serde_json::Value::String(node.transport_path.clone()));
                }
            }
            _ => {}
        }
        ob.insert("transport".to_string(), serde_json::Value::Object(transport));
    }

    serde_json::Value::Object(ob)
}

/// Options configuring the generated sing-box client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingboxConfigOptions {
    pub listen: String,
    pub mixed_port: u16,
    pub tun_enabled: bool,
    pub tun_mtu: u32,
    pub auto_urltest: bool,
    pub test_url: String,
    pub experimental_clash_api: bool,
    pub clash_api_port: u16,
}

impl Default for SingboxConfigOptions {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1".to_string(),
            mixed_port: 2080,
            tun_enabled: false,
            tun_mtu: 9000,
            auto_urltest: true,
            test_url: "https://www.gstatic.com/generate_204".to_string(),
            experimental_clash_api: true,
            clash_api_port: 9090,
        }
    }
}

/// Builds a complete, production-grade sing-box JSON configuration from a list of SingboxProxyNodes.
pub fn build_singbox_full_config(nodes: &[SingboxProxyNode], opts: &SingboxConfigOptions) -> serde_json::Value {
    let mut outbounds = Vec::new();
    let mut proxy_tags = Vec::new();

    for node in nodes {
        let ob = build_singbox_outbound(node);
        proxy_tags.push(node.tag.clone());
        outbounds.push(ob);
    }

    let mut selector_outbounds = Vec::new();
    if opts.auto_urltest && !proxy_tags.is_empty() {
        selector_outbounds.push(serde_json::Value::String("auto".to_string()));
    }
    for tag in &proxy_tags {
        selector_outbounds.push(serde_json::Value::String(tag.clone()));
    }
    selector_outbounds.push(serde_json::Value::String("direct".to_string()));

    let mut all_outbounds = Vec::new();

    // 1. Selector outbound
    let mut selector = serde_json::Map::new();
    selector.insert("type".to_string(), serde_json::Value::String("selector".to_string()));
    selector.insert("tag".to_string(), serde_json::Value::String("select".to_string()));
    selector.insert("outbounds".to_string(), serde_json::Value::Array(selector_outbounds));
    selector.insert(
        "default".to_string(),
        serde_json::Value::String(if opts.auto_urltest { "auto".to_string() } else { "select".to_string() }),
    );
    all_outbounds.push(serde_json::Value::Object(selector));

    // 2. URLTest outbound
    if opts.auto_urltest && !proxy_tags.is_empty() {
        let mut urltest = serde_json::Map::new();
        urltest.insert("type".to_string(), serde_json::Value::String("urltest".to_string()));
        urltest.insert("tag".to_string(), serde_json::Value::String("auto".to_string()));
        urltest.insert(
            "outbounds".to_string(),
            serde_json::Value::Array(proxy_tags.iter().map(|t| serde_json::Value::String(t.clone())).collect()),
        );
        urltest.insert("url".to_string(), serde_json::Value::String(opts.test_url.clone()));
        urltest.insert("interval".to_string(), serde_json::Value::String("3m".to_string()));
        urltest.insert("tolerance".to_string(), serde_json::Value::Number(50.into()));
        urltest.insert("idle_timeout".to_string(), serde_json::Value::String("30m".to_string()));
        all_outbounds.push(serde_json::Value::Object(urltest));
    }

    // 3. User node outbounds
    all_outbounds.extend(outbounds);

    // 4. Built-in outbounds (direct, block, dns-out)
    let mut direct = serde_json::Map::new();
    direct.insert("type".to_string(), serde_json::Value::String("direct".to_string()));
    direct.insert("tag".to_string(), serde_json::Value::String("direct".to_string()));
    all_outbounds.push(serde_json::Value::Object(direct));

    let mut block = serde_json::Map::new();
    block.insert("type".to_string(), serde_json::Value::String("block".to_string()));
    block.insert("tag".to_string(), serde_json::Value::String("block".to_string()));
    all_outbounds.push(serde_json::Value::Object(block));

    let mut dns_out = serde_json::Map::new();
    dns_out.insert("type".to_string(), serde_json::Value::String("dns".to_string()));
    dns_out.insert("tag".to_string(), serde_json::Value::String("dns-out".to_string()));
    all_outbounds.push(serde_json::Value::Object(dns_out));

    // Inbounds
    let mut inbounds = Vec::new();
    if opts.tun_enabled {
        let mut tun = serde_json::Map::new();
        tun.insert("type".to_string(), serde_json::Value::String("tun".to_string()));
        tun.insert("tag".to_string(), serde_json::Value::String("tun-in".to_string()));
        tun.insert(
            "address".to_string(),
            serde_json::Value::Array(vec![
                serde_json::Value::String("172.19.0.1/30".to_string()),
                serde_json::Value::String("fdfe:dcba:9876::1/126".to_string()),
            ]),
        );
        tun.insert("mtu".to_string(), serde_json::Value::Number(opts.tun_mtu.into()));
        tun.insert("auto_route".to_string(), serde_json::Value::Bool(true));
        tun.insert("strict_route".to_string(), serde_json::Value::Bool(true));
        tun.insert("stack".to_string(), serde_json::Value::String("system".to_string()));
        tun.insert("dns_mode".to_string(), serde_json::Value::String("hijack".to_string()));
        tun.insert(
            "dns_address".to_string(),
            serde_json::Value::Array(vec![
                serde_json::Value::String("172.19.0.2".to_string()),
                serde_json::Value::String("fdfe:dcba:9876::2".to_string()),
            ]),
        );
        inbounds.push(serde_json::Value::Object(tun));
    }

    let mut mixed = serde_json::Map::new();
    mixed.insert("type".to_string(), serde_json::Value::String("mixed".to_string()));
    mixed.insert("tag".to_string(), serde_json::Value::String("mixed-in".to_string()));
    mixed.insert("listen".to_string(), serde_json::Value::String(opts.listen.clone()));
    mixed.insert("listen_port".to_string(), serde_json::Value::Number(opts.mixed_port.into()));
    mixed.insert("set_system_proxy".to_string(), serde_json::Value::Bool(false));
    inbounds.push(serde_json::Value::Object(mixed));

    // DNS configuration
    let dns_json = serde_json::json!({
        "servers": [
            {"tag": "google", "address": "tls://8.8.8.8", "detour": "select"},
            {"tag": "local", "address": "223.5.5.5", "detour": "direct"}
        ],
        "rules": [
            {"outbound": ["any"], "server": "local"}
        ],
        "final": "google",
        "strategy": "prefer_ipv4",
        "optimistic": true,
        "reverse_mapping": true
    });

    // Routing rules
    let route_json = serde_json::json!({
        "rules": [
            {"ip_is_private": true, "outbound": "direct"},
            {"protocol": "dns", "action": "hijack-dns"},
            {"action": "route", "outbound": "select"}
        ],
        "final": "select",
        "auto_detect_interface": true
    });

    let mut root = serde_json::Map::new();
    root.insert(
        "log".to_string(),
        serde_json::json!({"level": "info", "timestamp": true}),
    );
    root.insert("dns".to_string(), dns_json);
    root.insert("inbounds".to_string(), serde_json::Value::Array(inbounds));
    root.insert("outbounds".to_string(), serde_json::Value::Array(all_outbounds));
    root.insert("route".to_string(), route_json);

    if opts.experimental_clash_api {
        root.insert(
            "experimental".to_string(),
            serde_json::json!({
                "cache_file": {
                    "enabled": true,
                    "path": "cache.db",
                    "store_dns": true
                },
                "clash_api": {
                    "external_controller": format!("127.0.0.1:{}", opts.clash_api_port),
                    "access_control_allow_origin": ["*"],
                    "access_control_allow_private_network": true
                }
            }),
        );
    }

    serde_json::Value::Object(root)
}
