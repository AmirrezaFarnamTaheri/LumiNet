//! # Proxy Node Identity, CDN-Aware Deduplication & Structural Filtering
//!
//! Provides deterministic CDN-aware node identity hashing, stable 6-character content tags,
//! dummy configuration pruning, and structural server/UUID/port validation.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// Protocols where the user identifier is treated as an explicit UUID/User-ID.
const UUID_PROTOCOLS: &[&str] = &["vless", "vmess", "tuic"];

/// Protocols where `insecure` / `skip-cert-verify` flag alters client-side identity.
const INSECURE_SCHEMES: &[&str] = &["hysteria2", "hy2", "tuic"];

/// Parameters that participate in the canonical identity fingerprint.
const IDENTITY_PARAMS: &[&str] = &[
    "security",
    "sni",
    "pbk",
    "sid",
    "host",
    "path",
    "servicename",
    "flow",
    "type",
    "headertype",
    "encryption",
    "mode",
    "alpn",
    "extra",
    "obfs",
    "obfs-password",
    "obfspassword",
    "congestion_control",
    "congestion",
    "publickey",
    "presharedkey",
    "address",
];

/// Parameters that are strictly case-sensitive (paths, public keys, passwords).
const CASE_SENSITIVE_PARAMS: &[&str] = &[
    "path",
    "servicename",
    "pbk",
    "publickey",
    "presharedkey",
    "obfs-password",
    "obfspassword",
];

/// Known bogus / dummy configuration substrings.
const DUMMY_INDICATORS: &[&str] = &[
    "00000000-0000-0000-0000-000000000000",
    "app%20not%20supported",
    "app not supported",
    "proxies: []",
];

/// Returns true if the given line contains dummy or placeholder indicators.
pub fn is_dummy_proxy(raw_line: &str) -> bool {
    if raw_line.is_empty() {
        return false;
    }
    let lower = raw_line.to_ascii_lowercase();
    DUMMY_INDICATORS.iter().any(|&ind| lower.contains(ind))
}

/// Validates whether a port is within the valid TCP/UDP range (1..=65535).
pub fn is_invalid_port(port: u32) -> bool {
    port == 0 || port > 65535
}

/// Checks if an IP address is unroutable (loopback, unspecified, multicast, reserved, link-local).
pub fn is_unroutable_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_link_local()
                // Reserved 240.0.0.0/4
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Checks if a server host is unroutable if it parses as an IP address.
pub fn is_unroutable_server(host: &str) -> bool {
    let clean = host.trim().trim_matches('[').trim_matches(']');
    if clean.is_empty() {
        return true;
    }
    if let Ok(ip) = clean.parse::<IpAddr>() {
        return is_unroutable_ip(&ip);
    }
    false
}

/// Checks if a host is structurally invalid (cannot be a valid public hostname or IP).
pub fn is_structurally_invalid_server(host: &str) -> bool {
    let clean = host.trim();
    if clean.is_empty() {
        return true;
    }
    let raw_ip = clean.trim_matches('[').trim_matches(']');
    if raw_ip.parse::<IpAddr>().is_ok() {
        return false;
    }
    if clean.contains('/')
        || clean.contains('?')
        || clean.contains('#')
        || clean.contains('@')
        || clean.contains('\\')
        || clean.contains("://")
        || clean.chars().any(|c| c.is_whitespace())
        || clean.contains(':')
    {
        return true;
    }
    if !clean.contains('.') {
        return true;
    }
    if clean.len() > 253 {
        return true;
    }
    let stripped = clean.trim_end_matches('.');
    for label in stripped.split('.') {
        if label.is_empty() || label.len() > 63 {
            return true;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return true;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return true;
        }
    }
    false
}

/// Checks if a UUID string is invalid according to Xray protocol specifications:
/// Valid if standard 36-char hyphenated UUID or 32-char compact hex, OR custom string < 30 bytes.
pub fn is_invalid_uuid(uuid: &str, proto: &str) -> bool {
    let proto_lower = proto.trim().to_ascii_lowercase();
    if !UUID_PROTOCOLS.contains(&proto_lower.as_str()) {
        return false;
    }
    let s = uuid.trim();
    if s.is_empty() {
        return true;
    }
    let hex_only: String = s.chars().filter(|c| *c != '-').collect();
    if hex_only.len() == 32 && hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
        if hex_only.chars().all(|c| c == '0') {
            return true; // nil UUID
        }
        return false;
    }
    s.as_bytes().len() >= 30
}

/// Checks whether a host string is a plausible CDN/Fronting host.
pub fn is_plausible_fronting_host(host: &str) -> bool {
    let s = host.trim();
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    if s.starts_with('[') && s.ends_with(']') && s.len() > 2 {
        return true; // IPv6 literal
    }
    let bad_chars = [' ', '\t', '\r', '\n', '/', ':', '@', '?', '#', '{', '}', '"', '\\', ',', ';', '|', '<', '>', '(', ')', '[', ']'];
    if s.chars().any(|c| bad_chars.contains(&c)) {
        return false;
    }
    let trimmed = s.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.contains("..") || !trimmed.contains('.') {
        return false;
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    true
}

/// Evaluates if SNI represents the actual terminal server endpoint.
pub fn sni_is_endpoint(security: &str) -> bool {
    security == "tls"
}

/// Normalizes alterId into a canonical string.
fn norm_aid(v: Option<&serde_json::Value>) -> String {
    match v {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0).to_string(),
        Some(serde_json::Value::String(s)) => {
            s.trim().parse::<u32>().unwrap_or(0).to_string()
        }
        _ => "0".to_string(),
    }
}

/// Normalizes network transport types.
fn norm_type(t: &str) -> String {
    let lower = t.trim().to_ascii_lowercase();
    match lower.as_str() {
        "" | "raw" | "none" | "tcp" => "tcp".to_string(),
        other => other.to_string(),
    }
}

/// Normalizes query parameter value according to identity rules.
fn norm_identity_value(key: &str, val: &str) -> String {
    if CASE_SENSITIVE_PARAMS.contains(&key) {
        return val.trim().to_string();
    }
    let mut v = val.trim().to_ascii_lowercase();
    if key == "sni" || key == "host" {
        for _ in 0..2 {
            let unquoted = urlencoding::decode(&v).unwrap_or(std::borrow::Cow::Borrowed(&v));
            if unquoted == v {
                break;
            }
            v = unquoted.trim().to_ascii_lowercase();
        }
    }
    match key {
        "type" => {
            let nt = norm_type(&v);
            if nt == "tcp" {
                String::new()
            } else {
                nt
            }
        }
        "encryption" | "security" | "headertype" => {
            if v.is_empty() || v == "none" {
                String::new()
            } else {
                v
            }
        }
        "flow" => {
            if v.is_empty() {
                String::new()
            } else {
                v
            }
        }
        _ => v,
    }
}

/// Decodes base64 text forgivingly (standard or URL-safe with/without padding).
fn decode_base64_text(input: &str) -> Option<String> {
    let clean = input.trim();
    if clean.is_empty() {
        return None;
    }
    if let Ok(b) = BASE64_STANDARD.decode(clean) {
        if let Ok(s) = String::from_utf8(b) {
            return Some(s);
        }
    }
    let padded = match clean.len() % 4 {
        2 => format!("{}==", clean),
        3 => format!("{}=", clean),
        _ => clean.to_string(),
    };
    if let Ok(b) = BASE64_STANDARD.decode(&padded) {
        if let Ok(s) = String::from_utf8(b) {
            return Some(s);
        }
    }
    let url_clean = clean.replace('-', "+").replace('_', "/");
    let url_padded = match url_clean.len() % 4 {
        2 => format!("{}==", url_clean),
        3 => format!("{}=", url_clean),
        _ => url_clean,
    };
    if let Ok(b) = BASE64_STANDARD.decode(&url_padded) {
        if let Ok(s) = String::from_utf8(b) {
            return Some(s);
        }
    }
    None
}

/// Computes the CDN-aware deduplication identity fingerprint key for any proxy configuration line.
pub fn compute_node_dedup_key(line: &str) -> String {
    let raw = line.trim();
    if raw.is_empty() {
        return String::new();
    }

    // VMess JSON base64 format
    if let Some(rest) = raw.strip_prefix("vmess://") {
        let b64 = rest.split('#').next().unwrap_or("").trim();
        if let Some(txt) = decode_base64_text(b64) {
            if let Ok(obj) = serde_json::from_str::<serde_json::Value>(&txt) {
                let add = obj.get("add").and_then(|v| v.as_str()).unwrap_or("").trim().to_ascii_lowercase();
                let raw_host = obj.get("host").and_then(|v| v.as_str()).unwrap_or("");
                let mut host = norm_identity_value("host", raw_host);
                let raw_sni = obj.get("sni").and_then(|v| v.as_str()).unwrap_or("");
                let mut sni = norm_identity_value("sni", raw_sni);
                let raw_tls = obj.get("tls").and_then(|v| v.as_str()).unwrap_or("").trim().to_ascii_lowercase();
                let tls = match raw_tls.as_str() {
                    "tls" | "reality" | "xtls" => raw_tls,
                    _ => String::new(),
                };
                let raw_net = obj.get("net").and_then(|v| v.as_str()).unwrap_or("");
                let net = norm_type(raw_net);
                let raw_path = obj.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let path = if raw_path.is_empty() { "/" } else { raw_path };

                if !host.is_empty() && !is_plausible_fronting_host(&host) {
                    host = String::new();
                }
                if !sni.is_empty() && !(is_plausible_fronting_host(&sni) && sni_is_endpoint(&tls)) {
                    sni = String::new();
                }

                let fallback_srv = if !raw_sni.is_empty() { raw_sni } else { raw_host };
                let mut srv = norm_identity_value("sni", fallback_srv);
                if !srv.is_empty() && !is_plausible_fronting_host(&srv) {
                    srv = String::new();
                }

                let fronting = if !sni.is_empty() {
                    format!("{}~{}", host, sni)
                } else {
                    host
                };

                let port = obj.get("port").map(|v| v.to_string().trim().trim_matches('"').to_string()).unwrap_or_default();
                let id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("").trim().to_ascii_lowercase();
                let aid = norm_aid(obj.get("aid"));
                let scy = obj.get("scy").and_then(|v| v.as_str()).unwrap_or("auto");

                return format!(
                    "vmess:{}|ep={}:{}:{}:{}:{}:{}:{}:{}:srv={}",
                    add, fronting, port, id, net, path, tls, aid, scy, srv
                );
            }
        }
        return raw.split('#').next().unwrap_or("").chars().take(120).collect();
    }

    // Shadowsocks format
    if let Some(rest) = raw.strip_prefix("ss://") {
        let without_remark = rest.split('#').next().unwrap_or("").trim();
        let authority = without_remark.split('?').next().unwrap_or("");
        if authority.contains('@') {
            let mut parts = authority.rsplitn(2, '@');
            let hostpart = parts.next().unwrap_or("").split('/').next().unwrap_or("");
            let userinfo_raw = parts.next().unwrap_or("");
            let mut userinfo = userinfo_raw.to_string();
            if let Some(decoded_ui) = decode_base64_text(&userinfo) {
                if decoded_ui.contains(':') {
                    userinfo = decoded_ui;
                }
            }
            let userinfo_clean = urlencoding::decode(&userinfo).unwrap_or(std::borrow::Cow::Borrowed(&userinfo)).to_ascii_lowercase();
            let mut hp_parts = hostpart.rsplitn(2, ':');
            let port = hp_parts.next().unwrap_or("");
            let host = hp_parts.next().unwrap_or("").to_ascii_lowercase();
            return format!("ss:sip002:{}@{}:{}", userinfo_clean, host, port);
        } else if let Some(decoded) = decode_base64_text(without_remark) {
            let d = decoded.split('#').next().unwrap_or("").split('?').next().unwrap_or("");
            if d.contains('@') {
                let mut parts = d.rsplitn(2, '@');
                let hostpart = parts.next().unwrap_or("").split('/').next().unwrap_or("");
                let userinfo = parts.next().unwrap_or("");
                let userinfo_clean = urlencoding::decode(userinfo).unwrap_or(std::borrow::Cow::Borrowed(userinfo)).to_ascii_lowercase();
                let mut hp_parts = hostpart.rsplitn(2, ':');
                let port = hp_parts.next().unwrap_or("");
                let host = hp_parts.next().unwrap_or("").to_ascii_lowercase();
                if !host.is_empty() && !port.is_empty() {
                    return format!("ss:sip002:{}@{}:{}", userinfo_clean, host, port);
                }
            }
            return format!("ss:legacy:{}", decoded.to_ascii_lowercase());
        }
        return raw.split('#').next().unwrap_or("").chars().take(120).collect();
    }

    // SSR format
    if let Some(rest) = raw.strip_prefix("ssr://") {
        if let Some(decoded) = decode_base64_text(rest.split('#').next().unwrap_or("").trim()) {
            let mut parts = decoded.splitn(2, "/?");
            let main = parts.next().unwrap_or("");
            let query = parts.next().unwrap_or("");
            let segs: Vec<&str> = main.split(':').collect();
            if segs.len() >= 6 {
                let host = segs[0].trim().to_ascii_lowercase();
                let port = segs[1].trim();
                let proto = segs[2].trim().to_ascii_lowercase();
                let method = segs[3].trim().to_ascii_lowercase();
                let obfs = segs[4].trim().to_ascii_lowercase();
                let pwd_b64 = segs[5].trim();
                let pwd = decode_base64_text(pwd_b64).unwrap_or_else(|| pwd_b64.to_string());

                let mut obfsparam = String::new();
                let mut protoparam = String::new();
                for pair in query.split('&') {
                    if let Some(val) = pair.strip_prefix("obfsparam=") {
                        obfsparam = decode_base64_text(val).unwrap_or_else(|| val.to_string());
                    } else if let Some(val) = pair.strip_prefix("protoparam=") {
                        protoparam = decode_base64_text(val).unwrap_or_else(|| val.to_string());
                    }
                }
                return format!(
                    "ssr:{}:{}:{}:{}:{}:{}:op={}:pp={}",
                    host,
                    port,
                    proto,
                    method,
                    obfs,
                    urlencoding::encode(&pwd),
                    urlencoding::encode(&obfsparam),
                    urlencoding::encode(&protoparam)
                );
            }
        }
    }

    // Generic URI parser (vless://, trojan://, hysteria2://, tuic://, etc.)
    let without_remark = raw.split('#').next().unwrap_or("").trim();
    if let Some(scheme_idx) = without_remark.find("://") {
        let scheme = without_remark[..scheme_idx].to_ascii_lowercase();
        let rest = &without_remark[scheme_idx + 3..];
        let mut query_map: BTreeMap<String, String> = BTreeMap::new();
        let (auth_and_path, query_str) = match rest.split_once('?') {
            Some((ap, q)) => (ap, q),
            None => (rest, ""),
        };

        let raw_insecure = INSECURE_SCHEMES.contains(&scheme.as_str());
        let mut has_insecure = false;

        for pair in query_str.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k_raw, v_raw) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            let k_clean = k_raw.trim();
            let k_lower = k_clean.to_ascii_lowercase();

            if raw_insecure && (k_clean == "insecure" || k_clean == "allowInsecure" || k_clean == "allow_insecure") {
                let v_clean = v_raw.trim().to_ascii_lowercase();
                if v_clean == "1" || v_clean == "true" || v_clean == "yes" || v_clean == "on" {
                    has_insecure = true;
                }
            }

            if IDENTITY_PARAMS.contains(&k_lower.as_str()) {
                let nv = norm_identity_value(&k_lower, v_raw);
                if !nv.is_empty() {
                    query_map.insert(k_lower, nv);
                }
            }
        }

        if raw_insecure {
            query_map.insert("insecure".to_string(), if has_insecure { "1".to_string() } else { "0".to_string() });
        }

        let (authority, path) = match auth_and_path.split_once('/') {
            Some((auth, p)) => (auth, format!("/{}", p.trim_end_matches('/'))),
            None => (auth_and_path, String::new()),
        };

        let (username, password, host, port) = parse_authority(authority);

        let mut sni_val = query_map.get("sni").cloned().unwrap_or_default();
        let mut host_val = query_map.get("host").cloned().unwrap_or_default();
        let security_val = query_map.get("security").cloned().unwrap_or_default();

        if !sni_val.is_empty() && !is_plausible_fronting_host(&sni_val) {
            sni_val = String::new();
            query_map.remove("sni");
        } else if !sni_val.is_empty() && !sni_is_endpoint(&security_val) {
            sni_val = String::new();
        }

        if !host_val.is_empty() && !is_plausible_fronting_host(&host_val) {
            host_val = String::new();
            query_map.remove("host");
        }

        let fronting_domain = if !sni_val.is_empty() { sni_val } else { host_val };
        let sorted_query: Vec<String> = query_map.into_iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        let q_joined = sorted_query.join("&");

        return format!(
            "{}:{}:{}@{}|ep={}:{}{}?{}",
            scheme, username, password, host, fronting_domain, port, path, q_joined
        );
    }

    without_remark.chars().take(200).collect()
}

/// Helper to parse authority into user, pass, host, port.
fn parse_authority(auth: &str) -> (String, String, String, String) {
    let (userinfo, hostport) = match auth.rsplit_once('@') {
        Some((u, hp)) => (u, hp),
        None => ("", auth),
    };
    let (username, password) = match userinfo.split_once(':') {
        Some((u, p)) => (
            urlencoding::decode(u).unwrap_or(std::borrow::Cow::Borrowed(u)).to_ascii_lowercase(),
            urlencoding::decode(p).unwrap_or(std::borrow::Cow::Borrowed(p)).to_ascii_lowercase(),
        ),
        None => (
            urlencoding::decode(userinfo).unwrap_or(std::borrow::Cow::Borrowed(userinfo)).to_ascii_lowercase(),
            String::new(),
        ),
    };
    let hostport_clean = hostport.split('/').next().unwrap_or("");
    let (host, port) = match hostport_clean.rsplit_once(':') {
        Some((h, pt)) => (h.trim_matches('[').trim_matches(']').to_ascii_lowercase(), pt.to_string()),
        None => (hostport_clean.trim_matches('[').trim_matches(']').to_ascii_lowercase(), String::new()),
    };
    (username, password, host, port)
}

/// Computes a stable 6-character content tag from the proxy deduplication key.
pub fn compute_stable_node_tag(line: &str) -> String {
    let key = compute_node_dedup_key(line);
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    hex.chars().take(6).collect::<String>().to_uppercase()
}

/// Converts a two-letter ISO country code into a flag emoji (e.g. "US" -> "🇺🇸").
pub fn country_code_to_flag(country_code: &str) -> Option<String> {
    let clean = country_code.trim().to_ascii_uppercase();
    if clean.len() != 2 || !clean.chars().all(|c| c.is_ascii_uppercase()) {
        return None;
    }
    let chars: Vec<char> = clean.chars().collect();
    let r1 = std::char::from_u32(0x1F1E6 + (chars[0] as u32 - 'A' as u32))?;
    let r2 = std::char::from_u32(0x1F1E6 + (chars[1] as u32 - 'A' as u32))?;
    Some(format!("{}{}", r1, r2))
}
