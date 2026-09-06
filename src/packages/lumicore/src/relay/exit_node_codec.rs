//! Exit node wire protocol codec, SSRF protection, loop detection,
//! Apps Script error classification, and adblock hosts parser.
//!

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Request payload sent to the exit node endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitNodeRequest {
    /// Pre-shared authentication key.
    pub k: String,
    /// Target URL (e.g. "https://example.com/api").
    pub u: String,
    /// HTTP method (GET, POST, PUT, DELETE, etc.).
    #[serde(default = "default_method")]
    pub m: String,
    /// Sanitized request headers.
    #[serde(default)]
    pub h: HashMap<String, String>,
    /// Base64-encoded request payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub b: Option<String>,
}

fn default_method() -> String {
    "GET".to_string()
}

/// Response payload received from an exit node or Apps Script relay.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExitNodeResponse {
    /// HTTP status code from target origin.
    #[serde(default = "default_status")]
    pub s: u16,
    /// Response headers from target origin.
    #[serde(default)]
    pub h: HashMap<String, serde_json::Value>,
    /// Base64-encoded response body.
    #[serde(default)]
    pub b: Option<String>,
    /// Relay error string (present on failure).
    #[serde(default)]
    pub e: Option<String>,
    /// Relay-level gzip compression flag.
    #[serde(default)]
    pub gz: Option<bool>,
}

fn default_status() -> u16 {
    200
}

/// Permanent failure categories that warrant disabling a script ID or exit node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermanentCategory {
    Quota,
    Auth,
    Deploy,
    Admin,
}

/// Relay loop detection error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayLoopError {
    #[error("Self-loop detected: target hostname '{0}' resolves back to this exit node")]
    SelfLoop(String),
    #[error("Hop loop detected: request contains x-mhr-hop header and targets another Apps Script deployment '{0}'")]
    HopRelayLoop(String),
}

/// Hop-by-hop headers that must never be forwarded across relay boundaries.
pub static STRIP_HEADERS: &[&str] = &[
    "host",
    "connection",
    "content-length",
    "transfer-encoding",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "forwarded",
    "via",
    "x-mhr-hop",
    "accept-encoding",
];

/// Sanitizes a header map by dropping hop-by-hop, proxy, and connection-local headers.
pub fn sanitize_outbound_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    let strip_set: HashSet<&'static str> = STRIP_HEADERS.iter().copied().collect();
    let mut out = HashMap::new();
    for (k, v) in headers {
        let lower = k.trim().to_lowercase();
        if lower.is_empty() || strip_set.contains(lower.as_str()) {
            continue;
        }
        out.insert(k.clone(), v.clone());
    }
    out
}

/// Validates that a target URL is safe against SSRF attacks (rejects localhost, private CIDRs, etc.).
pub fn is_safe_url(raw_url: &str) -> bool {
    let lower = raw_url.trim().to_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return false;
    }

    let after_scheme = if let Some(stripped) = lower.strip_prefix("https://") {
        stripped
    } else if let Some(stripped) = lower.strip_prefix("http://") {
        stripped
    } else {
        return false;
    };

    let host_port = after_scheme.split('/').next().unwrap_or("");
    let host = if host_port.starts_with('[') {
        if let Some(end_bracket) = host_port.find(']') {
            &host_port[1..end_bracket]
        } else {
            return false;
        }
    } else {
        host_port.split(':').next().unwrap_or("")
    };

    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return false;
    }

    if host == "localhost" || host.ends_with(".local") || host.ends_with(".lan") || host.ends_with(".home.arpa") {
        return false;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                if v4.is_loopback() || v4.is_unspecified() {
                    return false;
                }
                let octets = v4.octets();
                if octets[0] == 10 {
                    return false;
                }
                if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                    return false;
                }
                if octets[0] == 192 && octets[1] == 168 {
                    return false;
                }
                if octets[0] == 169 && octets[1] == 254 {
                    return false;
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() {
                    return false;
                }
                let segments = v6.segments();
                if (segments[0] & 0xfe00) == 0xfc00 {
                    return false;
                }
                if (segments[0] & 0xffc0) == 0xfe80 {
                    return false;
                }
            }
        }
    }

    true
}

/// Detects relay self-loops and multi-hop Apps Script loops.
pub fn detect_relay_loop(
    target_url: &str,
    exit_host: &str,
    has_hop_header: bool,
) -> Result<(), RelayLoopError> {
    let lower_target = target_url.trim().to_lowercase();
    let lower_exit = exit_host.trim().to_lowercase();

    let target_host = if let Some(stripped) = lower_target.strip_prefix("https://") {
        stripped.split('/').next().unwrap_or("").split(':').next().unwrap_or("")
    } else if let Some(stripped) = lower_target.strip_prefix("http://") {
        stripped.split('/').next().unwrap_or("").split(':').next().unwrap_or("")
    } else {
        ""
    };

    let exit_host_clean = lower_exit.split(':').next().unwrap_or("");

    if !target_host.is_empty() && !exit_host_clean.is_empty() && target_host == exit_host_clean {
        return Err(RelayLoopError::SelfLoop(target_host.to_string()));
    }

    if has_hop_header && lower_target.contains("/macros/s/") {
        return Err(RelayLoopError::HopRelayLoop(target_url.to_string()));
    }

    Ok(())
}

/// Classifies raw error strings returned from Apps Script into human-readable messages.
pub fn classify_relay_error(raw: &str) -> String {
    let lower = raw.to_lowercase();

    if lower.contains("loop detected") || lower == "loop_detected" {
        return "Relay loop detected. Your exit node URL is misconfigured — it points back to a Google Apps Script deployment or to the exit node itself.".to_string();
    }

    let quota_patterns = [
        "service invoked too many times",
        "invoked too many times",
        "bandwidth quota exceeded",
        "too much upload bandwidth",
        "too much traffic",
        "urlfetch",
        "quota",
        "exceeded",
        "rate limit",
    ];
    if quota_patterns.iter().any(|p| lower.contains(p)) {
        return "Apps Script quota exhausted. Either the 20,000 URL-fetch calls/day limit or bandwidth limit has been reached.".to_string();
    }

    let auth_patterns = [
        "authorization is required",
        "unauthorized",
        "not authorized",
        "permission denied",
        "access denied",
    ];
    if auth_patterns.iter().any(|p| lower.contains(p)) {
        return "Apps Script rejected the request (auth/permission error). Verify AUTH_KEY matches and deployment permissions are Execute as Me / Anyone can access.".to_string();
    }

    let deploy_patterns = [
        "error code not_found",
        "not_found",
        "deployment",
        "script id",
        "scriptid",
        "no script",
    ];
    if deploy_patterns.iter().any(|p| lower.contains(p)) {
        return "Apps Script deployment not found. Verify deployment ID in configuration is valid and active.".to_string();
    }

    let transient_patterns = [
        "server not available",
        "server error occurred",
        "please try again",
        "temporarily unavailable",
    ];
    if transient_patterns.iter().any(|p| lower.contains(p)) {
        return format!("Google Apps Script server is temporarily unavailable. (raw: {})", raw);
    }

    let admin_patterns = [
        "not permitted by your admin",
        "contact your administrator",
        "disabled. please contact",
        "domain policy has disabled",
    ];
    if admin_patterns.iter().any(|p| lower.contains(p)) {
        return format!("Apps Script is blocked by a Google Workspace admin policy. (raw: {})", raw);
    }

    if lower.contains("dns") {
        return "DNS error in exit node. Check exit node URL and reachability.".to_string();
    }

    let re = Regex::new(r"(?i)^(Exception|Error):\s*").unwrap();
    let cleaned = re.replace(raw, "").trim().to_string();
    if cleaned.is_empty() {
        format!("Relay error: {}", raw)
    } else {
        format!("Relay error: {}", cleaned)
    }
}

/// Classifies a raw relay response body to identify permanent script failures.
pub fn classify_relay_envelope(body: &[u8]) -> (Option<PermanentCategory>, String) {
    let text = match std::str::from_utf8(body) {
        Ok(t) => t.trim(),
        Err(_) => return (None, String::new()),
    };
    if text.is_empty() {
        return (None, String::new());
    }

    let data = match load_relay_json(text) {
        Some(d) => d,
        None => return (None, String::new()),
    };

    let raw_err = match data.get("e").and_then(|v| v.as_str()) {
        Some(e) => e,
        None => return (None, String::new()),
    };

    let lower = raw_err.to_lowercase();
    if lower.contains("quota") || lower.contains("invoked too many times") || lower.contains("urlfetch") {
        return (Some(PermanentCategory::Quota), raw_err.to_string());
    }
    if lower.contains("auth") || lower.contains("permission denied") || lower.contains("unauthorized") {
        return (Some(PermanentCategory::Auth), raw_err.to_string());
    }
    if lower.contains("not_found") || lower.contains("deployment") || lower.contains("script id") {
        return (Some(PermanentCategory::Deploy), raw_err.to_string());
    }
    if lower.contains("admin") || lower.contains("administrator") {
        return (Some(PermanentCategory::Admin), raw_err.to_string());
    }

    (None, raw_err.to_string())
}

/// Extracts embedded user HTML from an Apps Script iframe sandbox response.
pub fn extract_apps_script_user_html(text: &str) -> Option<String> {
    let marker = "goog.script.init(\"";
    let start = text.find(marker)? + marker.len();
    let end = text[start..].find("\", \"\", undefined")? + start;

    let encoded = &text[start..end];

    let mut decoded = String::with_capacity(encoded.len());
    let bytes = encoded.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1] == b'x' {
            if let Ok(hex_val) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 2..i + 4]).unwrap_or(""),
                16,
            ) {
                decoded.push(hex_val as char);
                i += 4;
                continue;
            }
        }
        decoded.push(bytes[i] as char);
        i += 1;
    }

    let unescaped = decoded.replace(r"\\", r"\").replace(r"\/", "/");
    let payload: serde_json::Value = serde_json::from_str(&unescaped).ok()?;
    payload.get("userHtml").and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Parses a relay JSON body, falling back to Apps Script HTML unwrapping.
pub fn load_relay_json(text: &str) -> Option<serde_json::Value> {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
        return Some(val);
    }

    if let Some(wrapped) = extract_apps_script_user_html(text) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&wrapped) {
            return Some(val);
        }
    }

    let re = Regex::new(r"\{[\s\S]*\}").ok()?;
    if let Some(m) = re.find(text) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(m.as_str()) {
            return Some(val);
        }
    }

    None
}

/// Splits combined Set-Cookie headers while preserving date commas (RFC 6265 compliant).
pub fn split_set_cookie(blob: &str) -> Vec<String> {
    let trimmed = blob.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut cookies = Vec::new();
    let mut current_start = 0;
    let bytes = trimmed.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i] == b',' {
            // Check if what follows is a new cookie name=value pair
            let mut j = i + 1;
            while j < len && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            // Look ahead until next ';' or ',' or end of string
            let mut k = j;
            let mut has_equals = false;
            let mut equals_pos = 0;
            while k < len && bytes[k] != b';' && bytes[k] != b',' {
                if bytes[k] == b'=' && !has_equals {
                    has_equals = true;
                    equals_pos = k;
                }
                k += 1;
            }

            if has_equals {
                let token_name = trimmed[j..equals_pos].trim();
                let is_valid_name = !token_name.is_empty()
                    && !token_name.contains(' ')
                    && !token_name.contains('\t');
                if is_valid_name {
                    let cookie = trimmed[current_start..i].trim();
                    if !cookie.is_empty() {
                        cookies.push(cookie.to_string());
                    }
                    current_start = j;
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }

    let last_cookie = trimmed[current_start..].trim();
    if !last_cookie.is_empty() {
        cookies.push(last_cookie.to_string());
    }

    cookies
}

/// Parses an adblock hosts list text file into a deduplicated list of valid domain strings.
pub fn parse_hosts_text(text: &str) -> Vec<String> {
    let domain_re = Regex::new(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$").unwrap();
    let wildcard_re = Regex::new(r"[*?]").unwrap();

    let hosts_prefixes: HashSet<&str> = ["0.0.0.0", "127.0.0.1", "::1", "::0"].iter().copied().collect();
    let skip_names: HashSet<&str> = [
        "localhost",
        "local",
        "broadcasthost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    ]
    .iter()
    .copied()
    .collect();

    let mut seen = HashSet::new();
    let mut domains = Vec::new();

    for raw_line in text.lines() {
        let mut line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(idx) = line.find(" #") {
            line = line[..idx].trim();
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        let domain = if parts.len() == 2 && hosts_prefixes.contains(parts[0]) {
            parts[1].to_lowercase().trim_end_matches('.').to_string()
        } else if parts.len() == 1 {
            parts[0].to_lowercase().trim_end_matches('.').to_string()
        } else {
            continue;
        };

        if wildcard_re.is_match(&domain) {
            continue;
        }
        if domain.parse::<IpAddr>().is_ok() {
            continue;
        }
        if skip_names.contains(domain.as_str()) {
            continue;
        }
        if !domain_re.is_match(&domain) {
            continue;
        }

        if !seen.contains(&domain) {
            seen.insert(domain.clone());
            domains.push(domain);
        }
    }

    domains
}

/// Unpacks a parsed relay response into raw HTTP/1.1 wire bytes.
pub fn unpack_relay_response_to_http(
    resp: &ExitNodeResponse,
    max_body_bytes: usize,
) -> Result<Vec<u8>, String> {
    if let Some(err) = &resp.e {
        let friendly = classify_relay_error(err);
        return Err(format!("502 Bad Gateway: {}", friendly));
    }

    let status = resp.s;
    let body_bytes = if let Some(b64) = &resp.b {
        BASE64_STANDARD
            .decode(b64)
            .map_err(|e| format!("Base64 decode error: {}", e))?
    } else {
        Vec::new()
    };

    if body_bytes.len() > max_body_bytes {
        return Err(format!(
            "Response size {} exceeds maximum allowed {}",
            body_bytes.len(),
            max_body_bytes
        ));
    }

    let status_text = match status {
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        508 => "Loop Detected",
        _ => "OK",
    };

    let mut out = format!("HTTP/1.1 {} {}\r\n", status, status_text);

    let skip_headers: HashSet<&str> = [
        "transfer-encoding",
        "connection",
        "keep-alive",
        "content-length",
    ]
    .iter()
    .copied()
    .collect();

    for (k, v) in &resp.h {
        let lower = k.to_lowercase();
        if skip_headers.contains(lower.as_str()) {
            continue;
        }

        if lower == "set-cookie" {
            let cookies = match v {
                serde_json::Value::String(s) => split_set_cookie(s),
                serde_json::Value::Array(arr) => {
                    let mut list = Vec::new();
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            list.extend(split_set_cookie(s));
                        }
                    }
                    list
                }
                _ => Vec::new(),
            };
            for cookie in cookies {
                out.push_str(&format!("{}: {}\r\n", k, cookie));
            }
        } else {
            let val_str = match v {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => continue,
            };
            out.push_str(&format!("{}: {}\r\n", k, val_str));
        }
    }

    out.push_str(&format!("Content-Length: {}\r\n\r\n", body_bytes.len()));

    let mut result = out.into_bytes();
    result.extend_from_slice(&body_bytes);
    Ok(result)
}
