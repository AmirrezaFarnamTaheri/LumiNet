//! Backend WebSocket reachability prober and duplex traffic meter.
//!

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Configuration for probing a backend proxy node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendProbeConfig {
    pub target_url: String,
    pub path: Option<String>,
    pub timeout_ms: u64,
}

impl Default for BackendProbeConfig {
    fn default() -> Self {
        Self {
            target_url: String::new(),
            path: Some("/novavpn".to_string()),
            timeout_ms: 5000,
        }
    }
}

/// Structured diagnostic result returned by the backend prober.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendProbeResult {
    pub ok: bool,
    pub backend_mode: bool,
    pub backend_url: String,
    pub target_tried: String,
    pub upstream_status: Option<u16>,
    pub got_websocket: bool,
    pub elapsed_ms: u64,
    pub server_header: String,
    pub steps: Vec<String>,
    pub fix_hint: Option<String>,
}

/// Builds an RFC 6455 WebSocket upgrade HTTP request string and target URL.
pub fn build_websocket_handshake_request(
    target_url: &str,
    override_path: Option<&str>,
) -> Result<(String, String, String), String> {
    let raw = target_url.trim();
    if raw.is_empty() {
        return Err("Backend URL is empty".to_string());
    }

    let (scheme, after_scheme) = if let Some(stripped) = raw.strip_prefix("https://") {
        ("https", stripped)
    } else if let Some(stripped) = raw.strip_prefix("http://") {
        ("http", stripped)
    } else {
        return Err("Backend URL must start with http:// or https://".to_string());
    };

    let (host_port, existing_path) = if let Some(idx) = after_scheme.find('/') {
        (&after_scheme[..idx], &after_scheme[idx..])
    } else {
        (after_scheme, "/")
    };

    if host_port.is_empty() {
        return Err("Malformed backend URL host".to_string());
    }

    let final_path = match override_path {
        Some(p) if !p.trim().is_empty() => {
            if p.starts_with('/') {
                p.to_string()
            } else {
                format!("/{}", p)
            }
        }
        _ => {
            if existing_path == "/" || existing_path.is_empty() {
                "/novavpn".to_string()
            } else {
                existing_path.to_string()
            }
        }
    };

    let target_tried = format!("{}://{}{}", scheme, host_port, final_path);

    let host_only = host_port.split(':').next().unwrap_or(host_port);

    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        final_path, host_only
    );

    Ok((request, target_tried, host_only.to_string()))
}

/// Analyzes upstream probe response headers and status code to determine health and remediation hints.
pub fn analyze_probe_response(
    status: u16,
    server_header: &str,
    target_host: &str,
    elapsed_ms: u64,
    is_websocket: bool,
) -> (bool, Vec<String>, Option<String>) {
    let mut steps = Vec::new();
    let mut fix_hint = None;

    if status == 101 && is_websocket {
        steps.push(
            "SUCCESS: Backend reached and upgraded to WebSocket (101). Relay path works."
                .to_string(),
        );
        return (true, steps, None);
    }

    if status == 101 && !is_websocket {
        steps.push(
            "Backend returned 101 but did not expose an active WebSocket connection. Verify TLS certificates."
                .to_string(),
        );
        return (false, steps, None);
    }

    let is_raw_ip = target_host.parse::<IpAddr>().is_ok();

    if status == 403 {
        if is_raw_ip && elapsed_ms < 100 {
            steps.push(format!(
                "403 in {}ms to RAW IP — Edge SSRF sandbox blocks bare IP.",
                elapsed_ms
            ));
            fix_hint = Some(
                "Use a gray-cloud (DNS-only) A record in Backend URL instead of raw IP."
                    .to_string(),
            );
        } else {
            steps.push(
                "Backend returned 403. Check that path matches Xray wsSettings.path and Host header is accepted."
                    .to_string(),
            );
            fix_hint = Some("Verify wsSettings.path and inbound Host whitelist.".to_string());
        }
    } else {
        steps.push(format!(
            "Backend did NOT upgrade. Status {}. Server header: '{}'. Check that port is open and path is configured.",
            status, server_header
        ));
    }

    (false, steps, fix_hint)
}

/// Duplex bandwidth traffic meter for a single user or tunnel session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficMeter {
    pub user_id: String,
    pub up_bytes: u64,
    pub down_bytes: u64,
}

impl TrafficMeter {
    pub fn new(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            up_bytes: 0,
            down_bytes: 0,
        }
    }

    pub fn record_up(&mut self, bytes: usize) {
        self.up_bytes = self.up_bytes.saturating_add(bytes as u64);
    }

    pub fn record_down(&mut self, bytes: usize) {
        self.down_bytes = self.down_bytes.saturating_add(bytes as u64);
    }

    pub fn total_bytes(&self) -> u64 {
        self.up_bytes.saturating_add(self.down_bytes)
    }
}
