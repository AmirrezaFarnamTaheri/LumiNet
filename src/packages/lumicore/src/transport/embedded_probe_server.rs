//! Embedded Diagnostic Probe and Provisioning Server
//!
//! Provides lightweight authenticated HTTP diagnostic endpoints, range response parsing,
//! probe telemetry benchmarking, and asset payload delivery.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

pub struct EmbeddedProbeServer {
    pub bind_host: String,
    pub bind_port: u16,
    auth_credentials: Option<(String, String)>,
    served_payloads: HashMap<String, Vec<u8>>,
    total_probes_served: u64,
}

impl EmbeddedProbeServer {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            bind_host: host.into(),
            bind_port: port,
            auth_credentials: None,
            served_payloads: HashMap::new(),
            total_probes_served: 0,
        }
    }

    pub fn set_auth(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.auth_credentials = Some((username.into(), password.into()));
    }

    pub fn register_payload(&mut self, path: impl Into<String>, data: Vec<u8>) {
        self.served_payloads.insert(path.into(), data);
    }

    pub fn handle_request(
        &mut self,
        method: &str,
        path: &str,
        auth_header: Option<&str>,
        range_header: Option<&str>,
    ) -> ProbeResponse {
        self.total_probes_served += 1;
        let mut headers = HashMap::new();
        headers.insert("Server".to_string(), "LumiProbe/1.0".to_string());

        // Check authentication if configured
        if let Some((user, pass)) = &self.auth_credentials {
            let expected_token = format!("{}:{}", user, pass);
            let authorized = auth_header.map_or(false, |hdr| {
                if let Some(token) = hdr.strip_prefix("Basic ") {
                    token.trim() == expected_token
                } else {
                    false
                }
            });

            if !authorized {
                headers.insert("WWW-Authenticate".to_string(), "Basic realm=\"LumiProbe\"".to_string());
                return ProbeResponse {
                    status_code: 401,
                    headers,
                    body: b"Unauthorized".to_vec(),
                };
            }
        }

        // Built-in health / ping endpoint
        if path == "/health" || path == "/ping" {
            headers.insert("Content-Type".to_string(), "text/plain".to_string());
            return ProbeResponse {
                status_code: 200,
                headers,
                body: b"OK".to_vec(),
            };
        }

        // Diagnostic speed probe endpoint (generate N dummy bytes)
        if path.starts_with("/probe/bandwidth") {
            let size = 1024 * 64; // 64KB test payload
            let payload = vec![0x55; size];
            headers.insert("Content-Type".to_string(), "application/octet-stream".to_string());
            headers.insert("Content-Length".to_string(), size.to_string());
            return ProbeResponse {
                status_code: 200,
                headers,
                body: payload,
            };
        }

        // Check registered static payload
        if let Some(payload) = self.served_payloads.get(path) {
            headers.insert("Content-Type".to_string(), "application/octet-stream".to_string());

            // Handle HTTP Range header (e.g., "bytes=0-100")
            if let Some(range) = range_header {
                if let Some(spec) = range.strip_prefix("bytes=") {
                    let parts: Vec<&str> = spec.split('-').collect();
                    if parts.len() == 2 {
                        let start = parts[0].parse::<usize>().unwrap_or(0);
                        let end = parts[1].parse::<usize>().unwrap_or(payload.len().saturating_sub(1));
                        if start < payload.len() && start <= end {
                            let end_clamped = end.min(payload.len() - 1);
                            let slice = payload[start..=end_clamped].to_vec();
                            headers.insert(
                                "Content-Range".to_string(),
                                format!("bytes {}-{}/{}", start, end_clamped, payload.len()),
                            );
                            headers.insert("Content-Length".to_string(), slice.len().to_string());
                            return ProbeResponse {
                                status_code: 206,
                                headers,
                                body: slice,
                            };
                        }
                    }
                }
            }

            headers.insert("Content-Length".to_string(), payload.len().to_string());
            return ProbeResponse {
                status_code: 200,
                headers,
                body: payload.clone(),
            };
        }

        ProbeResponse {
            status_code: 404,
            headers,
            body: b"Not Found".to_vec(),
        }
    }

    pub fn total_probes(&self) -> u64 {
        self.total_probes_served
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_probe_server() {
        let mut server = EmbeddedProbeServer::new("127.0.0.1", 8080);
        server.set_auth("admin", "secret123");
        server.register_payload("/tunnel.conf", b"tun_cfg_data".to_vec());

        // Unauthorized request
        let res1 = server.handle_request("GET", "/health", None, None);
        assert_eq!(res1.status_code, 401);

        // Authorized health check
        let res2 = server.handle_request("GET", "/health", Some("Basic admin:secret123"), None);
        assert_eq!(res2.status_code, 200);
        assert_eq!(res2.body, b"OK");

        // Range request for payload
        let res3 = server.handle_request(
            "GET",
            "/tunnel.conf",
            Some("Basic admin:secret123"),
            Some("bytes=0-3"),
        );
        assert_eq!(res3.status_code, 206);
        assert_eq!(res3.body, b"tun_");
    }
}
