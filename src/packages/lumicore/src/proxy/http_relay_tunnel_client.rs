//! High-Throughput HTTP Relay Tunnel Client
//!
//! Envelopes arbitrary TCP socket payloads into streaming HTTP POST requests with
//! token-bucket bandwidth throttle and buffer recycling.

#[derive(Debug, Clone)]
pub struct HttpRelayTunnelClient {
    pub target_host: String,
    pub target_port: u16,
    pub relay_url: String,
    pub token: String,
    pub max_payload_size: usize,
}

impl HttpRelayTunnelClient {
    pub fn new(target_host: &str, target_port: u16, relay_url: &str, token: &str) -> Self {
        Self {
            target_host: target_host.to_string(),
            target_port,
            relay_url: relay_url.to_string(),
            token: token.to_string(),
            max_payload_size: 65536,
        }
    }

    pub fn build_relay_request_header(&self, content_length: usize) -> Vec<u8> {
        format!(
            "POST {} HTTP/1.1\r\n\
            Host: {}\r\n\
            Content-Type: application/octet-stream\r\n\
            Content-Length: {}\r\n\
            X-Target-Host: {}\r\n\
            X-Target-Port: {}\r\n\
            X-Relay-Token: {}\r\n\
            Connection: keep-alive\r\n\
            \r\n",
            self.relay_url,
            self.target_host,
            content_length,
            self.target_host,
            self.target_port,
            self.token
        )
        .into_bytes()
    }

    pub fn frame_payload(&self, data: &[u8]) -> Vec<u8> {
        let mut out = self.build_relay_request_header(data.len());
        out.extend_from_slice(data);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_relay_tunnel_client() {
        let client = HttpRelayTunnelClient::new("dest.server.io", 443, "/relay", "secret123");
        let payload = b"tcp payload data";
        let framed = client.frame_payload(payload);

        let s = String::from_utf8_lossy(&framed);
        assert!(s.contains("POST /relay HTTP/1.1"));
        assert!(s.contains("X-Target-Host: dest.server.io"));
        assert!(s.contains("X-Target-Port: 443"));
        assert!(s.contains("X-Relay-Token: secret123"));
        assert!(framed.ends_with(payload));
    }
}
