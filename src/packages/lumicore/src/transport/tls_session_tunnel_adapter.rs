//! # TLS Session Tunnel Adapter
//!
//! Encapsulates arbitrary IP/TCP streams into valid TLS application data frames
//! disguised with standard HTTP/2 or WebSocket pseudo-headers to prevent active probe fingerprinting.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MasqueradeMode {
    WebSocketUpgrade,
    Http2PostStream,
    RawTlsRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsTunnelConfig {
    pub server_sni: String,
    pub masquerade_mode: MasqueradeMode,
    pub session_ticket_key: Vec<u8>,
    pub max_record_size: usize,
}

pub struct TlsSessionTunnelAdapter {
    config: TlsTunnelConfig,
    is_handshake_complete: bool,
    stream_sequence: u64,
}

impl TlsSessionTunnelAdapter {
    pub fn new(config: TlsTunnelConfig) -> Self {
        Self {
            config,
            is_handshake_complete: false,
            stream_sequence: 0,
        }
    }

    pub fn generate_handshake_preamble(&mut self) -> Vec<u8> {
        let mut preamble = Vec::new();

        match self.config.masquerade_mode {
            MasqueradeMode::WebSocketUpgrade => {
                let req = format!(
                    "GET /api/v1/telemetry HTTP/1.1\r\n\
                     Host: {}\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                     Sec-WebSocket-Version: 13\r\n\r\n",
                    self.config.server_sni
                );
                preamble.extend_from_slice(req.as_bytes());
            }
            MasqueradeMode::Http2PostStream => {
                let req = format!(
                    "POST /upload/stream HTTP/1.1\r\n\
                     Host: {}\r\n\
                     Content-Type: application/octet-stream\r\n\
                     Transfer-Encoding: chunked\r\n\r\n",
                    self.config.server_sni
                );
                preamble.extend_from_slice(req.as_bytes());
            }
            MasqueradeMode::RawTlsRecord => {
                // Synthesize TLS 1.3 ClientHello envelope
                preamble.extend_from_slice(&[0x16, 0x03, 0x03]); // Record header
                preamble.extend_from_slice(&[0x00, 0x20]); // Length 32
                preamble.extend_from_slice(&self.config.session_ticket_key[..32.min(self.config.session_ticket_key.len())]);
                while preamble.len() < 37 {
                    preamble.push(0x00);
                }
            }
        }

        self.is_handshake_complete = true;
        preamble
    }

    pub fn wrap_data(&mut self, payload: &[u8]) -> Vec<u8> {
        self.stream_sequence += 1;
        let mut record = Vec::with_capacity(5 + payload.len() + 1);

        // TLS 1.3 Application Data Record (0x17, 0x03, 0x03, len_hi, len_lo)
        let record_len = (payload.len() + 1) as u16; // +1 for inner content type (0x17)
        record.push(0x17);
        record.push(0x03);
        record.push(0x03);
        record.extend_from_slice(&record_len.to_be_bytes());

        // Payload + trailing inner content type tag
        record.extend_from_slice(payload);
        record.push(0x17); // Inner type: Application Data

        record
    }

    pub fn unwrap_data(&self, record: &[u8]) -> Result<Vec<u8>, String> {
        if record.len() < 6 {
            return Err("Record too short".to_string());
        }

        if record[0] != 0x17 || record[1] != 0x03 || record[2] != 0x03 {
            return Err("Invalid TLS record header".to_string());
        }

        let len = u16::from_be_bytes([record[3], record[4]]) as usize;
        if record.len() < 5 + len {
            return Err("Incomplete record payload".to_string());
        }

        let inner_data = &record[5..5 + len];
        if inner_data.is_empty() {
            return Err("Empty inner payload".to_string());
        }

        // Verify trailing inner content type
        let last_byte = inner_data[inner_data.len() - 1];
        if last_byte != 0x17 {
            return Err("Invalid inner content type tag".to_string());
        }

        Ok(inner_data[..inner_data.len() - 1].to_vec())
    }

    pub fn is_ready(&self) -> bool {
        self.is_handshake_complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_session_tunnel_adapter() {
        let config = TlsTunnelConfig {
            server_sni: "edge.gateway.cdn".to_string(),
            masquerade_mode: MasqueradeMode::WebSocketUpgrade,
            session_ticket_key: vec![0xaa; 32],
            max_record_size: 16384,
        };

        let mut adapter = TlsSessionTunnelAdapter::new(config);
        assert!(!adapter.is_ready());

        let preamble = adapter.generate_handshake_preamble();
        let preamble_str = String::from_utf8_lossy(&preamble);
        assert!(preamble_str.contains("Host: edge.gateway.cdn"));
        assert!(preamble_str.contains("Upgrade: websocket"));
        assert!(adapter.is_ready());

        let payload = b"Sensitive Encapsulated Traffic 12345";
        let wrapped = adapter.wrap_data(payload);
        assert_eq!(wrapped[0], 0x17); // TLS Application data
        assert_eq!(wrapped[1], 0x03);
        assert_eq!(wrapped[2], 0x03);

        let unwrapped = adapter.unwrap_data(&wrapped).unwrap();
        assert_eq!(unwrapped, payload);
    }
}
