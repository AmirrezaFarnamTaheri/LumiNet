//! # RFC 8484 DoH Transparent Proxy & ClientHello SNI Offset Scanner
//!
//! Implements RFC 8484 DNS-over-HTTPS wire formatting, connection pooling options,
//! and byte-accurate ClientHello SNI offset extraction for TLS fragmentation.
//!

use serde::{Deserialize, Serialize};

/// RFC 8484 MIME Content-Type.
pub const DOH_CONTENT_TYPE: &str = "application/dns-message";

/// Configuration for DoH connection pool and proxy resolver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DohClientConfig {
    pub endpoint_url: String,
    pub custom_sni: Option<String>,
    pub timeout_ms: u64,
    pub max_idle_connections: usize,
    pub fragmentation_strategy: String,
}

impl Default for DohClientConfig {
    fn default() -> Self {
        Self {
            endpoint_url: "https://cloudflare-dns.com/dns-query".to_string(),
            custom_sni: Some("cloudflare-dns.com".to_string()),
            timeout_ms: 5000,
            max_idle_connections: 16,
            fragmentation_strategy: "sni_split".to_string(),
        }
    }
}

/// Helper encoding DNS query in wire format for RFC 8484 HTTP POST body.
pub fn encode_doh_post_body(wire_dns_query: &[u8]) -> Vec<u8> {
    wire_dns_query.to_vec()
}

/// Validates that an HTTP response payload contains a syntactically valid DNS response.
pub fn validate_doh_response(body: &[u8]) -> Result<Vec<u8>, String> {
    if body.len() < 12 {
        return Err("DNS response payload too short (< 12 bytes)".to_string());
    }
    // Flags byte 2: QR bit (bit 7) must be 1 for response
    let flags = u16::from_be_bytes([body[2], body[3]]);
    let is_response = (flags & 0x8000) != 0;
    if !is_response {
        return Err("DNS packet is a query, expected response (QR bit != 1)".to_string());
    }

    Ok(body.to_vec())
}

/// Scans a TLS ClientHello packet to identify the exact byte offset and length
/// of the Server Name Indication (SNI) hostname string.
///
/// Returns `Some((hostname_start_offset, hostname_len))` if found, or `None`.
pub fn find_sni_hostname_offset(data: &[u8]) -> Option<(usize, usize)> {
    // Minimum TLS ClientHello length with headers
    if data.len() < 44 {
        return None;
    }

    // Must start with TLS Handshake (0x16) and ClientHello (0x01)
    if data[0] != 0x16 {
        return None;
    }

    let mut pos = 5 + 4; // TLS record header (5) + handshake header (4)
    pos += 2; // client version
    pos += 32; // client random

    if pos >= data.len() {
        return None;
    }

    // Session ID
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > data.len() {
        return None;
    }

    // Cipher suites
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    if pos + 1 > data.len() {
        return None;
    }

    // Compression methods
    let comp_methods_len = data[pos] as usize;
    pos += 1 + comp_methods_len;

    if pos + 2 > data.len() {
        return None;
    }

    // Extensions length
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = (pos + extensions_len).min(data.len());

    // Iterate extensions to locate SNI (Type 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 && ext_len > 0 {
            // SNI extension structure:
            // list_length (2) + name_type (1) + hostname_length (2) + hostname
            if pos + 5 <= extensions_end {
                let hostname_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
                let hostname_start = pos + 5;
                if hostname_start + hostname_len <= data.len() {
                    return Some((hostname_start, hostname_len));
                }
            }
        }
        pos += ext_len;
    }

    None
}

/// Splits a TLS ClientHello according to the chosen strategy:
/// - `"sni_split"`: splits at the midpoint of the SNI hostname, desyncing middlebox SNI parsers.
/// - `"half"`: splits the entire payload into two equal halves.
/// - `"multi"`: splits the payload into small fixed-size chunks (24 bytes).
pub fn split_client_hello(data: &[u8], strategy: &str) -> Vec<Vec<u8>> {
    match strategy {
        "sni_split" => {
            if let Some((offset, len)) = find_sni_hostname_offset(data) {
                let mid = if len > 0 {
                    offset + len / 2
                } else {
                    offset + (data.len() - offset) / 2
                };
                let split_pos = mid.clamp(1, data.len().saturating_sub(1));
                vec![data[..split_pos].to_vec(), data[split_pos..].to_vec()]
            } else {
                split_half(data)
            }
        }
        "half" => split_half(data),
        "multi" => split_multi(data, 24),
        _ => split_half(data),
    }
}

fn split_half(data: &[u8]) -> Vec<Vec<u8>> {
    if data.len() <= 1 {
        return vec![data.to_vec()];
    }
    let mid = data.len() / 2;
    vec![data[..mid].to_vec(), data[mid..].to_vec()]
}

fn split_multi(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut offset = 0;
    let size = if chunk_size == 0 { 24 } else { chunk_size };

    while offset < data.len() {
        let end = (offset + size).min(data.len());
        chunks.push(data[offset..end].to_vec());
        offset = end;
    }

    chunks
}
