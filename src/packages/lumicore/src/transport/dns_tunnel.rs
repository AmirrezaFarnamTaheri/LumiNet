//! DNS-over-UDP / DNSTT Covert Tunnel Engine
//!
//! Ported and unified from `WhiteDNS-Android-main` (`WhiteDnsAutoTune.kt`), `WhiteAesther-main`,
//! and dnstt client architectures.
//! Implements a resilient DNS tunnel with Base32 label chunking (RFC 1035 63-byte label limits),
//! TXT/NULL record encoding, packet duplication for lossy links, and Iran-specific auto-tune profiles.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;
use serde::{Deserialize, Serialize};

/// Maximum length of a single DNS domain label per RFC 1035.
pub const MAX_DNS_LABEL_LEN: usize = 63;
/// Maximum length of a full DNS query name per RFC 1035.
pub const MAX_DNS_NAME_LEN: usize = 253;

/// DNS Record Types used for tunnel transport.
pub const DNS_TYPE_A: u16 = 1;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_NULL: u16 = 10;
pub const DNS_CLASS_IN: u16 = 1;

/// Network stability profile for DNS tunnel parameter auto-tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsTunnelPreset {
    /// Baseline tuned for filtered mobile/cellular networks (e.g. MCI / Irancell).
    IranAverage,
    /// Conservative profile with low MTU and high redundancy for heavily choked UDP.
    IranLowMtu,
    /// Balanced standard profile for broadband connections.
    Standard,
}

/// Dynamic auto-tune parameters controlling packet size, timeouts, and duplication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsTunnelConfig {
    pub preset: DnsTunnelPreset,
    pub domain: String,
    pub resolver: Option<SocketAddr>,
    pub min_upload_mtu: usize,
    pub max_upload_mtu: usize,
    pub min_download_mtu: usize,
    pub max_download_mtu: usize,
    pub resolver_timeout: Duration,
    pub fragment_store_capacity: usize,
    pub upload_duplication: usize,
    pub download_duplication: usize,
    pub record_type: u16,
}

impl Default for DnsTunnelConfig {
    fn default() -> Self {
        Self::from_preset(DnsTunnelPreset::IranAverage, "t.example.com")
    }
}

impl DnsTunnelConfig {
    /// Constructs an auto-tuned configuration based on network profile.
    pub fn from_preset(preset: DnsTunnelPreset, domain: impl Into<String>) -> Self {
        let domain_str = domain.into();
        match preset {
            DnsTunnelPreset::IranAverage => Self {
                preset,
                domain: domain_str,
                resolver: None,
                min_upload_mtu: 40,
                max_upload_mtu: 140,
                min_download_mtu: 300,
                max_download_mtu: 3000,
                resolver_timeout: Duration::from_millis(2500),
                fragment_store_capacity: 256,
                upload_duplication: 3,
                download_duplication: 7,
                record_type: DNS_TYPE_TXT,
            },
            DnsTunnelPreset::IranLowMtu => Self {
                preset,
                domain: domain_str,
                resolver: None,
                min_upload_mtu: 20,
                max_upload_mtu: 120,
                min_download_mtu: 160,
                max_download_mtu: 768,
                resolver_timeout: Duration::from_millis(3500),
                fragment_store_capacity: 512,
                upload_duplication: 4,
                download_duplication: 8,
                record_type: DNS_TYPE_TXT,
            },
            DnsTunnelPreset::Standard => Self {
                preset,
                domain: domain_str,
                resolver: None,
                min_upload_mtu: 60,
                max_upload_mtu: 200,
                min_download_mtu: 512,
                max_download_mtu: 4096,
                resolver_timeout: Duration::from_millis(1500),
                fragment_store_capacity: 128,
                upload_duplication: 1,
                download_duplication: 1,
                record_type: DNS_TYPE_TXT,
            },
        }
    }
}

/// Errors occurring during DNS tunnel encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsTunnelError {
    PayloadTooLarge { max: usize, found: usize },
    InvalidName(String),
    MalformedPacket,
    NoAnswerFound,
    UnsupportedRecordType(u16),
}

impl fmt::Display for DnsTunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { max, found } => {
                write!(f, "dns payload exceeds max {} bytes, found {}", max, found)
            }
            Self::InvalidName(s) => write!(f, "invalid dns domain name: {}", s),
            Self::MalformedPacket => write!(f, "malformed dns packet"),
            Self::NoAnswerFound => write!(f, "no answer records found in dns response"),
            Self::UnsupportedRecordType(t) => write!(f, "unsupported dns record type {}", t),
        }
    }
}

impl std::error::Error for DnsTunnelError {}

// ---- RFC 4648 Base32 for DNS Labels (Lowercase, Unpadded) ----
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encodes raw payload into lowercase unpadded Base32.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u64);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

/// Decodes lowercase Base32 back into raw bytes.
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity((s.len() * 5) / 8);
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;

    for c in s.bytes() {
        let val = match c {
            b'a'..=b'z' => c - b'a',
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | (val as u64);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// The DNS Tunnel engine managing query crafting and response ingestion.
pub struct DNSTunnel {
    pub config: DnsTunnelConfig,
}

impl DNSTunnel {
    /// Creates a new DNS tunnel instance with the given configuration.
    pub fn new(config: DnsTunnelConfig) -> Self {
        Self { config }
    }

    /// Formats data into RFC 1035 compliant DNS labels (each <= 63 characters) appended to base domain.
    pub fn format_query_name(&self, payload: &[u8]) -> Result<String, DnsTunnelError> {
        let encoded = base32_encode(payload);
        let mut labels = Vec::new();

        // Split into chunks of at most 63 chars
        for chunk in encoded.as_bytes().chunks(MAX_DNS_LABEL_LEN) {
            labels.push(std::str::from_utf8(chunk).unwrap());
        }

        let full_name = format!("{}.{}", labels.join("."), self.config.domain.trim_start_matches('.'));
        if full_name.len() > MAX_DNS_NAME_LEN {
            return Err(DnsTunnelError::PayloadTooLarge {
                max: MAX_DNS_NAME_LEN,
                found: full_name.len(),
            });
        }

        Ok(full_name)
    }

    /// Builds an RFC 1035 DNS Question packet containing the tunneled payload.
    pub fn build_query_packet(
        &self,
        tx_id: u16,
        qname: &str,
        qtype: u16,
    ) -> Result<Vec<u8>, DnsTunnelError> {
        let mut buf = Vec::with_capacity(12 + qname.len() + 6);

        // 1. Transaction ID (2 bytes)
        buf.extend_from_slice(&tx_id.to_be_bytes());

        // 2. Flags: Standard Query with Recursion Desired (0x0100)
        buf.extend_from_slice(&[0x01, 0x00]);

        // 3. QDCOUNT = 1 (1 question), ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // 4. QNAME labels
        for label in qname.split('.') {
            if label.is_empty() {
                continue;
            }
            if label.len() > MAX_DNS_LABEL_LEN {
                return Err(DnsTunnelError::InvalidName(format!(
                    "label exceeds {} bytes",
                    MAX_DNS_LABEL_LEN
                )));
            }
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0x00); // Root label null terminator

        // 5. QTYPE (2 bytes)
        buf.extend_from_slice(&qtype.to_be_bytes());

        // 6. QCLASS: IN = 1 (2 bytes)
        buf.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        Ok(buf)
    }

    /// Parses a DNS response packet and extracts the payload from TXT or NULL records.
    pub fn extract_response_payload(&self, response: &[u8]) -> Result<Vec<u8>, DnsTunnelError> {
        if response.len() < 12 {
            return Err(DnsTunnelError::MalformedPacket);
        }

        let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
        if ancount == 0 {
            return Err(DnsTunnelError::NoAnswerFound);
        }

        // Skip DNS header (12 bytes)
        let mut pos = 12;

        // Skip Question Section
        let qdcount = u16::from_be_bytes([response[4], response[5]]) as usize;
        for _ in 0..qdcount {
            pos = Self::skip_name(response, pos)?;
            pos += 4; // Skip QTYPE (2) + QCLASS (2)
            if pos > response.len() {
                return Err(DnsTunnelError::MalformedPacket);
            }
        }

        let mut extracted_data = Vec::new();

        // Read Answers
        for _ in 0..ancount {
            if pos >= response.len() {
                break;
            }
            pos = Self::skip_name(response, pos)?;
            if pos + 10 > response.len() {
                return Err(DnsTunnelError::MalformedPacket);
            }

            let rtype = u16::from_be_bytes([response[pos], response[pos + 1]]);
            let _rclass = u16::from_be_bytes([response[pos + 2], response[pos + 3]]);
            let _ttl = u32::from_be_bytes([
                response[pos + 4],
                response[pos + 5],
                response[pos + 6],
                response[pos + 7],
            ]);
            let rdlength = u16::from_be_bytes([response[pos + 8], response[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > response.len() {
                return Err(DnsTunnelError::MalformedPacket);
            }

            let rdata = &response[pos..pos + rdlength];
            pos += rdlength;

            match rtype {
                DNS_TYPE_TXT => {
                    // TXT records contain <len><string> segments
                    let mut txt_pos = 0;
                    while txt_pos < rdata.len() {
                        let slen = rdata[txt_pos] as usize;
                        txt_pos += 1;
                        if txt_pos + slen <= rdata.len() {
                            extracted_data.extend_from_slice(&rdata[txt_pos..txt_pos + slen]);
                            txt_pos += slen;
                        }
                    }
                }
                DNS_TYPE_NULL => {
                    // NULL records contain raw binary data directly
                    extracted_data.extend_from_slice(rdata);
                }
                _ => {}
            }
        }

        if extracted_data.is_empty() {
            return Err(DnsTunnelError::NoAnswerFound);
        }

        // Decode Base32 if payload is text-encoded
        if let Ok(text) = std::str::from_utf8(&extracted_data) {
            if let Some(decoded) = base32_decode(text) {
                return Ok(decoded);
            }
        }

        Ok(extracted_data)
    }

    /// Skips a DNS name (handling compression pointers per RFC 1035).
    fn skip_name(buf: &[u8], mut pos: usize) -> Result<usize, DnsTunnelError> {
        while pos < buf.len() {
            let len = buf[pos] as usize;
            if len == 0 {
                return Ok(pos + 1);
            }
            if (len & 0xC0) == 0xC0 {
                // Compression pointer: 2 bytes
                return Ok(pos + 2);
            }
            pos += 1 + len;
        }
        Err(DnsTunnelError::MalformedPacket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_codec() {
        let original = b"covert dns tunneled payload 12345";
        let encoded = base32_encode(original);
        let decoded = base32_decode(&encoded).expect("valid decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_format_query_name() {
        let tunnel = DNSTunnel::new(DnsTunnelConfig::from_preset(
            DnsTunnelPreset::IranAverage,
            "tunnel.domain.com",
        ));

        let qname = tunnel.format_query_name(b"test1234").expect("format name");
        assert!(qname.ends_with(".tunnel.domain.com"));

        // All labels must be <= 63 chars
        for label in qname.split('.') {
            assert!(label.len() <= MAX_DNS_LABEL_LEN);
        }
    }

    #[test]
    fn test_build_query_packet() {
        let tunnel = DNSTunnel::new(DnsTunnelConfig::default());
        let packet = tunnel
            .build_query_packet(0x1234, "abc.def.tunnel.com", DNS_TYPE_TXT)
            .expect("build packet");

        assert_eq!(&packet[0..2], &[0x12, 0x34]); // TX ID
        assert_eq!(&packet[2..4], &[0x01, 0x00]); // Standard Query + RD
        assert_eq!(&packet[4..6], &[0x00, 0x01]); // 1 question
    }

    #[test]
    fn test_extract_txt_response() {
        let tunnel = DNSTunnel::new(DnsTunnelConfig::default());

        // Build a mock DNS response with 1 Question and 1 TXT Answer
        let mut resp = Vec::new();
        // Header
        resp.extend_from_slice(&[0x12, 0x34, 0x81, 0x80]); // Response, NoError
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]); // QD=1, AN=1

        // Question: "a.com"
        resp.extend_from_slice(&[0x01, b'a', 0x03, b'c', b'o', b'm', 0x00]);
        resp.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // Type TXT, Class IN

        // Answer: pointer to name (0xC00C)
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x10, 0x00, 0x01]); // Type TXT, Class IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60s

        // Payload: Base32 encoded "hello world"
        let encoded_payload = base32_encode(b"hello world");
        let rdlen = (1 + encoded_payload.len()) as u16;
        resp.extend_from_slice(&rdlen.to_be_bytes());
        resp.push(encoded_payload.len() as u8);
        resp.extend_from_slice(encoded_payload.as_bytes());

        let payload = tunnel
            .extract_response_payload(&resp)
            .expect("extract payload");
        assert_eq!(payload, b"hello world");
    }
}
