//! # Protocol Detector
//!
//! Detects protocols from the first bytes of a connection.
//! Uses signatures from `signatures.rs` and pattern matching.

use super::signatures::get_all_signatures;
use crate::netutil::contains_pattern;

/// Protocol match result.
#[derive(Debug, Clone)]
pub struct ProtocolMatch {
    pub protocol: String,
    pub confidence: f32,
    pub category: ProtocolCategory,
}

/// Protocol category.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProtocolCategory {
    Web,
    Email,
    Chat,
    VoIP,
    VPN,
    P2P,
    RemoteAccess,
    Gaming,
    FileTransfer,
    DNS,
    Networking,
    Streaming,
    Other,
}

/// Detects protocol from the first bytes of a connection.
pub fn detect_protocol(data: &[u8]) -> Option<ProtocolMatch> {
    if data.is_empty() {
        return None;
    }

    let signatures = get_all_signatures();
    let mut best_match: Option<ProtocolMatch> = None;
    let mut best_confidence = 0.0f32;

    for sig in &signatures {
        // Check prefix match
        if !sig.patterns.prefix.is_empty() {
            for &p in sig.patterns.prefix {
                if data.starts_with(&[p]) {
                    let confidence = 0.85;
                    if confidence > best_confidence {
                        best_confidence = confidence;
                        best_match = Some(ProtocolMatch {
                            protocol: sig.name.to_string(),
                            confidence,
                            category: sig.category,
                        });
                    }
                    break;
                }
            }
        }

        // Check contains match (search first 512 bytes)
        let search_len = data.len().min(512);
        let search_data = &data[..search_len];

        for &pattern in sig.patterns.contains {
            if !pattern.is_empty() && contains_pattern(search_data, pattern) {
                let confidence = 0.9;
                if confidence > best_confidence {
                    best_confidence = confidence;
                    best_match = Some(ProtocolMatch {
                        protocol: sig.name.to_string(),
                        confidence,
                        category: sig.category,
                    });
                }
                break;
            }
        }
    }

    // Fallback: check for TLS specifically
    if data.len() >= 3 && data[0] == 0x16 && data[1] == 0x03 && best_confidence < 0.95 {
        return Some(ProtocolMatch {
            protocol: "tls".to_string(),
            confidence: 0.95,
            category: ProtocolCategory::VPN,
        });
    }

    // Fallback: check for DNS
    if data.len() >= 12 {
        let qdcount = u16::from_be_bytes([data[4], data[5]]);
        let flags = u16::from_be_bytes([data[2], data[3]]);
        if (flags & 0x8000 == 0) && (flags & 0x7800 == 0) && qdcount >= 1 && best_confidence < 0.8 {
            return Some(ProtocolMatch {
                protocol: "dns".to_string(),
                confidence: 0.8,
                category: ProtocolCategory::DNS,
            });
        }
    }

    best_match
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_http() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        let result = detect_protocol(data).unwrap();
        assert_eq!(result.protocol, "http");
    }

    #[test]
    fn test_detect_tls() {
        let data = vec![0x16, 0x03, 0x01, 0x00, 0x05];
        let result = detect_protocol(&data).unwrap();
        assert_eq!(result.protocol, "tls");
    }

    #[test]
    fn test_empty_data() {
        assert!(detect_protocol(&[]).is_none());
    }
}
