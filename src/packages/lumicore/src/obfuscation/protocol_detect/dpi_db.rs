//! # DPI Signature Database
//!
//! Known DPI signatures for censorship detection.

use std::collections::HashMap;

/// DPI signature database.
pub struct DpiSignatureDb {
    signatures: HashMap<String, Vec<Vec<u8>>>,
}

impl Default for DpiSignatureDb {
    fn default() -> Self {
        Self::new()
    }
}

impl DpiSignatureDb {
    /// Creates a new DPI signature database.
    pub fn new() -> Self {
        let mut signatures = HashMap::new();

        // Known DPI probe signatures
        signatures.insert(
            "gfw_probe".to_string(),
            vec![
                b"GET / HTTP/1.1\r\nHost: ".to_vec(),
                b"\x16\x03\x01".to_vec(),
            ],
        );

        // Known censorship patterns
        signatures.insert(
            "http_block".to_string(),
            vec![
                b"HTTP/1.1 403".to_vec(),
                b"HTTP/1.1 451".to_vec(),
                b"Your request has been blocked".to_vec(),
                b"This site has been blocked".to_vec(),
                b"Access Denied".to_vec(),
            ],
        );

        signatures.insert("dns_poison".to_string(), vec![b"\x00\x00\x81\x80".to_vec()]);

        Self { signatures }
    }

    /// Checks if data matches any known DPI signature.
    pub fn check(&self, data: &[u8]) -> Vec<String> {
        let mut matches = Vec::new();
        for (name, patterns) in &self.signatures {
            for pattern in patterns {
                if contains_pattern_bytes(data, pattern) {
                    matches.push(name.clone());
                    break;
                }
            }
        }
        matches
    }
}

fn contains_pattern_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dpi_signature_db() {
        let db = DpiSignatureDb::new();
        let http_block = b"HTTP/1.1 403 Forbidden\r\nYour request has been blocked";
        let matches = db.check(http_block);
        assert!(matches.contains(&"http_block".to_string()));
    }
}
