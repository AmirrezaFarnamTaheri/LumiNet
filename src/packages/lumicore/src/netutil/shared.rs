//! # Shared Utilities
//!
//! Common utility functions used across multiple modules.
//! Consolidates duplicates from forensics, http_tunnel, proxy_handler, etc.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns current Unix timestamp in seconds.
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Returns current Unix timestamp in milliseconds.
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Encodes bytes to hex string.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Decodes hex string to bytes.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("Odd-length hex string".to_string());
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let byte = u8::from_str_radix(std::str::from_utf8(chunk).map_err(|e| e.to_string())?, 16)
            .map_err(|e| e.to_string())?;
        bytes.push(byte);
    }
    Ok(bytes)
}

/// Encodes bytes to base64 string.
pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decodes base64 string to bytes.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| e.to_string())
}

/// Decodes base64 string to UTF-8 string.
pub fn base64_decode_str(s: &str) -> Result<String, String> {
    let bytes = base64_decode(s)?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

/// Encodes bytes to base64url (URL-safe, no padding).
pub fn base64url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decodes base64url (URL-safe, no padding) to bytes.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| e.to_string())
}

/// Searches for a byte pattern in a byte slice.
/// Returns the index of the first occurrence.
pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

/// Searches for a byte pattern in a byte slice (alias for find_pattern).
pub fn contains_pattern(haystack: &[u8], needle: &[u8]) -> bool {
    find_pattern(haystack, needle).is_some()
}

/// Computes MD5 hash of input bytes, returns hex string.
pub fn md5_hex(input: &[u8]) -> String {
    let result = md5::compute(input);
    format!("{:x}", result)
}

/// Computes SHA-256 hash of input bytes, returns hex string.
pub fn sha256_hex(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let result = Sha256::digest(input);
    hex_encode(&result)
}

/// Formats bytes into human-readable string.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    for unit in UNITS {
        if value < 1024.0 {
            return format!("{:.1} {}", value, unit);
        }
        value /= 1024.0;
    }
    format!("{:.1} PB", value)
}

/// Formats duration into human-readable string.
pub fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m {}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

/// Formats milliseconds into human-readable latency string.
pub fn format_latency(ms: f64) -> String {
    if ms < 1.0 {
        "<1ms".to_string()
    } else if ms < 1000.0 {
        format!("{:.0}ms", ms)
    } else {
        format!("{:.1}s", ms / 1000.0)
    }
}

/// Returns the minimum of two values.
pub fn min<T: Ord>(a: T, b: T) -> T {
    if a < b {
        a
    } else {
        b
    }
}

/// Returns the maximum of two values.
pub fn max<T: Ord>(a: T, b: T) -> T {
    if a > b {
        a
    } else {
        b
    }
}

/// Clamps a value between min and max.
pub fn clamp<T: Ord>(value: T, min_val: T, max_val: T) -> T {
    min(max(value, min_val), max_val)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_hex_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "deadbeef");
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, world!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_find_pattern() {
        assert_eq!(find_pattern(b"Hello World", b"World"), Some(6));
        assert_eq!(find_pattern(b"Hello World", b"xyz"), None);
        assert_eq!(find_pattern(b"Hello", b""), None);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0.0 B");
        assert_eq!(format_bytes(1023), "1023.0 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
    }

    #[test]
    fn test_md5_hex() {
        let hash = md5_hex(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello");
        assert_eq!(hash.len(), 64);
    }
}
