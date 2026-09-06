//! # Header Sanitization
//!
//! Hop-by-hop and proxy-leaking headers that must be stripped from relayed requests.

use std::collections::HashSet;

/// Headers that must be stripped from relayed requests.
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
    "accept-encoding",
];

/// Returns true if the header should be stripped.
pub fn should_strip_header(name: &str) -> bool {
    STRIP_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name))
}

/// Builds a set for fast lookup.
pub fn build_strip_set() -> HashSet<String> {
    STRIP_HEADERS.iter().map(|s| s.to_lowercase()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_headers() {
        assert!(should_strip_header("X-Forwarded-For"));
        assert!(should_strip_header("PROXY-AUTHORIZATION"));
        assert!(!should_strip_header("Authorization"));
        assert!(!should_strip_header("Content-Type"));
    }
}
