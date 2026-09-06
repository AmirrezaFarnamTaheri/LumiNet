//! # SSRF Protection
//!
//! Validates relay target URLs don't point to private infrastructure.

use super::ip_check::is_private_address;
use std::net::IpAddr;

/// Validates a relay target URL doesn't point to private infrastructure.
pub fn validate_relay_target(url: &str) -> Result<(), String> {
    let hostname =
        extract_hostname(url).ok_or_else(|| format!("Cannot parse hostname from URL: {}", url))?;

    if let Ok(ip) = hostname.parse::<IpAddr>() {
        if is_private_address(&ip) {
            return Err(format!(
                "Blocked: target {} is a private/reserved address",
                ip
            ));
        }
    }
    Ok(())
}

/// Extracts hostname from a URL string.
pub fn extract_hostname(url: &str) -> Option<&str> {
    let url = url.trim();
    let after_proto = if let Some(pos) = url.find("://") {
        &url[pos + 3..]
    } else {
        url
    };
    let host_port = after_proto.split('/').next()?;
    let host_and_port = host_port.split('@').next_back().unwrap_or(host_port);
    let host = host_and_port.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_relay_target() {
        assert!(validate_relay_target("https://example.com/api").is_ok());
        assert!(validate_relay_target("https://10.0.0.1/admin").is_err());
        assert!(validate_relay_target("https://127.0.0.1/local").is_err());
    }

    #[test]
    fn test_extract_hostname() {
        assert_eq!(
            extract_hostname("https://example.com/path"),
            Some("example.com")
        );
        assert_eq!(
            extract_hostname("http://10.0.0.1:8080/api"),
            Some("10.0.0.1")
        );
        assert_eq!(
            extract_hostname("https://user:pass@host.com/"),
            Some("host.com")
        );
    }
}
