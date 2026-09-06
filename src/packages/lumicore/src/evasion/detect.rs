//! # Censorship Detection
//!
//! Detects and classifies ISP censorship methods.
//! Consolidates: censorship_detect.rs + dpi_evasion.rs (without duplicates).

use std::net::IpAddr;

/// DNS manipulation detection result.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsManipulation {
    None,
    Redirected,
    RedirectedAndSpoofed,
    Spoofed,
    DnsBlocked,
    Unknown,
}

/// HTTP blocking detection result.
#[derive(Debug, Clone, PartialEq)]
pub enum HttpBlocking {
    None,
    IpBlock,
    UrlDpi,
    FullDpi,
}

/// HTTPS certificate result.
#[derive(Debug, Clone, PartialEq)]
pub enum HttpsResult {
    Ok,
    CertificateSpoofed,
    Blocked,
}

/// DNS comparison result.
#[derive(Debug, Clone)]
pub struct DnsComparison {
    pub system_ips: Vec<IpAddr>,
    pub trusted_ips: Vec<IpAddr>,
    pub doh_ips: Vec<IpAddr>,
    pub fake_dns_ips: Vec<IpAddr>,
}

/// Full censorship detection report.
#[derive(Debug, Clone)]
pub struct CensorshipReport {
    pub dns: DnsManipulation,
    pub http: HttpBlocking,
    pub https: HttpsResult,
    pub passive_dpi: bool,
}

/// Detects DNS manipulation by comparing responses from multiple sources.
pub fn detect_dns_manipulation(comparison: &DnsComparison) -> DnsManipulation {
    if !comparison.fake_dns_ips.is_empty() {
        return if comparison.system_ips != comparison.doh_ips {
            DnsManipulation::RedirectedAndSpoofed
        } else {
            DnsManipulation::Redirected
        };
    }
    if !comparison.system_ips.is_empty()
        && !comparison.doh_ips.is_empty()
        && comparison.system_ips != comparison.doh_ips
    {
        return DnsManipulation::Spoofed;
    }
    if comparison.trusted_ips.is_empty() && !comparison.system_ips.is_empty() {
        return DnsManipulation::DnsBlocked;
    }
    DnsManipulation::None
}

/// Classifies HTTP blocking based on direct vs proxy access results.
pub fn classify_http_blocking(
    direct_success: bool,
    proxy_success: bool,
    ipv6_success: bool,
) -> HttpBlocking {
    match (direct_success, proxy_success, ipv6_success) {
        (true, _, _) => HttpBlocking::None,
        (false, true, _) => HttpBlocking::UrlDpi,
        (false, false, true) => HttpBlocking::IpBlock,
        (false, false, false) => HttpBlocking::FullDpi,
    }
}

/// Detects HTTPS certificate spoofing (MITM).
pub fn detect_https_mitm(
    connection_success: bool,
    cert_valid: bool,
    expected_content_found: bool,
) -> HttpsResult {
    if !connection_success {
        return HttpsResult::Blocked;
    }
    if !cert_valid {
        return HttpsResult::CertificateSpoofed;
    }
    if expected_content_found {
        return HttpsResult::Ok;
    }
    HttpsResult::Blocked
}

/// Detects passive DPI: content leaks through a non-200 response.
pub fn detect_passive_dpi(response: &[u8], expected_content: &str) -> bool {
    let response_str = String::from_utf8_lossy(response);
    if let Some(status_end) = response_str.find("\r\n") {
        let status_line = &response_str[..status_end];
        if !status_line.contains("200") && response_str.contains(expected_content) {
            return true;
        }
    }
    false
}

/// Runs a full censorship detection scan.
pub fn run_detection_scan(
    dns_comparison: &DnsComparison,
    direct_http: bool,
    proxy_http: bool,
    ipv6_http: bool,
    https_result: HttpsResult,
    response_body: &[u8],
    expected_content: &str,
) -> CensorshipReport {
    CensorshipReport {
        dns: detect_dns_manipulation(dns_comparison),
        http: classify_http_blocking(direct_http, proxy_http, ipv6_http),
        https: https_result,
        passive_dpi: detect_passive_dpi(response_body, expected_content),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_no_manipulation() {
        let comp = DnsComparison {
            system_ips: vec!["1.2.3.4".parse().unwrap()],
            trusted_ips: vec!["1.2.3.4".parse().unwrap()],
            doh_ips: vec!["1.2.3.4".parse().unwrap()],
            fake_dns_ips: vec![],
        };
        assert_eq!(detect_dns_manipulation(&comp), DnsManipulation::None);
    }

    #[test]
    fn test_dns_spoofed() {
        let comp = DnsComparison {
            system_ips: vec!["5.6.7.8".parse().unwrap()],
            trusted_ips: vec!["1.2.3.4".parse().unwrap()],
            doh_ips: vec!["1.2.3.4".parse().unwrap()],
            fake_dns_ips: vec![],
        };
        assert_eq!(detect_dns_manipulation(&comp), DnsManipulation::Spoofed);
    }

    #[test]
    fn test_http_no_blocking() {
        assert_eq!(classify_http_blocking(true, true, true), HttpBlocking::None);
    }

    #[test]
    fn test_passive_dpi() {
        let response = b"HTTP/1.1 403 Forbidden\r\n\r\n<html>Expected Content</html>";
        assert!(detect_passive_dpi(response, "Expected Content"));
    }
}
