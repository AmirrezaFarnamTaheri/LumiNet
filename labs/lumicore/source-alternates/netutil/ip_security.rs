//! # IP Security Analysis
//!
//! IP reputation scoring, security header analysis, and WebRTC leak detection.
//! Ported from IP-Security-Analyzer-Cloudflare-Worker.
//!
//! Uses `netutil` module for IP validation and network classification.
//! This module adds header analysis and WebRTC leak detection on top.

use std::net::IpAddr;

// Re-export netutil functions for backward compatibility
pub use crate::netutil::{
    is_private_address as is_private_ip,
    classify_network_type,
    compute_risk_score,
    known_hosting_asns,
    NetworkType,
};

// ─── Header Analysis ─────────────────────────────────────────────────────────

/// Header analysis result.
#[derive(Debug, Clone)]
pub struct HeaderAnalysis {
    pub has_user_agent: bool,
    pub has_client_hints: bool,
    pub is_automation: bool,
    pub tls_version: Option<String>,
    pub bot_score: Option<u32>,
    pub risk_factors: Vec<String>,
}

/// Analyzes HTTP headers for security signals.
/// Detects automation signatures, missing headers, and bot indicators.
pub fn analyze_headers(headers: &[(String, String)]) -> HeaderAnalysis {
    let mut has_user_agent = false;
    let mut has_client_hints = false;
    let mut is_automation = false;
    let mut tls_version = None;
    let mut bot_score = None;
    let mut risk_factors = Vec::new();

    for (name, value) in headers {
        let lower_name = name.to_lowercase();

        match lower_name.as_str() {
            "user-agent" => {
                has_user_agent = true;
                let lower_value = value.to_lowercase();
                if lower_value.contains("headless")
                    || lower_value.contains("phantom")
                    || lower_value.contains("selenium")
                    || lower_value.contains("puppeteer")
                    || lower_value.contains("playwright")
                    || lower_value.contains("bot")
                    || lower_value.contains("crawler")
                    || lower_value.contains("spider")
                {
                    is_automation = true;
                    risk_factors.push("Automation UA detected".to_string());
                }
                if value.is_empty() {
                    risk_factors.push("Empty User-Agent".to_string());
                }
            }
            "sec-ch-ua" | "sec-ch-ua-mobile" | "sec-ch-ua-platform" => {
                has_client_hints = true;
            }
            "cf-bot-score" => {
                if let Ok(score) = value.parse() {
                    bot_score = Some(score);
                }
            }
            "cf-tls-version" => {
                tls_version = Some(value.clone());
            }
            _ => {}
        }
    }

    if !has_user_agent {
        risk_factors.push("Missing User-Agent".to_string());
    }
    if !has_client_hints {
        risk_factors.push("Missing Client Hints (possible bot)".to_string());
    }

    HeaderAnalysis {
        has_user_agent,
        has_client_hints,
        is_automation,
        tls_version,
        bot_score,
        risk_factors,
    }
}

// ─── WebRTC Leak Detection ──────────────────────────────────────────────────

/// WebRTC leak test result.
#[derive(Debug, Clone)]
pub struct WebRTCLeakResult {
    pub public_ip_match: bool,
    pub private_ip_exposed: bool,
    pub mDNS_masked: bool,
    pub ice_candidates: Vec<String>,
}

/// Analyzes WebRTC ICE candidates for IP leaks.
/// Detects when browser exposes real IP via WebRTC despite VPN/proxy.
pub fn analyze_webrtc_leak(
    server_ip: &str,
    ice_candidates: &[String],
) -> WebRTCLeakResult {
    let mut public_ip_match = false;
    let mut private_ip_exposed = false;
    let mut mDNS_masked = false;

    for candidate in ice_candidates {
        // Check for mDNS masking (privacy feature)
        if candidate.contains(".local") {
            mDNS_masked = true;
            continue;
        }

        // Extract IP from ICE candidate
        if let Some(ip) = extract_ip_from_candidate(candidate) {
            if crate::netutil::is_private_address(&ip) {
                private_ip_exposed = true;
            } else if ip.to_string() == server_ip {
                public_ip_match = true;
            }
        }
    }

    WebRTCLeakResult {
        public_ip_match,
        private_ip_exposed,
        mDNS_masked,
        ice_candidates: ice_candidates.to_vec(),
    }
}

/// Extracts an IP address from an ICE candidate string.
fn extract_ip_from_candidate(candidate: &str) -> Option<IpAddr> {
    for part in candidate.split_whitespace() {
        if part.contains('.') || part.contains(':') {
            let clean = part.trim_end_matches(',');
            if let Ok(ip) = clean.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}

// ─── IP Analysis Result ─────────────────────────────────────────────────────

/// Complete IP analysis result combining all checks.
#[derive(Debug, Clone)]
pub struct IpAnalysis {
    pub ip: String,
    pub network_type: NetworkType,
    pub risk_score: u32,
    pub asn: Option<u32>,
    pub as_name: Option<String>,
    pub country: Option<String>,
    pub is_tor: bool,
    pub is_vpn: bool,
    pub is_proxy: bool,
    pub abuse_score: Option<u32>,
    pub risk_factors: Vec<String>,
}

/// Performs a complete IP analysis.
pub fn analyze_ip(
    ip: &str,
    asn: Option<u32>,
    as_name: Option<&str>,
    is_tor: bool,
    is_vpn: bool,
    abuse_score: Option<u32>,
    abuse_reports: u32,
) -> IpAnalysis {
    let parsed_ip: IpAddr = ip.parse().unwrap_or("0.0.0.0".parse().unwrap());
    let network_type = asn
        .zip(as_name)
        .map(|(a, n)| classify_network_type(a, n))
        .unwrap_or(NetworkType::Unknown);

    let (risk_score, risk_factors) = compute_risk_score(
        network_type,
        is_tor,
        is_vpn,
        abuse_score,
        abuse_reports,
    );

    IpAnalysis {
        ip: ip.to_string(),
        network_type,
        risk_score,
        asn,
        as_name: as_name.map(|s| s.to_string()),
        country: None,
        is_tor,
        is_vpn,
        is_proxy: false,
        abuse_score,
        risk_factors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_analysis() {
        let headers = vec![
            ("User-Agent".to_string(), "Mozilla/5.0".to_string()),
            ("sec-ch-ua".to_string(), "Chrome".to_string()),
        ];
        let result = analyze_headers(&headers);
        assert!(result.has_user_agent);
        assert!(result.has_client_hints);
        assert!(!result.is_automation);
    }

    #[test]
    fn test_automation_detection() {
        let headers = vec![
            ("User-Agent".to_string(), "HeadlessChrome Selenium".to_string()),
        ];
        let result = analyze_headers(&headers);
        assert!(result.is_automation);
    }

    #[test]
    fn test_webrtc_leak() {
        let candidates = vec![
            "candidate:1 1 UDP 2122252543 192.168.1.100 12345 typ host".to_string(),
        ];
        let result = analyze_webrtc_leak("8.8.8.8", &candidates);
        assert!(result.private_ip_exposed);
        assert!(!result.public_ip_match);
    }

    #[test]
    fn test_ip_analysis() {
        let analysis = analyze_ip(
            "8.8.8.8",
            Some(15169),
            Some("Google LLC"),
            false,
            false,
            None,
            0,
        );
        assert_eq!(analysis.network_type, NetworkType::Hosting);
        assert_eq!(analysis.risk_score, 100);
    }
}
