//! # Network Classification
//!
//! IP reputation scoring and network type classification.

use std::collections::HashSet;

/// Network type classification.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NetworkType {
    Hosting,
    Mobile,
    Residential,
    Corporate,
    Education,
    VPN,
    Proxy,
    Tor,
    Unknown,
}

/// Known hosting/cloud ASN numbers.
pub fn known_hosting_asns() -> HashSet<u32> {
    vec![
        14061, 16276, 16509, 20473, 14618, 396982, 36459, 19527, 24940, 31034, 57043, 20940, 16625,
        13335, 15169, 32934, 13414, 3842, 20278, 45102, 63949, 14576, 25369, 46664, 54825, 42831,
        55720, 197075, 16186, 174, 3356, 1299, 2914, 6939, 6461, 9009, 44477, 48693, 208091,
        212238,
    ]
    .into_iter()
    .collect()
}

/// Classifies network type from ASN name and number.
pub fn classify_network_type(asn: u32, as_name: &str) -> NetworkType {
    let lower = as_name.to_lowercase();

    if known_hosting_asns().contains(&asn) {
        return NetworkType::Hosting;
    }

    let hosting_kws = [
        "hosting",
        "cloud",
        "datacenter",
        "server",
        "dedicated",
        "virtual",
        "vps",
        "amazon",
        "google",
        "microsoft",
        "azure",
        "digitalocean",
        "linode",
        "vultr",
        "hetzner",
        "ovh",
        "cloudflare",
        "akamai",
        "fastly",
    ];
    for kw in &hosting_kws {
        if lower.contains(kw) {
            return NetworkType::Hosting;
        }
    }

    let vpn_kws = [
        "vpn",
        "proxy",
        "tor",
        "socks",
        "tunnel",
        "wireguard",
        "openvpn",
        "nordvpn",
        "expressvpn",
        "surfshark",
        "proton",
        "mullvad",
    ];
    for kw in &vpn_kws {
        if lower.contains(kw) {
            return NetworkType::VPN;
        }
    }

    let mobile_kws = [
        "mobile", "cellular", "wireless", "lte", "5g", "4g", "vodafone", "t-mobile", "at&t",
        "verizon",
    ];
    for kw in &mobile_kws {
        if lower.contains(kw) {
            return NetworkType::Mobile;
        }
    }

    NetworkType::Residential
}

/// Computes risk score (0-100, lower = riskier).
pub fn compute_risk_score(
    _network_type: NetworkType,
    is_tor: bool,
    is_vpn: bool,
    abuse_score: Option<u32>,
    abuse_reports: u32,
) -> (u32, Vec<String>) {
    let mut score = 100u32;
    let mut factors = Vec::new();

    if is_tor {
        score = score.saturating_sub(40);
        factors.push("Tor exit node".to_string());
    }
    if is_vpn {
        score = score.saturating_sub(15);
        factors.push("VPN/Proxy".to_string());
    }
    if let Some(abuse) = abuse_score {
        if abuse > 75 {
            score = score.saturating_sub(30);
            factors.push(format!("High abuse score: {}", abuse));
        } else if abuse > 50 {
            score = score.saturating_sub(15);
            factors.push(format!("Medium abuse score: {}", abuse));
        }
    }
    if abuse_reports > 100 {
        score = score.saturating_sub(20);
        factors.push(format!("Many abuse reports: {}", abuse_reports));
    }

    (score, factors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_hosting() {
        assert_eq!(
            classify_network_type(14061, "DIGITALOCEAN"),
            NetworkType::Hosting
        );
    }

    #[test]
    fn test_classify_vpn() {
        assert_eq!(
            classify_network_type(0, "NordVPN Services"),
            NetworkType::VPN
        );
    }

    #[test]
    fn test_risk_score_clean() {
        let (score, factors) = compute_risk_score(NetworkType::Residential, false, false, None, 0);
        assert_eq!(score, 100);
        assert!(factors.is_empty());
    }

    #[test]
    fn test_risk_score_tor() {
        let (score, _) = compute_risk_score(NetworkType::Hosting, true, true, Some(80), 150);
        assert!(score < 50);
    }
}
