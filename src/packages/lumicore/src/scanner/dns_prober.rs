//! 6-Stage DNS Resolver Capability Assessor & Transparent Proxy Detector.
//!
//! Evaluates recursive resolvers for DNS tunneling viability through:
//! 1. Transparent DNS proxy detection via RFC 5737 TEST-NET IPs.
//! 2. NS record query and NS host recursion resolution.
//! 3. TXT query capability for tunnel data egress.
//! 4. Random subdomain resolution (testing wildcard/delegation handling).
//! 5. Tunnel realism: high-entropy Base32 encoded 57-char label queries.
//! 6. EDNS0 payload size probing (512, 900, 1232 bytes).
//! 7. NXDOMAIN correctness verification (filtering DNS hijackers/forgers).

use std::net::Ipv4Addr;

/// RFC 5737 TEST-NET IPs used to detect transparent DNS proxies.
/// Since these documentation IPs are unroutable on the public internet,
/// any DNS response from them indicates on-path middlebox/ISP interception.
pub const TRANSPARENT_PROXY_TEST_IPS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(192, 0, 2, 1),    // TEST-NET-1
    Ipv4Addr::new(198, 51, 100, 1), // TEST-NET-2
    Ipv4Addr::new(203, 0, 113, 1),  // TEST-NET-3
];

/// Default qualification threshold for DNS tunneling.
pub const DEFAULT_TUNNEL_SCORE_THRESHOLD: u8 = 2;

/// Results of the 6 DNS tunneling capability stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TunnelTestResult {
    pub ns_support: bool,
    pub txt_support: bool,
    pub random_sub: bool,
    pub tunnel_realism: bool,
    pub edns0_support: bool,
    pub edns_max_payload: u16,
    pub nxdomain_correct: bool,
}

impl TunnelTestResult {
    /// Computes the compatibility score (0 to 6).
    pub fn score(&self) -> u8 {
        let mut count = 0;
        if self.ns_support { count += 1; }
        if self.txt_support { count += 1; }
        if self.random_sub { count += 1; }
        if self.tunnel_realism { count += 1; }
        if self.edns0_support { count += 1; }
        if self.nxdomain_correct { count += 1; }
        count
    }

    /// Whether this resolver meets the score threshold for tunneling.
    pub fn is_qualified(&self, threshold: u8) -> bool {
        self.score() >= threshold
    }

    /// Fully compatible resolver passing all 6 capability stages.
    pub fn is_stable(&self) -> bool {
        self.score() == 6
    }
}

/// Evaluates whether an on-path transparent proxy is intercepting UDP DNS.
/// Returns true if any response is received for the RFC 5737 test IPs.
pub fn is_transparent_proxy_detected<F>(mut probe_fn: F) -> bool
where
    F: FnMut(Ipv4Addr) -> bool,
{
    for ip in TRANSPARENT_PROXY_TEST_IPS {
        if probe_fn(ip) {
            return true;
        }
    }
    false
}

/// Encodes raw payload bytes into Base32 (RFC 4648 without padding, lowercase)
/// and splits into 57-byte DNS label segments for tunnel realism testing.
pub fn format_tunnel_realism_qname(payload: &[u8], base_domain: &str) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut b32 = String::new();
    let mut buffer = 0u64;
    let mut bits = 0;

    for &byte in payload {
        buffer = (buffer << 8) | (byte as u64);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1F) as usize;
            b32.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        b32.push(ALPHABET[idx] as char);
    }

    // Chunk into 57-char DNS labels
    let mut labels = Vec::new();
    let mut chars = b32.as_str();
    while !chars.is_empty() {
        let take = chars.len().min(57);
        labels.push(&chars[..take]);
        chars = &chars[take..];
    }

    let joined_labels = labels.join(".");
    let domain = base_domain.trim_matches('.');
    if domain.is_empty() {
        joined_labels
    } else {
        format!("{}.{}", joined_labels, domain)
    }
}

/// Validates NXDOMAIN responses: at least 2 out of 3 invalid domain queries
/// must return NXDOMAIN (RCODE = 3) to ensure the resolver is not hijacking queries.
pub fn verify_nxdomain_ratio(nxdomain_count: usize, total_queries: usize) -> bool {
    if total_queries == 0 {
        return false;
    }
    nxdomain_count * 3 >= total_queries * 2 // >= 66.6%
}
