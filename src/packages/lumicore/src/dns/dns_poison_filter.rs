//! # DNS Poison Filter and Clean Resolver Vault
//!
//! Provides wire-level RFC 1035 DNS A-record probing, Iranian & intranet censorship
//! redirection detection (e.g. 10.10.34.*, RFC 1918, loopback, CGNAT), automated
//! DNS rescue scanning, a persistent clean DNS resolver vault, and hybrid chained
//! tunnel configurations.
//!
//! Originates from RedCloud Windows core and adapted for LumiNet's unified network plane.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

/// Well-known poisoned IP addresses and redirection ranges in hostile censorship environments.
pub const IRAN_FILTER_REDIRECT_PREFIX: (u8, u8, u8) = (10, 10, 34);

/// Configuration for probing a DNS server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProbeConfig {
    pub dns_server: SocketAddr,
    pub test_domain: String,
    pub timeout: Duration,
    pub strict_poison_checks: bool,
}

impl Default for DnsProbeConfig {
    fn default() -> Self {
        Self {
            dns_server: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            test_domain: "google.com".to_string(),
            timeout: Duration::from_millis(2000),
            strict_poison_checks: true,
        }
    }
}

/// Result of probing a DNS server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsProbeResult {
    pub server_ip: IpAddr,
    pub latency_ms: u64,
    pub resolved_ips: Vec<Ipv4Addr>,
    pub is_poisoned: bool,
    pub poison_reason: Option<String>,
    pub success: bool,
}

/// Detects if an IPv4 address belongs to a poisoned or bogus redirection range.
pub fn is_poisoned_ipv4(ip: Ipv4Addr) -> Option<&'static str> {
    let octets = ip.octets();

    // Iranian national filtering redirect page: 10.10.34.*
    if octets[0] == 10 && octets[1] == 10 && octets[2] == 34 {
        return Some("Iranian Censorship Redirect Page (10.10.34.0/24)");
    }

    // RFC 1918 Class A: 10.0.0.0/8
    if octets[0] == 10 {
        return Some("Bogus Private RFC 1918 Class A (10.0.0.0/8)");
    }

    // Loopback: 127.0.0.0/8
    if octets[0] == 127 {
        return Some("Bogus Loopback Address (127.0.0.0/8)");
    }

    // Current network / zero: 0.0.0.0/8
    if octets[0] == 0 {
        return Some("Bogus Unspecified Address (0.0.0.0/8)");
    }

    // RFC 1918 Class C: 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return Some("Bogus Private RFC 1918 Class C (192.168.0.0/16)");
    }

    // RFC 1918 Class B: 172.16.0.0 - 172.31.255.255
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return Some("Bogus Private RFC 1918 Class B (172.16.0.0/12)");
    }

    // CGNAT / Shared Address Space: 100.64.0.0/10 (100.64.0.0 to 100.127.255.255)
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return Some("Bogus CGNAT RFC 6598 (100.64.0.0/10)");
    }

    // Link-local: 169.254.0.0/16
    if octets[0] == 169 && octets[1] == 254 {
        return Some("Bogus Link-Local RFC 3927 (169.254.0.0/16)");
    }

    // Benchmarking / Bogus: 198.18.0.0/15 (198.18.0.0 to 198.19.255.255)
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return Some("Bogus Benchmarking RFC 2544 (198.18.0.0/15)");
    }

    // Broadcast: 255.255.255.255
    if ip == Ipv4Addr::BROADCAST {
        return Some("Bogus Broadcast Address (255.255.255.255)");
    }

    // Multicast: 224.0.0.0/4 (224.0.0.0 to 239.255.255.255)
    if octets[0] >= 224 && octets[0] <= 239 {
        return Some("Bogus Multicast Address (224.0.0.0/4)");
    }

    None
}

/// Builds an RFC 1035 A-record DNS query packet for standard UDP port 53.
pub fn build_rfc1035_a_query(domain: &str, tx_id: u16) -> Result<Vec<u8>, String> {
    if domain.is_empty() || domain.len() > 253 {
        return Err("Invalid domain length".to_string());
    }

    let mut packet = Vec::with_capacity(64);

    // Header: 12 bytes
    // Transaction ID: 2 bytes
    packet.extend_from_slice(&tx_id.to_be_bytes());
    // Flags: 0x0100 (Standard query, RD = 1: recursion desired)
    packet.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT: 1 (1 question)
    packet.extend_from_slice(&[0x00, 0x01]);
    // ANCOUNT: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // NSCOUNT: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // ARCOUNT: 0
    packet.extend_from_slice(&[0x00, 0x00]);

    // Question Section: QNAME
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() {
            return Err("Empty label in domain name".to_string());
        }
        if label.len() > 63 {
            return Err(format!("Label too long: {}", label));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    // Null byte terminating QNAME
    packet.push(0x00);

    // QTYPE: A record = 1
    packet.extend_from_slice(&[0x00, 0x01]);
    // QCLASS: IN (Internet) = 1
    packet.extend_from_slice(&[0x00, 0x01]);

    Ok(packet)
}

/// Parses an RFC 1035 DNS response buffer and extracts all IPv4 addresses in Answer section.
pub fn parse_rfc1035_a_response(buf: &[u8], expected_tx_id: Option<u16>) -> Result<Vec<Ipv4Addr>, String> {
    if buf.len() < 12 {
        return Err("DNS packet too short for header".to_string());
    }

    let tx_id = u16::from_be_bytes([buf[0], buf[1]]);
    if let Some(expected) = expected_tx_id {
        if tx_id != expected {
            return Err(format!("Transaction ID mismatch: got {}, expected {}", tx_id, expected));
        }
    }

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = (flags >> 15) & 0x01;
    if qr == 0 {
        return Err("Not a DNS response packet (QR=0)".to_string());
    }

    let rcode = flags & 0x0F;
    if rcode != 0 {
        return Err(format!("DNS error response code: {}", rcode));
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    if ancount == 0 {
        return Ok(Vec::new());
    }

    let mut offset = 12;

    // Skip Question section
    for _ in 0..qdcount {
        offset = skip_dns_name(buf, offset)?;
        if offset + 4 > buf.len() {
            return Err("DNS packet truncated in question section".to_string());
        }
        // Skip QTYPE (2) + QCLASS (2)
        offset += 4;
    }

    let mut results = Vec::with_capacity(ancount);

    // Parse Answer section
    for _ in 0..ancount {
        if offset >= buf.len() {
            break;
        }
        offset = skip_dns_name(buf, offset)?;
        if offset + 10 > buf.len() {
            return Err("DNS packet truncated in answer header".to_string());
        }

        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let _rclass = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        let _ttl = u32::from_be_bytes([buf[offset + 4], buf[offset + 5], buf[offset + 6], buf[offset + 7]]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > buf.len() {
            return Err("DNS packet truncated in RDATA".to_string());
        }

        // TYPE A is 1, RDLENGTH for IPv4 must be 4
        if rtype == 1 && rdlength == 4 {
            let ip = Ipv4Addr::new(
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            );
            results.push(ip);
        }

        offset += rdlength;
    }

    Ok(results)
}

/// Helper to skip a DNS name (handling label lengths and compression pointers).
fn skip_dns_name(buf: &[u8], mut offset: usize) -> Result<usize, String> {
    let mut jumps = 0;
    while offset < buf.len() {
        let len = buf[offset];
        if len == 0 {
            return Ok(offset + 1);
        }
        // Compression pointer (top 2 bits set: 0xC0)
        if (len & 0xC0) == 0xC0 {
            if offset + 2 > buf.len() {
                return Err("Truncated compression pointer".to_string());
            }
            return Ok(offset + 2);
        }
        // Regular label
        let label_len = len as usize;
        offset += 1 + label_len;
        jumps += 1;
        if jumps > 128 {
            return Err("Too many DNS label jumps (possible loop)".to_string());
        }
    }
    Err("Unexpected end of packet while parsing name".to_string())
}

/// Probes a DNS server over UDP port 53, validates responsiveness, and scans for poisoned IPs.
pub async fn verify_dns_resolution(
    server_ip: IpAddr,
    domain: &str,
    timeout_dur: Duration,
) -> DnsProbeResult {
    let target_addr = SocketAddr::new(server_ip, 53);
    let tx_id = rand::random::<u16>();

    let query = match build_rfc1035_a_query(domain, tx_id) {
        Ok(q) => q,
        Err(e) => {
            return DnsProbeResult {
                server_ip,
                latency_ms: 0,
                resolved_ips: Vec::new(),
                is_poisoned: false,
                poison_reason: Some(e),
                success: false,
            };
        }
    };

    let bind_addr = match server_ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };

    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            return DnsProbeResult {
                server_ip,
                latency_ms: 0,
                resolved_ips: Vec::new(),
                is_poisoned: false,
                poison_reason: Some(format!("UDP bind error: {}", e)),
                success: false,
            };
        }
    };

    let start = Instant::now();
    let send_res = socket.send_to(&query, target_addr).await;
    if let Err(e) = send_res {
        return DnsProbeResult {
            server_ip,
            latency_ms: 0,
            resolved_ips: Vec::new(),
            is_poisoned: false,
            poison_reason: Some(format!("UDP send error: {}", e)),
            success: false,
        };
    }

    let mut buf = [0u8; 1024];
    let recv_res = tokio::time::timeout(timeout_dur, socket.recv_from(&mut buf)).await;

    let latency_ms = start.elapsed().as_millis() as u64;

    match recv_res {
        Ok(Ok((len, _from))) => {
            if len < 32 {
                return DnsProbeResult {
                    server_ip,
                    latency_ms,
                    resolved_ips: Vec::new(),
                    is_poisoned: true,
                    poison_reason: Some(format!("Response too short ({} bytes)", len)),
                    success: false,
                };
            }

            match parse_rfc1035_a_response(&buf[..len], Some(tx_id)) {
                Ok(ips) => {
                    if ips.is_empty() {
                        return DnsProbeResult {
                            server_ip,
                            latency_ms,
                            resolved_ips: ips,
                            is_poisoned: false,
                            poison_reason: Some("No A records in answer".to_string()),
                            success: true,
                        };
                    }

                    // Check for poisoning in any returned IP
                    for &ip in &ips {
                        if let Some(reason) = is_poisoned_ipv4(ip) {
                            return DnsProbeResult {
                                server_ip,
                                latency_ms,
                                resolved_ips: ips,
                                is_poisoned: true,
                                poison_reason: Some(format!("Poisoned IP {}: {}", ip, reason)),
                                success: false,
                            };
                        }
                    }

                    DnsProbeResult {
                        server_ip,
                        latency_ms,
                        resolved_ips: ips,
                        is_poisoned: false,
                        poison_reason: None,
                        success: true,
                    }
                }
                Err(e) => DnsProbeResult {
                    server_ip,
                    latency_ms,
                    resolved_ips: Vec::new(),
                    is_poisoned: true,
                    poison_reason: Some(format!("Parse error / spoofed packet: {}", e)),
                    success: false,
                },
            }
        }
        Ok(Err(e)) => DnsProbeResult {
            server_ip,
            latency_ms,
            resolved_ips: Vec::new(),
            is_poisoned: false,
            poison_reason: Some(format!("UDP recv error: {}", e)),
            success: false,
        },
        Err(_) => DnsProbeResult {
            server_ip,
            latency_ms,
            resolved_ips: Vec::new(),
            is_poisoned: false,
            poison_reason: Some("Query timed out".to_string()),
            success: false,
        },
    }
}

/// A verified record inside the clean DNS vault.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifiedDnsRecord {
    pub ip: IpAddr,
    pub latency_ms: u64,
    pub verified_at: u64,
    pub provider_label: String,
    pub consecutive_successes: u32,
    pub is_clean: bool,
}

/// Persistent in-memory and disk-serializable storage for verified clean DNS resolvers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsVaultStore {
    pub records: HashMap<String, VerifiedDnsRecord>,
}

impl DnsVaultStore {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    /// Records or updates a verification attempt for a DNS resolver.
    pub fn update_record(&mut self, ip: IpAddr, latency_ms: u64, is_clean: bool, label: &str) {
        let key = ip.to_string();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(rec) = self.records.get_mut(&key) {
            rec.latency_ms = latency_ms;
            rec.verified_at = now;
            rec.is_clean = is_clean;
            if is_clean {
                rec.consecutive_successes += 1;
            } else {
                rec.consecutive_successes = 0;
            }
            if !label.is_empty() {
                rec.provider_label = label.to_string();
            }
        } else {
            self.records.insert(
                key,
                VerifiedDnsRecord {
                    ip,
                    latency_ms,
                    verified_at: now,
                    provider_label: label.to_string(),
                    consecutive_successes: if is_clean { 1 } else { 0 },
                    is_clean,
                },
            );
        }
    }

    /// Retrieves all clean resolvers sorted by latency ascending.
    pub fn rank_clean_dns(&self) -> Vec<VerifiedDnsRecord> {
        let mut clean: Vec<VerifiedDnsRecord> = self
            .records
            .values()
            .filter(|r| r.is_clean && r.consecutive_successes > 0)
            .cloned()
            .collect();

        clean.sort_by_key(|r| r.latency_ms);
        clean
    }

    /// Returns the fastest clean DNS resolver, if available.
    pub fn get_fastest_clean(&self) -> Option<VerifiedDnsRecord> {
        self.rank_clean_dns().into_iter().next()
    }

    /// Serializes vault to a JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes vault from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}

/// Runs an automated rescue scan across candidate DNS addresses to find unpoisoned servers.
pub async fn run_dns_rescue_scan(
    candidates: &[IpAddr],
    domain: &str,
    timeout_dur: Duration,
) -> Vec<DnsProbeResult> {
    let mut tasks = Vec::with_capacity(candidates.len());

    for &server in candidates {
        let dom = domain.to_string();
        tasks.push(tokio::spawn(async move {
            verify_dns_resolution(server, &dom, timeout_dur).await
        }));
    }

    let mut results = Vec::with_capacity(candidates.len());
    for task in tasks {
        if let Ok(res) = task.await {
            results.push(res);
        }
    }

    results
}

/// Configuration for hybrid chained tunnel orchestration (e.g. MASQUE/Aether -> Downstream Node).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridChainedTunnelConfig {
    pub local_bridge_port: u16,
    pub local_bridge_protocol: String,
    pub upstream_core_type: String,
    pub downstream_node_tag: String,
    pub upstream_listen_host: String,
}

impl Default for HybridChainedTunnelConfig {
    fn default() -> Self {
        Self {
            local_bridge_port: 1819,
            local_bridge_protocol: "socks5".to_string(),
            upstream_core_type: "masque_bridge".to_string(),
            downstream_node_tag: "proxy_main".to_string(),
            upstream_listen_host: "127.0.0.1".to_string(),
        }
    }
}

impl HybridChainedTunnelConfig {
    /// Compiles an outbound chaining JSON structure linking downstream proxy via upstream loopback bridge.
    pub fn generate_chained_dialer_config(&self) -> serde_json::Value {
        serde_json::json!({
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed_in",
                    "listen": "127.0.0.1",
                    "listen_port": 2080
                }
            ],
            "outbounds": [
                {
                    "type": self.local_bridge_protocol,
                    "tag": "hybrid_upstream_bridge",
                    "server": self.upstream_listen_host,
                    "server_port": self.local_bridge_port
                },
                {
                    "type": "selector",
                    "tag": "proxy",
                    "outbounds": [self.downstream_node_tag.clone(), "direct"]
                },
                {
                    "type": "direct",
                    "tag": "direct"
                }
            ],
            "chain_metadata": {
                "upstream_core": self.upstream_core_type,
                "dialer_proxy_tag": "hybrid_upstream_bridge",
                "target_node": self.downstream_node_tag
            }
        })
    }
}
