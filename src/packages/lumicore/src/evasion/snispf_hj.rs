//! # SNISPF-HJ — Multi-IP/SNI Pool, Cloudflare Subnet Scanner, and Node Drainage
//!
//! - Dynamic combinations of CONNECT_IPS and FAKE_SNIS from JSON config
//! - Parallel Cloudflare subnet scanning and reachability validation
//! - Active pool management with node drainage on high packet-loss detection

use std::collections::HashMap;
use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Official Cloudflare IPv4 CIDR ranges (source: cloudflare.com/ips-v4).
/// These rarely change; update when Cloudflare publishes new allocations.
pub const CLOUDFLARE_CIDRS: &[&str] = &[
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
];

/// Configuration for the SNISPF-HJ pool engine.
#[derive(Debug, Clone)]
pub struct SnispfHjConfig {
    pub listen_host: String,
    pub listen_port: u16,
    pub connect_port: u16,
    pub bypass_method: String,
    pub fragment_strategy: String,
    pub fragment_delay_ms: u64,
    pub use_ttl_trick: bool,
    pub fake_sni_method: String,
    pub active_slots: usize,
    pub health_check_interval_s: u64,
    pub health_check_timeout_s: u64,
    pub probe_count: usize,
    pub loss_threshold: f64,
    pub dead_threshold: f64,
    pub drain_timeout_s: u64,
    pub max_draining: usize,
    pub evict_every: usize,
    pub evict_count: usize,
    pub dynamic_ip_discovery: bool,
    pub discovery_batch: usize,
    pub discovery_interval_s: u64,
    pub discovery_probe_tries: usize,
    pub discovery_timeout_s: u64,
    pub discovery_min_success: f64,
    pub discovery_max_ips: usize,
    pub connect_ips: Vec<String>,
    pub fake_snis: Vec<String>,
}

impl Default for SnispfHjConfig {
    fn default() -> Self {
        Self {
            listen_host: "0.0.0.0".to_string(),
            listen_port: 40443,
            connect_port: 443,
            bypass_method: "combined".to_string(),
            fragment_strategy: "sni_split".to_string(),
            fragment_delay_ms: 100,
            use_ttl_trick: false,
            fake_sni_method: "prefix_fake".to_string(),
            active_slots: 3,
            health_check_interval_s: 30,
            health_check_timeout_s: 3,
            probe_count: 5,
            loss_threshold: 0.20,
            dead_threshold: 0.80,
            drain_timeout_s: 30,
            max_draining: 5,
            evict_every: 3,
            evict_count: 5,
            dynamic_ip_discovery: true,
            discovery_batch: 100,
            discovery_interval_s: 120,
            discovery_probe_tries: 3,
            discovery_timeout_s: 2,
            discovery_min_success: 0.50,
            discovery_max_ips: 200,
            connect_ips: vec![
                "172.66.41.252".to_string(),
                "108.162.196.145".to_string(),
                "172.65.13.230".to_string(),
                "104.24.92.151".to_string(),
                "104.24.130.92".to_string(),
            ],
            fake_snis: vec![
                "apple.com".to_string(),
                "github.com".to_string(),
                "google.com".to_string(),
                "microsoft.com".to_string(),
                "cloudflare.com".to_string(),
                "wikipedia.org".to_string(),
                "rust-lang.org".to_string(),
            ],
        }
    }
}

/// Statistics for a (IP, SNI) pair in the active pool.
#[derive(Debug, Clone, Default)]
pub struct PairStats {
    pub probe_sent: u64,
    pub probe_success: u64,
    pub latency_ms: u64,
    pub is_draining: bool,
    pub last_probe: Option<Instant>,
}

impl PairStats {
    /// Returns the packet loss ratio (0.0 = no loss, 1.0 = all lost).
    pub fn loss_ratio(&self) -> f64 {
        if self.probe_sent == 0 {
            return 0.0;
        }
        1.0 - (self.probe_success as f64 / self.probe_sent as f64)
    }

    /// Returns true if this pair is considered unhealthy based on loss threshold.
    pub fn is_unhealthy(&self, threshold: f64) -> bool {
        self.probe_sent >= 3 && self.loss_ratio() > threshold
    }

    /// Returns true if this pair should be declared dead.
    pub fn is_dead(&self, dead_threshold: f64) -> bool {
        self.probe_sent >= 3 && self.loss_ratio() >= dead_threshold
    }
}

/// A (connect_ip, fake_sni) combination pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpSniPair {
    pub ip: String,
    pub sni: String,
}

impl IpSniPair {
    pub fn new(ip: impl Into<String>, sni: impl Into<String>) -> Self {
        Self {
            ip: ip.into(),
            sni: sni.into(),
        }
    }
}

/// Generates all combinations of connect_ips × fake_snis.
pub fn generate_all_combinations(ips: &[String], snis: &[String]) -> Vec<IpSniPair> {
    let mut pairs = Vec::with_capacity(ips.len() * snis.len());
    for ip in ips {
        for sni in snis {
            pairs.push(IpSniPair::new(ip.clone(), sni.clone()));
        }
    }
    pairs
}

/// Active pool manager for IP-SNI pairs with health checking and drainage.
pub struct ActivePool {
    config: SnispfHjConfig,
    active: Arc<Mutex<Vec<IpSniPair>>>,
    stats: Arc<Mutex<HashMap<IpSniPair, PairStats>>>,
}

impl ActivePool {
    /// Creates a new ActivePool initialized from the given config.
    pub fn new(config: SnispfHjConfig) -> Self {
        let all_pairs = generate_all_combinations(&config.connect_ips, &config.fake_snis);
        let active_count = config.active_slots.min(all_pairs.len());
        let active: Vec<IpSniPair> = all_pairs[..active_count].to_vec();
        let mut stats_map = HashMap::new();
        for pair in &all_pairs {
            stats_map.insert(pair.clone(), PairStats::default());
        }
        Self {
            config,
            active: Arc::new(Mutex::new(active)),
            stats: Arc::new(Mutex::new(stats_map)),
        }
    }

    /// Returns the current list of active (IP, SNI) pairs.
    pub fn get_active_pairs(&self) -> Vec<IpSniPair> {
        self.active.lock().unwrap().clone()
    }

    /// Records a probe result for a given pair.
    pub fn record_probe(&self, pair: &IpSniPair, success: bool, latency_ms: u64) {
        let mut stats = self.stats.lock().unwrap();
        let entry = stats.entry(pair.clone()).or_default();
        entry.probe_sent += 1;
        if success {
            entry.probe_success += 1;
        }
        entry.latency_ms = latency_ms;
        entry.last_probe = Some(Instant::now());
    }

    /// Drains unhealthy pairs from the active pool, replacing with candidates from reserves.
    pub fn drain_unhealthy(&self, all_candidates: &[IpSniPair]) {
        let stats = self.stats.lock().unwrap();
        let mut active = self.active.lock().unwrap();

        let mut draining_count = 0;
        let mut healthy: Vec<IpSniPair> = Vec::new();
        let mut to_drain: Vec<IpSniPair> = Vec::new();

        for pair in active.iter() {
            if let Some(s) = stats.get(pair) {
                if s.is_dead(self.config.dead_threshold)
                    && draining_count < self.config.max_draining
                {
                    to_drain.push(pair.clone());
                    draining_count += 1;
                } else {
                    healthy.push(pair.clone());
                }
            } else {
                healthy.push(pair.clone());
            }
        }

        // Replace drained slots with fresh candidates not in active set
        let active_set: std::collections::HashSet<IpSniPair> = healthy.iter().cloned().collect();
        let replacements: Vec<IpSniPair> = all_candidates
            .iter()
            .filter(|p| !active_set.contains(p) && !to_drain.contains(p))
            .take(to_drain.len())
            .cloned()
            .collect();

        *active = healthy;
        active.extend(replacements);
    }
}

/// Probes a single IP:port via TCP connect to measure reachability.
///
/// Returns Some(latency_ms) on success, None on failure.
pub fn probe_tcp(ip: &str, port: u16, timeout: Duration) -> Option<u64> {
    let addr = format!("{}:{}", ip, port);
    let start = Instant::now();
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(socket_addr) = addrs.next() {
            if TcpStream::connect_timeout(&socket_addr, timeout).is_ok() {
                return Some(start.elapsed().as_millis() as u64);
            }
        }
    }
    None
}

/// Probes a single IP:port via HTTP GET request to verify application-layer connectivity and latency.
///
/// Returns Some(latency_ms) on success, None on failure.
pub fn probe_http(ip: &str, port: u16, host: &str, path: &str, timeout: Duration) -> Option<u64> {
    let addr = format!("{}:{}", ip, port);
    let start = Instant::now();
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(socket_addr) = addrs.next() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&socket_addr, timeout) {
                let _ = stream.set_write_timeout(Some(timeout));
                let _ = stream.set_read_timeout(Some(timeout));

                use std::io::{Read, Write};
                let req = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: LumiNet/1.0\r\nConnection: close\r\n\r\n",
                    path, host
                );

                if stream.write_all(req.as_bytes()).is_err() {
                    return None;
                }
                if stream.flush().is_err() {
                    return None;
                }

                let mut buf = [0u8; 16];
                if let Ok(bytes_read) = stream.read(&mut buf) {
                    if bytes_read >= 12 && buf.starts_with(b"HTTP/1.") {
                        return Some(start.elapsed().as_millis() as u64);
                    }
                }
            }
        }
    }
    None
}

/// Probes a single IP:port via TLS connection stability check (idle-hold check) to detect DPI resets.
///
/// Returns true if the connection survived the idle hold period.
pub fn probe_stability(ip: &str, port: u16, sni: &str, timeout: Duration, hold: Duration) -> bool {
    let addr = format!("{}:{}", ip, port);
    let socket_addr = match addr.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(sa) => sa,
        None => return false,
    };

    let mut stream = match TcpStream::connect_timeout(&socket_addr, timeout) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let _ = stream.set_write_timeout(Some(timeout));
    let _ = stream.set_read_timeout(Some(timeout));

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let server_name = match rustls_pki_types::ServerName::try_from(sni.to_string()) {
        Ok(name) => name.to_owned(),
        Err(_) => return false,
    };

    let mut conn = match rustls::ClientConnection::new(config, server_name) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);

    // Attempt raw write to complete handshake
    use std::io::{Read, Write};
    if tls_stream.write_all(b"GET / HTTP/1.1\r\n\r\n").is_err() {
        return false;
    }
    let _ = tls_stream.flush();

    // Idle hold
    std::thread::sleep(hold);

    // Verify socket is still readable/alive without errors
    let mut buf = [0u8; 1];
    if let Ok(raw_stream) = tls_stream.sock.try_clone() {
        let _ = raw_stream.set_read_timeout(Some(Duration::from_millis(50)));
    }
    read_indicates_alive(tls_stream.read(&mut buf))
}

fn read_indicates_alive(result: std::io::Result<usize>) -> bool {
    match result {
        Ok(0) => false,
        Ok(_) => true,
        Err(e) => {
            e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut
        }
    }
}

/// Probes a single IP:port via WebSocket upgrade handshake to verify GFW DPI bypass.
///
/// Returns true if a valid HTTP upgrade response was received.
pub fn probe_websocket(
    ip: &str,
    port: u16,
    sni: &str,
    host: &str,
    path: &str,
    timeout: Duration,
) -> bool {
    let addr = format!("{}:{}", ip, port);
    let socket_addr = match addr.to_socket_addrs().ok().and_then(|mut a| a.next()) {
        Some(sa) => sa,
        None => return false,
    };

    let mut stream = match TcpStream::connect_timeout(&socket_addr, timeout) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let _ = stream.set_write_timeout(Some(timeout));
    let _ = stream.set_read_timeout(Some(timeout));

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let server_name = match rustls_pki_types::ServerName::try_from(sni.to_string()) {
        Ok(name) => name.to_owned(),
        Err(_) => return false,
    };

    let mut conn = match rustls::ClientConnection::new(config, server_name) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);

    let ws_host = if host.is_empty() { sni } else { host };
    let ws_req = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        path, ws_host
    );

    use std::io::{Read, Write};
    if tls_stream.write_all(ws_req.as_bytes()).is_err() {
        return false;
    }
    let _ = tls_stream.flush();

    let mut buf = [0u8; 128];
    if let Ok(bytes_read) = tls_stream.read(&mut buf) {
        if bytes_read >= 12 {
            let res = String::from_utf8_lossy(&buf[..bytes_read]);
            return res.contains("HTTP/");
        }
    }
    false
}

/// Generates a batch of random IPv4 addresses from a CIDR range.
///
/// The CIDR is parsed to its network/mask, and `count` addresses are sampled
/// uniformly within the usable host range. This mirrors the Python ip_discovery.py logic.
pub fn sample_cidr_ips(cidr: &str, count: usize) -> Vec<Ipv4Addr> {
    let parts: Vec<&str> = cidr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return vec![];
    }
    let base_ip: Ipv4Addr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return vec![],
    };
    let prefix_len: u32 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return vec![],
    };
    if prefix_len > 32 {
        return vec![];
    }
    let host_bits = 32 - prefix_len;
    let host_count = if host_bits >= 32 {
        u32::MAX
    } else {
        (1u32 << host_bits).saturating_sub(2)
    };
    if host_count == 0 {
        return vec![];
    }

    let base_u32 = u32::from(base_ip);
    let mask = if prefix_len == 0 {
        0
    } else {
        !(0xFFFF_FFFFu32 >> prefix_len)
    };
    let network = base_u32 & mask;

    let actual_count = count.min(host_count as usize);
    let mut result = Vec::with_capacity(actual_count);

    // Simple deterministic sampling spread across the range
    let step = if actual_count > 1 {
        host_count as usize / actual_count
    } else {
        1
    };
    for i in 0..actual_count {
        let host_index = 1 + (i * step) as u32;
        let ip_u32 = network | (host_index & !mask);
        result.push(Ipv4Addr::from(ip_u32));
    }
    result
}

/// Scans a batch of IPs from Cloudflare CIDRs in parallel, returning reachable IPs.
///
/// `batch_size` controls how many IPs are sampled per CIDR, and `timeout` is the
/// per-probe TCP connect timeout. Success threshold (`min_success_ratio`) determines
/// how many successful probes (out of `probe_tries`) are required per IP.
pub fn scan_cloudflare_ips(
    port: u16,
    batch_size: usize,
    probe_tries: usize,
    timeout: Duration,
    min_success_ratio: f64,
    max_results: usize,
) -> Vec<String> {
    let mut results = Vec::new();
    let per_cidr = (batch_size / CLOUDFLARE_CIDRS.len()).max(1);

    for cidr in CLOUDFLARE_CIDRS {
        if results.len() >= max_results {
            break;
        }
        let ips = sample_cidr_ips(cidr, per_cidr);
        for ip in ips {
            if results.len() >= max_results {
                break;
            }
            let ip_str = ip.to_string();
            let mut successes = 0usize;
            for _ in 0..probe_tries {
                if probe_tcp(&ip_str, port, timeout).is_some() {
                    successes += 1;
                }
            }
            let ratio = successes as f64 / probe_tries as f64;
            if ratio >= min_success_ratio {
                results.push(ip_str);
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    // rustls 0.23 needs an explicit process-level CryptoProvider when both
    // the "ring" and "aws-lc-rs" features are enabled by the dependency
    // graph. Install the ring provider once so probe tests (which build
    // live ClientConnections) can construct TLS sessions.
    fn ensure_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn test_generate_all_combinations() {
        let ips = vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()];
        let snis = vec![
            "a.com".to_string(),
            "b.com".to_string(),
            "c.com".to_string(),
        ];
        let pairs = generate_all_combinations(&ips, &snis);
        assert_eq!(pairs.len(), 6);
        assert_eq!(pairs[0], IpSniPair::new("1.1.1.1", "a.com"));
        assert_eq!(pairs[5], IpSniPair::new("2.2.2.2", "c.com"));
    }

    #[test]
    fn test_pair_stats_loss_ratio() {
        let s = PairStats {
            probe_sent: 10,
            probe_success: 8,
            ..Default::default()
        };
        let loss = s.loss_ratio();
        assert!((loss - 0.2).abs() < 1e-9);
    }

    #[test]
    fn read_liveness_distinguishes_eof_from_idle_socket() {
        assert!(!read_indicates_alive(Ok(0)));
        assert!(read_indicates_alive(Ok(1)));
        assert!(read_indicates_alive(Err(std::io::Error::from(
            std::io::ErrorKind::WouldBlock,
        ))));
        assert!(!read_indicates_alive(Err(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset,
        ))));
    }

    #[test]
    fn test_pair_stats_unhealthy() {
        let s = PairStats {
            probe_sent: 5,
            probe_success: 1,
            ..Default::default()
        }; // 80% loss
        assert!(s.is_unhealthy(0.20));
        assert!(s.is_dead(0.80));
    }

    #[test]
    fn test_active_pool_initialization() {
        let cfg = SnispfHjConfig {
            active_slots: 2,
            connect_ips: vec!["1.1.1.1".to_string(), "2.2.2.2".to_string()],
            fake_snis: vec!["a.com".to_string(), "b.com".to_string()],
            ..Default::default()
        };
        let pool = ActivePool::new(cfg);
        let active = pool.get_active_pairs();
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn test_sample_cidr_ips() {
        let ips = sample_cidr_ips("172.64.0.0/13", 5);
        assert_eq!(ips.len(), 5);
        for ip in &ips {
            let octets = ip.octets();
            // All should be in the 172.64.0.0/13 range
            assert_eq!(octets[0], 172);
            assert!(octets[1] >= 64 && octets[1] < 72);
        }
    }

    #[test]
    fn test_sample_cidr_ips_invalid() {
        let ips = sample_cidr_ips("not-a-cidr", 5);
        assert!(ips.is_empty());
    }

    #[test]
    fn test_snispf_default_config() {
        let cfg = SnispfHjConfig::default();
        assert_eq!(cfg.active_slots, 3);
        assert_eq!(cfg.connect_port, 443);
        assert!(!cfg.connect_ips.is_empty());
        assert!(!cfg.fake_snis.is_empty());
    }

    #[test]
    fn test_probe_http() {
        // Test basic execution (may succeed or time out, should not panic)
        let _ = probe_http(
            "1.1.1.1",
            80,
            "one.one.one.one",
            "/",
            Duration::from_millis(300),
        );
    }

    #[test]
    fn test_probe_stability() {
        ensure_provider();
        // Verify execution completes without panicking
        let _ = probe_stability(
            "1.1.1.1",
            443,
            "one.one.one.one",
            Duration::from_millis(300),
            Duration::from_millis(100),
        );
    }

    #[test]
    fn test_probe_websocket() {
        ensure_provider();
        // Verify execution completes without panicking
        let _ = probe_websocket(
            "1.1.1.1",
            443,
            "one.one.one.one",
            "one.one.one.one",
            "/ws",
            Duration::from_millis(300),
        );
    }
}
