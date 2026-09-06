//! # Cancellable Gateway Scanner & RTT Ranker
//!
//! Scans and benchmarks candidate MASQUE / WARP gateway endpoints across Cloudflare
//! dedicated anycast ranges and CDN subnets. Features asynchronous streaming,
//! active atomic cancellation, dynamic quiet window bounding, and RTT ranking.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use thiserror::Error;

pub const MASQUE_CIDRS_V4: &[&str] = &[
    "162.159.197.0/24",
    "162.159.198.0/24",
    "162.159.196.0/24",
    "162.159.195.0/24",
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.204.0/24",
    "172.65.251.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "162.159.36.0/24",
    "162.159.46.0/24",
];

pub const MASQUE_CDN_CIDRS_V4: &[&str] = &[
    "104.16.0.0/16",
    "104.17.0.0/16",
    "104.18.0.0/16",
    "104.19.0.0/16",
    "104.24.0.0/16",
    "104.25.0.0/16",
    "104.26.0.0/16",
    "104.27.0.0/16",
    "172.64.0.0/16",
    "172.66.0.0/16",
    "172.67.0.0/16",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "141.101.64.0/18",
    "190.93.240.0/20",
    "198.41.128.0/17",
];

pub const MASQUE_SEEDS: &[&str] = &[
    "162.159.197.3",
    "162.159.197.1",
    "162.159.198.2",
    "162.159.198.1",
    "162.159.196.1",
    "162.159.195.1",
    "162.159.192.1",
    "162.159.193.1",
];

pub const MASQUE_PORTS: &[u16] = &[443, 500, 1701, 4500, 4443, 8443, 8095];

pub const MASQUE_CIDRS_V6: &[&str] = &[
    "2606:4700:102::/48",
    "2606:4700:d0::/48",
    "2606:4700:d1::/48",
];

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ScannerError {
    #[error("endpoint scan was cancelled")]
    Cancelled,
    #[error("no clean or responsive endpoint discovered")]
    NoCleanEndpoint,
    #[error("timeout waiting for scan candidates")]
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Turbo,
    Balanced,
    Thorough,
    Ironclad,
}

impl ScanMode {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "turbo" => ScanMode::Turbo,
            "thorough" => ScanMode::Thorough,
            "ironclad" => ScanMode::Ironclad,
            _ => ScanMode::Balanced,
        }
    }

    pub fn strategy(self) -> ScanStrategy {
        match self {
            ScanMode::Turbo => ScanStrategy {
                concurrency: 32,
                per_probe_timeout: Duration::from_millis(800),
                overall_deadline: Duration::from_secs(6),
                quiet_after_first: Duration::from_secs(3),
                sample_count: 16,
            },
            ScanMode::Balanced => ScanStrategy {
                concurrency: 48,
                per_probe_timeout: Duration::from_millis(1500),
                overall_deadline: Duration::from_secs(12),
                quiet_after_first: Duration::from_secs(5),
                sample_count: 48,
            },
            ScanMode::Thorough => ScanStrategy {
                concurrency: 64,
                per_probe_timeout: Duration::from_millis(2500),
                overall_deadline: Duration::from_secs(25),
                quiet_after_first: Duration::from_secs(8),
                sample_count: 96,
            },
            ScanMode::Ironclad => ScanStrategy {
                concurrency: 16,
                per_probe_timeout: Duration::from_millis(3000),
                overall_deadline: Duration::from_secs(30),
                quiet_after_first: Duration::from_secs(10),
                sample_count: 32,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanStrategy {
    pub concurrency: usize,
    pub per_probe_timeout: Duration,
    pub overall_deadline: Duration,
    pub quiet_after_first: Duration,
    pub sample_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpScanFilter {
    V4,
    V6,
    DualStack,
}

impl IpScanFilter {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "v6" => IpScanFilter::V6,
            "dual" | "both" => IpScanFilter::DualStack,
            _ => IpScanFilter::V4,
        }
    }

    pub fn allows_v4(self) -> bool {
        matches!(self, IpScanFilter::V4 | IpScanFilter::DualStack)
    }

    pub fn allows_v6(self) -> bool {
        matches!(self, IpScanFilter::V6 | IpScanFilter::DualStack)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayProbeResult {
    pub peer: SocketAddr,
    pub rtt: Duration,
}

/// Generates a spread list of candidate SocketAddrs from seed lists and CIDRs.
pub fn generate_candidates(
    filter: IpScanFilter,
    ports: &[u16],
    sample_limit: usize,
) -> Vec<SocketAddr> {
    let mut v4_addrs = Vec::new();
    let mut v6_addrs = Vec::new();

    // 1. Always prioritize known high-yield seeds
    if filter.allows_v4() {
        for &seed in MASQUE_SEEDS {
            if let Ok(ip) = seed.parse::<IpAddr>() {
                for &port in ports {
                    v4_addrs.push(SocketAddr::new(ip, port));
                }
            }
        }

        // 2. Synthesize candidates from dedicated subnets (e.g. .1, .2, .3, .254)
        for &cidr in MASQUE_CIDRS_V4 {
            if let Some(base) = cidr.split('/').next() {
                if let Ok(v4) = base.parse::<Ipv4Addr>() {
                    let octets = v4.octets();
                    for host in [1u8, 2, 3, 10, 100, 254] {
                        let candidate_ip = IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], host));
                        for &port in &ports[..ports.len().min(3)] {
                            v4_addrs.push(SocketAddr::new(candidate_ip, port));
                        }
                    }
                }
            }
        }
    }

    if filter.allows_v6() {
        for &cidr in MASQUE_CIDRS_V6 {
            if let Some(base) = cidr.split('/').next() {
                if let Ok(v6) = base.parse::<Ipv6Addr>() {
                    let mut segs = v6.segments();
                    segs[7] = 1;
                    let candidate_ip = IpAddr::V6(Ipv6Addr::from(segs));
                    for &port in &ports[..ports.len().min(2)] {
                        v6_addrs.push(SocketAddr::new(candidate_ip, port));
                    }
                }
            }
        }
    }

    let mut addrs = Vec::with_capacity(sample_limit);
    let mut seen = std::collections::HashSet::new();

    if filter == IpScanFilter::DualStack {
        // Interleave V4 and V6 for balanced representation
        let max_len = v4_addrs.len().max(v6_addrs.len());
        for i in 0..max_len {
            if i < v4_addrs.len() && seen.insert(v4_addrs[i]) {
                addrs.push(v4_addrs[i]);
                if addrs.len() >= sample_limit {
                    break;
                }
            }
            if i < v6_addrs.len() && seen.insert(v6_addrs[i]) {
                addrs.push(v6_addrs[i]);
                if addrs.len() >= sample_limit {
                    break;
                }
            }
        }
    } else {
        let pool = if filter.allows_v6() { v6_addrs } else { v4_addrs };
        for addr in pool {
            if seen.insert(addr) {
                addrs.push(addr);
                if addrs.len() >= sample_limit {
                    break;
                }
            }
        }
    }

    addrs
}

/// Scans candidate gateways asynchronously with active cancellation and quiet windowing.
pub async fn scan_gateways_with_canceller<F, Fut>(
    candidates: Vec<SocketAddr>,
    strategy: ScanStrategy,
    limit: usize,
    cancelled: &AtomicBool,
    probe_fn: F,
) -> Result<Vec<GatewayProbeResult>, ScannerError>
where
    F: Fn(SocketAddr, Duration) -> Fut + Sync + Send + 'static,
    Fut: std::future::Future<Output = Option<Duration>> + Send + 'static,
{
    let limit = limit.clamp(1, 64);
    let mut results = Vec::new();
    let deadline = Instant::now() + strategy.overall_deadline;
    let mut quiet_until: Option<Instant> = None;
    let probe_fn = Arc::new(probe_fn);

    for chunk in candidates.chunks(strategy.concurrency) {
        if cancelled.load(Ordering::Relaxed) {
            return Err(ScannerError::Cancelled);
        }

        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if let Some(quiet) = quiet_until {
            if now >= quiet {
                break;
            }
        }

        let mut tasks = Vec::new();
        for &addr in chunk {
            let timeout = strategy.per_probe_timeout;
            let probe = Arc::clone(&probe_fn);
            tasks.push(async move {
                let fut = probe(addr, timeout);
                tokio::time::timeout(timeout, fut).await.ok().flatten().map(|rtt| GatewayProbeResult {
                    peer: addr,
                    rtt,
                })
            });
        }

        let batch_results = futures::future::join_all(tasks).await;

        for res in batch_results.into_iter().flatten() {
            if !results.iter().any(|r: &GatewayProbeResult| r.peer == res.peer) {
                results.push(res);
                results.sort_by_key(|r| r.rtt);

                if quiet_until.is_none() {
                    quiet_until = Some(Instant::now() + strategy.quiet_after_first);
                }

                if results.len() >= limit {
                    break;
                }
            }
        }

        if results.len() >= limit {
            break;
        }
    }

    if cancelled.load(Ordering::Relaxed) {
        return Err(ScannerError::Cancelled);
    }

    if results.is_empty() {
        Err(ScannerError::NoCleanEndpoint)
    } else {
        results.truncate(limit);
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidate_generation() {
        let candidates = generate_candidates(IpScanFilter::V4, MASQUE_PORTS, 50);
        assert!(!candidates.is_empty());
        assert!(candidates.len() <= 50);
        for c in &candidates {
            assert!(c.is_ipv4());
            assert!(MASQUE_PORTS.contains(&c.port()));
        }
    }

    #[tokio::test]
    async fn test_scan_with_cancellation() {
        let cancelled = AtomicBool::new(true);
        let candidates = vec!["1.1.1.1:443".parse().unwrap()];
        let strat = ScanMode::Turbo.strategy();

        let res = scan_gateways_with_canceller(
            candidates,
            strat,
            5,
            &cancelled,
            |_addr, _timeout| async { Some(Duration::from_millis(50)) },
        )
        .await;

        assert_eq!(res.unwrap_err(), ScannerError::Cancelled);
    }

    #[tokio::test]
    async fn test_scan_rtt_ranking() {
        let cancelled = AtomicBool::new(false);
        let candidates = vec![
            "1.1.1.1:443".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
            "9.9.9.9:443".parse().unwrap(),
        ];
        let strat = ScanMode::Turbo.strategy();

        let res = scan_gateways_with_canceller(
            candidates,
            strat,
            3,
            &cancelled,
            |addr, _timeout| async move {
                if addr.ip() == "1.1.1.1".parse::<IpAddr>().unwrap() {
                    Some(Duration::from_millis(150))
                } else if addr.ip() == "8.8.8.8".parse::<IpAddr>().unwrap() {
                    Some(Duration::from_millis(25))
                } else {
                    Some(Duration::from_millis(80))
                }
            },
        )
        .await
        .expect("scan succeeded");

        assert_eq!(res.len(), 3);
        // Should be sorted by lowest RTT: 8.8.8.8 (25ms), 9.9.9.9 (80ms), 1.1.1.1 (150ms)
        assert_eq!(res[0].peer.ip(), "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(res[1].peer.ip(), "9.9.9.9".parse::<IpAddr>().unwrap());
        assert_eq!(res[2].peer.ip(), "1.1.1.1".parse::<IpAddr>().unwrap());
    }
}
