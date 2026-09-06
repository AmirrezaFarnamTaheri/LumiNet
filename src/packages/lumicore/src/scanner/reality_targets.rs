// SPDX-License-Identifier: MIT
// C5.3a — REALITY Target Scanner: clean-room implementation of the
// RealiTLScanner scoring heuristic for selecting REALITY-compatible
// destination servers.
//
// REALITY is a TLS-based fronting protocol (used by Xray-core) that disguises
// VPN traffic as ordinary TLS connections to a target website. The target
// website must:
//   1. Support TLS 1.3.
//   2. Have a recently issued (renewed) certificate.
//   3. Be hosted on a server with sufficient hardware to handle proxying.
//   4. Not be on a known blocklist.
//
// This module provides a RealityTarget structure and a scoring heuristic
// mirroring RealiTLScanner's scoreServer() function.
// MIT License — no RealiTLScanner source code copied.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// RealityTarget represents a candidate REALITY destination server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RealityTarget {
    /// Server hostname.
    pub hostname: String,
    /// Port (typically 443).
    pub port: u16,
    /// Server fingerprint name (e.g. "chrome120", "firefox117", "safari17_2").
    pub fingerprint: String,
    /// TLS SNI to use for connection.
    pub dest: String,
    /// X25519 public key of the server (used for key derivation in REALITY).
    /// In hex format, 32 bytes (64 hex chars).
    pub x25519_pub: String,
    /// Optional short ID (u32) for fallback to a specific REALITY key.
    pub short_id: Option<String>,
    /// Handshake latency in milliseconds (None = not yet probed).
    pub latency_ms: Option<u64>,
    /// TLS version supported (e.g. "1.3"). None = not yet probed.
    pub tls_version: Option<String>,
    /// Whether the certificate is recently issued (within 60 days).
    pub cert_recent: bool,
    /// Days until certificate expiry.
    pub cert_expiry_days: Option<u32>,
    /// Server's country (ISO 3166-1 alpha-2).
    pub country: Option<String>,
    /// Whether the server passes known blocklists.
    pub not_blocked: bool,
    /// The scanner's computed cleanliness score.
    pub score: u32,
    /// Notes about this target (e.g. "fast, high reputation").
    pub notes: String,
}

impl RealityTarget {
    /// Creates a new RealityTarget with default values.
    pub fn new(hostname: &str, port: u16) -> Self {
        let dest = if port == 443 {
            hostname.to_string()
        } else {
            format!("{}:{}", hostname, port)
        };
        Self {
            hostname: hostname.to_string(),
            port,
            fingerprint: "chrome120".to_string(),
            dest,
            x25519_pub: String::new(),
            short_id: None,
            latency_ms: None,
            tls_version: None,
            cert_recent: false,
            cert_expiry_days: None,
            country: None,
            not_blocked: true,
            score: 0,
            notes: String::new(),
        }
    }

    /// Returns the dest string for use as a REALITY `dest` field.
    pub fn dest_string(&self) -> String {
        self.dest.clone()
    }

    /// Returns the SNI server name, falling back to the hostname.
    pub fn sni(&self) -> &str {
        if !self.dest.is_empty() {
            // SNI is the hostname portion of the dest, if any
            self.dest.split(':').next().unwrap_or(&self.hostname)
        } else {
            &self.hostname
        }
    }
}

/// RealityTargetSet is a collection of RealityTarget records with statistics
/// and ordering operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RealityTargetSet {
    pub targets: Vec<RealityTarget>,
    pub last_updated: u64,
}

impl RealityTargetSet {
    /// Creates a new empty RealityTargetSet.
    pub fn new() -> Self {
        Self {
            targets: Vec::new(),
            last_updated: unix_time_secs(),
        }
    }

    /// Adds a target to the set.
    pub fn add(&mut self, target: RealityTarget) {
        // Replace if already present.
        if let Some(existing) = self.targets.iter_mut().find(|t| t.hostname == target.hostname) {
            *existing = target;
        } else {
            self.targets.push(target);
        }
        self.last_updated = unix_time_secs();
    }

    /// Returns the count of targets.
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    /// Returns whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    /// Returns the highest-scored target.
    pub fn best(&self) -> Option<&RealityTarget> {
        self.targets.iter().max_by_key(|t| t.score)
    }

    /// Returns the top N targets by score, descending.
    pub fn top_n(&self, n: usize) -> Vec<&RealityTarget> {
        let mut sorted: Vec<&RealityTarget> = self.targets.iter().collect();
        sorted.sort_by(|a, b| b.score.cmp(&a.score));
        sorted.into_iter().take(n).collect()
    }

    /// Returns the average score.
    pub fn average_score(&self) -> f32 {
        if self.targets.is_empty() {
            return 0.0;
        }
        let sum: u32 = self.targets.iter().map(|t| t.score).sum();
        sum as f32 / self.targets.len() as f32
    }
}

/// ScoreRealityTarget computes a cleanliness score for a target based on its
/// observable properties. The scoring follows the RealiTLScanner heuristic:
///
///   score = (latency_score + cert_score + version_score + geo_score)
///          * (not_blocked ? 1.0 : 0.0)
///   clamped to [0, 100]
///
/// Components:
///   - latency_score: 0-40 (lower latency = higher score)
///   - cert_score: 0-30 (recent cert = higher score)
///   - version_score: 0-20 (TLS 1.3 = full score)
///   - geo_score: 0-10 (CDN countries get full score)
pub fn ScoreRealityTarget(target: &RealityTarget) -> u32 {
    let mut score: f32 = 0.0;

    // Latency component: 0-40 points
    if let Some(latency) = target.latency_ms {
        // 0ms = 40, 1000ms+ = 0
        let latency_score = 40.0 * (1.0 - (latency as f32 / 1000.0).min(1.0));
        score += latency_score;
    } else {
        // No measurement yet: give neutral 20 points
        score += 20.0;
    }

    // Certificate component: 0-30 points
    if target.cert_recent {
        score += 30.0;
    } else if let Some(days) = target.cert_expiry_days {
        // Cert that expires in 60+ days gets partial credit
        if days >= 60 {
            score += 15.0;
        } else if days >= 30 {
            score += 10.0;
        }
    }

    // TLS version component: 0-20 points
    match target.tls_version.as_deref() {
        Some("1.3") | Some("TLS1.3") => score += 20.0,
        Some("1.2") | Some("TLS1.2") => score += 5.0,
        _ => {}
    }

    // Geographic / hosting component: 0-10 points
    match target.country.as_deref() {
        Some("US") | Some("GB") | Some("DE") | Some("JP") | Some("SG") | Some("NL") => {
            score += 10.0;
        }
        Some(_) => score += 5.0,
        None => score += 5.0, // unknown country, neutral
    }

    // Blocklist penalty
    if !target.not_blocked {
        score = 0.0;
    }

    score.clamp(0.0, 100.0) as u32
}

/// ApplyScores computes scores for all targets in the set and updates them in place.
pub fn ApplyScores(set: &mut RealityTargetSet) {
    for target in &mut set.targets {
        target.score = ScoreRealityTarget(target);
    }
}

/// RecommendedTargets filters a RealityTargetSet to only the top N highest-scored
/// targets, with optional filter conditions.
///
/// Filters:
///   - min_score: minimum score to include
///   - require_tls13: only include TLS 1.3-capable targets
///   - exclude_countries: skip targets hosted in these countries
///   - max_latency_ms: skip targets slower than this
pub fn RecommendedTargets(
    set: &RealityTargetSet,
    n: usize,
    min_score: u32,
    require_tls13: bool,
    exclude_countries: &[String],
    max_latency_ms: Option<u64>,
) -> Vec<RealityTarget> {
    let mut result: Vec<RealityTarget> = set
        .targets
        .iter()
        .filter(|t| t.score >= min_score)
        .filter(|t| !require_tls13 || t.tls_version.as_deref() == Some("1.3") || t.tls_version.as_deref() == Some("TLS1.3"))
        .filter(|t| match (&t.country, exclude_countries) {
            (Some(c), ex) => !ex.contains(c),
            (None, _) => true,
        })
        .filter(|t| match (t.latency_ms, max_latency_ms) {
            (Some(l), Some(m)) => l <= m,
            _ => true,
        })
        .cloned()
        .collect();

    result.sort_by(|a, b| b.score.cmp(&a.score));
    result.truncate(n);
    result
}

/// FingerprintSet is a registry of available REALITY fingerprints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintRegistry {
    pub fingerprints: HashMap<String, FingerprintInfo>,
}

/// FingerprintInfo describes a single REALITY fingerprint profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintInfo {
    pub name: String,
    pub browser: String,
    pub version: String,
    pub user_agent: String,
    pub alpn: Vec<String>,
}

impl FingerprintRegistry {
    /// Returns the default fingerprint registry, mirroring uTLS profiles.
    pub fn default_registry() -> Self {
        let mut reg = Self {
            fingerprints: HashMap::new(),
        };
        reg.register(FingerprintInfo {
            name: "chrome120".to_string(),
            browser: "Chrome".to_string(),
            version: "120".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        });
        reg.register(FingerprintInfo {
            name: "firefox117".to_string(),
            browser: "Firefox".to_string(),
            version: "117".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0".to_string(),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        });
        reg.register(FingerprintInfo {
            name: "safari17_2".to_string(),
            browser: "Safari".to_string(),
            version: "17.2".to_string(),
            user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15".to_string(),
            alpn: vec!["h2".to_string()],
        });
        reg
    }

    fn register(&mut self, info: FingerprintInfo) {
        self.fingerprints.insert(info.name.clone(), info);
    }
}

/// Returns the current Unix timestamp in seconds.
fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_target_creation() {
        let target = RealityTarget::new("example.com", 443);
        assert_eq!(target.hostname, "example.com");
        assert_eq!(target.port, 443);
        assert_eq!(target.dest, "example.com");
        assert_eq!(target.fingerprint, "chrome120");
    }

    #[test]
    fn test_reality_target_with_port() {
        let target = RealityTarget::new("example.com", 8443);
        assert_eq!(target.dest, "example.com:8443");
        assert_eq!(target.sni(), "example.com");
    }

    #[test]
    fn test_score_reality_target_clean() {
        let target = RealityTarget {
            hostname: "fast.com".to_string(),
            port: 443,
            fingerprint: "chrome120".to_string(),
            dest: "fast.com:443".to_string(),
            x25519_pub: "ab".repeat(32),
            short_id: None,
            latency_ms: Some(20),
            tls_version: Some("1.3".to_string()),
            cert_recent: true,
            cert_expiry_days: Some(90),
            country: Some("US".to_string()),
            not_blocked: true,
            score: 0,
            notes: "ideal".to_string(),
        };
        let score = ScoreRealityTarget(&target);
        // Expected: 40 (latency) + 30 (cert) + 20 (TLS) + 10 (geo) = 100
        assert!(score >= 90, "expected score >= 90, got {}", score);
    }

    #[test]
    fn test_score_reality_target_blocked() {
        let target = RealityTarget {
            hostname: "blocked.com".to_string(),
            port: 443,
            fingerprint: "chrome120".to_string(),
            dest: "blocked.com:443".to_string(),
            x25519_pub: "ab".repeat(32),
            short_id: None,
            latency_ms: Some(20),
            tls_version: Some("1.3".to_string()),
            cert_recent: true,
            cert_expiry_days: Some(90),
            country: Some("US".to_string()),
            not_blocked: false,
            score: 0,
            notes: String::new(),
        };
        let score = ScoreRealityTarget(&target);
        assert_eq!(score, 0);
    }

    #[test]
    fn test_score_reality_target_slow() {
        let target = RealityTarget {
            hostname: "slow.com".to_string(),
            port: 443,
            fingerprint: "chrome120".to_string(),
            dest: "slow.com:443".to_string(),
            x25519_pub: "ab".repeat(32),
            short_id: None,
            latency_ms: Some(2000),
            tls_version: Some("1.2".to_string()),
            cert_recent: false,
            cert_expiry_days: Some(20),
            country: Some("XX".to_string()),
            not_blocked: true,
            score: 0,
            notes: String::new(),
        };
        let score = ScoreRealityTarget(&target);
        // Expected: 0 (latency) + 0 (cert) + 5 (TLS1.2) + 5 (geo) = 10
        assert!(score <= 20, "expected low score for slow target, got {}", score);
    }

    #[test]
    fn test_reality_target_set_add() {
        let mut set = RealityTargetSet::new();
        let t1 = RealityTarget::new("example.com", 443);
        set.add(t1);
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());

        // Add duplicate (should replace)
        let t2 = RealityTarget {
            hostname: "example.com".to_string(),
            port: 443,
            fingerprint: "firefox117".to_string(),
            dest: "example.com:443".to_string(),
            x25519_pub: String::new(),
            short_id: None,
            latency_ms: Some(50),
            tls_version: Some("1.3".to_string()),
            cert_recent: true,
            cert_expiry_days: Some(60),
            country: Some("US".to_string()),
            not_blocked: true,
            score: 75,
            notes: String::new(),
        };
        set.add(t2);
        assert_eq!(set.len(), 1);
        assert_eq!(set.targets[0].fingerprint, "firefox117");
    }

    #[test]
    fn test_reality_target_set_top_n() {
        let mut set = RealityTargetSet::new();
        for (i, score) in [10u32, 90, 50, 80, 30].iter().enumerate() {
            let mut t = RealityTarget::new(&format!("target{}.com", i), 443);
            t.score = *score;
            set.add(t);
        }
        let top = set.top_n(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].score, 90);
        assert_eq!(top[1].score, 80);
    }

    #[test]
    fn test_recommended_targets_filter() {
        let mut set = RealityTargetSet::new();
        for i in 0..5 {
            let mut t = RealityTarget::new(&format!("target{}.com", i), 443);
            t.score = (i as u32 + 1) * 20; // 20, 40, 60, 80, 100
            t.tls_version = Some(if i % 2 == 0 { "1.3".to_string() } else { "1.2".to_string() });
            t.country = Some(if i == 0 { "RU".to_string() } else { "US".to_string() });
            t.latency_ms = Some((i as u64 + 1) * 100);
            set.add(t);
        }

        let recs = RecommendedTargets(&set, 10, 50, true, &["RU".to_string()], Some(450));
        // Should include targets 2 (TLS 1.3, US, 300ms, score 60),
        // 3 (TLS 1.2, so excluded by require_tls13),
        // 4 (TLS 1.3, US, 500ms excluded by max_latency_ms=450)
        // Result: just target 2
        assert!(recs.len() <= 2);
        for r in &recs {
            assert!(r.score >= 50);
            assert_eq!(r.tls_version.as_deref(), Some("1.3"));
            assert_ne!(r.country.as_deref(), Some("RU"));
        }
    }

    #[test]
    fn test_fingerprint_registry() {
        let reg = FingerprintRegistry::default_registry();
        assert!(reg.fingerprints.contains_key("chrome120"));
        assert!(reg.fingerprints.contains_key("firefox117"));
        assert!(reg.fingerprints.contains_key("safari17_2"));
        let chrome = reg.fingerprints.get("chrome120").unwrap();
        assert_eq!(chrome.browser, "Chrome");
        assert!(chrome.user_agent.contains("Chrome"));
    }
}
