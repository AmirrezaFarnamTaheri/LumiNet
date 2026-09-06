//! # LumiNet Engine
//!
//! Unified entry point orchestrating all ported modules into a cohesive system.
//! This is the main API for the Rust core that the Go server calls via FLI.
//!
//! ## Design Principles
//!
//! - **Single entry point**: All functionality accessible through `LumiNetEngine`
//! - **Preset-driven**: Pre-configured profiles for common use cases
//! - **Configurable**: Every behavior can be customized
//! - **Observable**: All operations produce metrics and logs
//! - **Safe**: All public APIs are safe to call from any thread

use crate::dns::antipoison::DnsCache;
use crate::evasion::{BrowserFingerprint, EvasionEngine};
use crate::netutil::{classify_network_type, is_private_address, is_safe_target, NetworkType};
use crate::obfuscation::protocol_detect;
use crate::proxy::{virtual_dns::VirtualDns, ParseError, ProxyNode};
use crate::security::blocklist::DomainBlocklist;
use crate::security::challenge_solver::{
    detect_cdn_challenge, CdnChallengeType, SessionStore as CdnSessionStore,
};
use crate::security::gov_blocklist;
use std::net::IpAddr;
use std::time::Duration;

// ─── Engine Presets ──────────────────────────────────────────────────────────

/// Pre-configured engine profiles for common use cases.
#[derive(Debug, Clone)]
pub enum EnginePreset {
    /// Default balanced configuration.
    Default,
    /// Maximum stealth - all evasion techniques enabled.
    Stealth,
    /// Performance mode - minimal overhead.
    Performance,
    /// Iran-specific - optimized for Iranian censorship.
    Iran,
    /// China-specific - optimized for GFW bypass.
    China,
    /// Russia-specific - optimized for Russian censorship.
    Russia,
    /// Mobile mode - optimized for cellular networks.
    Mobile,
    /// Debug mode - verbose logging, no evasion.
    Debug,
}

/// Engine configuration with all tunable parameters.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Browser fingerprint to mimic.
    pub fingerprint: BrowserFingerprint,
    /// Enable SNI spoofing.
    pub enable_sni_spoof: bool,
    /// Enable TLS record fragmentation.
    pub enable_tls_fragment: bool,
    /// Enable TCP desync attacks.
    pub enable_desync: bool,
    /// Enable QUIC noise injection.
    pub enable_quic_noise: bool,
    /// Enable HTTP header tricks.
    pub enable_http_tricks: bool,
    /// Enable traffic polymorphism.
    pub enable_polymorphism: bool,
    /// Enable FakeDNS.
    pub enable_fake_dns: bool,
    /// Enable government IP blocking.
    pub enable_gov_block: bool,
    /// Enable domain blocklist.
    pub enable_blocklist: bool,
    /// Enable CDN challenge bypass.
    pub enable_cdn_bypass: bool,
    /// DNS cache size.
    pub dns_cache_size: usize,
    /// DNS cache min TTL.
    pub dns_cache_min_ttl: Duration,
    /// DNS cache max TTL.
    pub dns_cache_max_ttl: Duration,
    /// Virtual DNS pool size.
    pub virtual_dns_pool_size: u32,
    /// Session trust threshold (consecutive successes).
    pub session_trust_threshold: u32,
    /// Max concurrent connections.
    pub max_concurrent: usize,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Desync split position.
    pub desync_split_position: usize,
    /// Fragment size for TLS records.
    pub fragment_size: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            fingerprint: BrowserFingerprint::Firefox120,
            enable_sni_spoof: false,
            enable_tls_fragment: false,
            enable_desync: false,
            enable_quic_noise: false,
            enable_http_tricks: false,
            enable_polymorphism: false,
            enable_fake_dns: true,
            enable_gov_block: true,
            enable_blocklist: true,
            enable_cdn_bypass: true,
            dns_cache_size: 4096,
            dns_cache_min_ttl: Duration::from_secs(60),
            dns_cache_max_ttl: Duration::from_secs(86400),
            virtual_dns_pool_size: 131072,
            session_trust_threshold: 3,
            max_concurrent: 256,
            connect_timeout: Duration::from_secs(10),
            desync_split_position: 1,
            fragment_size: 20,
        }
    }
}

impl EngineConfig {
    /// Creates config from a preset.
    pub fn from_preset(preset: EnginePreset) -> Self {
        match preset {
            EnginePreset::Default => Self::default(),
            EnginePreset::Stealth => Self {
                fingerprint: BrowserFingerprint::Chrome120,
                enable_sni_spoof: true,
                enable_tls_fragment: true,
                enable_desync: true,
                enable_quic_noise: true,
                enable_http_tricks: true,
                enable_polymorphism: true,
                enable_fake_dns: true,
                enable_gov_block: true,
                ..Self::default()
            },
            EnginePreset::Performance => Self {
                enable_sni_spoof: false,
                enable_tls_fragment: false,
                enable_desync: false,
                enable_quic_noise: false,
                enable_http_tricks: false,
                enable_polymorphism: false,
                enable_fake_dns: false,
                max_concurrent: 1024,
                ..Self::default()
            },
            EnginePreset::Iran => Self {
                fingerprint: BrowserFingerprint::Chrome120,
                enable_sni_spoof: true,
                enable_tls_fragment: true,
                enable_desync: true,
                enable_http_tricks: true,
                enable_gov_block: true,
                desync_split_position: 3,
                fragment_size: 3,
                ..Self::default()
            },
            EnginePreset::China => Self {
                fingerprint: BrowserFingerprint::Chrome133,
                enable_sni_spoof: true,
                enable_tls_fragment: true,
                enable_desync: true,
                enable_quic_noise: true,
                enable_http_tricks: true,
                enable_gov_block: true,
                desync_split_position: 1,
                fragment_size: 3,
                ..Self::default()
            },
            EnginePreset::Russia => Self {
                fingerprint: BrowserFingerprint::Firefox120,
                enable_sni_spoof: true,
                enable_tls_fragment: true,
                enable_desync: true,
                enable_http_tricks: true,
                enable_gov_block: true,
                ..Self::default()
            },
            EnginePreset::Mobile => Self {
                fingerprint: BrowserFingerprint::IOS14,
                enable_sni_spoof: false,
                enable_tls_fragment: false,
                enable_desync: false,
                enable_quic_noise: false,
                max_concurrent: 64,
                connect_timeout: Duration::from_secs(15),
                ..Self::default()
            },
            EnginePreset::Debug => Self {
                enable_sni_spoof: false,
                enable_tls_fragment: false,
                enable_desync: false,
                enable_quic_noise: false,
                enable_http_tricks: false,
                enable_polymorphism: false,
                enable_fake_dns: false,
                enable_gov_block: false,
                enable_blocklist: false,
                enable_cdn_bypass: false,
                ..Self::default()
            },
        }
    }
}

// ─── Engine Metrics ──────────────────────────────────────────────────────────

/// Runtime metrics for monitoring engine behavior.
#[derive(Debug, Clone, Default)]
pub struct EngineMetrics {
    /// Total requests processed.
    pub total_requests: u64,
    /// Requests that required evasion.
    pub evasion_requests: u64,
    /// CDN challenges detected.
    pub cdn_challenges_detected: u64,
    /// CDN challenges bypassed.
    pub cdn_challenges_bypassed: u64,
    /// Government IPs blocked.
    pub gov_ips_blocked: u64,
    /// Domains blocked by blocklist.
    pub domains_blocked: u64,
    /// DNS cache hits.
    pub dns_cache_hits: u64,
    /// DNS cache misses.
    pub dns_cache_misses: u64,
    /// Virtual DNS resolutions.
    pub virtual_dns_resolutions: u64,
    /// Protocols detected.
    pub protocols_detected: u64,
    /// Active sessions.
    pub active_sessions: u64,
}

// ─── Main Engine ─────────────────────────────────────────────────────────────

/// The unified LumiNet engine.
///
/// This is the main entry point for all LumiNet functionality.
/// Create an instance with `LumiNetEngine::new()` or `LumiNetEngine::from_preset()`.
pub struct LumiNetEngine {
    /// Engine configuration.
    config: EngineConfig,
    /// DPI evasion engine.
    pub evasion: EvasionEngine,
    /// CDN bypass session store.
    cdn_sessions: CdnSessionStore,
    /// DNS response cache.
    dns_cache: DnsCache,
    /// Domain blocklist.
    blocklist: DomainBlocklist,
    /// Virtual DNS server.
    virtual_dns: VirtualDns,
    /// Runtime metrics.
    metrics: std::sync::RwLock<EngineMetrics>,
}

impl LumiNetEngine {
    /// Creates a new engine with default configuration.
    pub fn new() -> Self {
        Self::from_config(EngineConfig::default())
    }

    /// Creates a new engine from a preset.
    pub fn from_preset(preset: EnginePreset) -> Self {
        Self::from_config(EngineConfig::from_preset(preset))
    }

    /// Creates a new engine with custom configuration.
    pub fn from_config(config: EngineConfig) -> Self {
        Self {
            evasion: EvasionEngine {
                fingerprint: config.fingerprint,
                ..EvasionEngine::default()
            },
            cdn_sessions: CdnSessionStore::new(3600),
            dns_cache: DnsCache::new(config.dns_cache_size, config.dns_cache_max_ttl),
            blocklist: DomainBlocklist::new(),
            virtual_dns: VirtualDns::new(None),
            metrics: std::sync::RwLock::new(EngineMetrics::default()),
            config,
        }
    }

    /// Creates a new engine with Chrome fingerprint.
    pub fn chrome() -> Self {
        Self::from_config(EngineConfig {
            fingerprint: BrowserFingerprint::Chrome120,
            ..EngineConfig::default()
        })
    }

    /// Creates a new engine with Firefox fingerprint.
    pub fn firefox() -> Self {
        Self::from_config(EngineConfig {
            fingerprint: BrowserFingerprint::Firefox120,
            ..EngineConfig::default()
        })
    }

    // ─── Configuration ───────────────────────────────────────────────────

    /// Returns the current configuration.
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Returns the engine fingerprint name.
    pub fn fingerprint_name(&self) -> &str {
        self.evasion.fingerprint_name()
    }

    /// Returns the CDN challenge session store used by this engine.
    pub fn cdn_sessions(&self) -> &CdnSessionStore {
        &self.cdn_sessions
    }

    /// Returns the DNS response cache used by this engine.
    pub fn dns_cache(&self) -> &DnsCache {
        &self.dns_cache
    }

    // ─── IP Validation ───────────────────────────────────────────────────

    /// Checks if an IP is safe to connect to (not private/reserved).
    pub fn is_safe_ip(&self, ip: &IpAddr) -> bool {
        is_safe_target(ip)
    }

    /// Checks if an IP is private/reserved.
    pub fn is_private_ip(&self, ip: &IpAddr) -> bool {
        is_private_address(ip)
    }

    /// Checks if an IP belongs to a government entity.
    pub fn is_government_ip(&self, ip: &IpAddr) -> bool {
        if self.config.enable_gov_block {
            let result = gov_blocklist::is_government_ip(ip);
            if result {
                if let Ok(mut m) = self.metrics.write() {
                    m.gov_ips_blocked += 1;
                }
            }
            result
        } else {
            false
        }
    }

    /// Classifies network type from ASN information.
    pub fn classify_network(&self, asn: u32, as_name: &str) -> NetworkType {
        classify_network_type(asn, as_name)
    }

    // ─── Domain Blocking ─────────────────────────────────────────────────

    /// Checks if a domain is blocked by the blocklist.
    pub fn is_domain_blocked(&self, domain: &str) -> bool {
        if self.config.enable_blocklist {
            let blocked = self.blocklist.is_blocked(domain);
            if blocked {
                if let Ok(mut m) = self.metrics.write() {
                    m.domains_blocked += 1;
                }
            }
            blocked
        } else {
            false
        }
    }

    // ─── CDN Challenge Bypass ────────────────────────────────────────────

    /// Detects CDN challenge in response body.
    pub fn detect_cdn_challenge(&self, body: &str) -> CdnChallengeType {
        if self.config.enable_cdn_bypass {
            let detection = detect_cdn_challenge(body);
            if let Ok(mut m) = self.metrics.write() {
                m.cdn_challenges_detected += 1;
            }
            detection.challenge_type
        } else {
            CdnChallengeType::Cloudflare
        }
    }

    // ─── Virtual DNS ─────────────────────────────────────────────────────

    /// Resolves a domain to a virtual DNS IP.
    pub fn resolve_virtual(&self, domain: &str) -> Option<IpAddr> {
        if self.config.enable_fake_dns {
            let result = self.virtual_dns.resolve(domain).map(IpAddr::V4);
            if result.is_some() {
                if let Ok(mut m) = self.metrics.write() {
                    m.virtual_dns_resolutions += 1;
                }
            }
            result
        } else {
            None
        }
    }

    /// Reverse-resolves a virtual IP to a domain.
    pub fn reverse_virtual(&self, ip: &IpAddr) -> Option<String> {
        match ip {
            IpAddr::V4(v4) => self.virtual_dns.reverse_resolve(v4),
            _ => None,
        }
    }

    /// Checks if an IP is from the virtual DNS pool.
    pub fn is_virtual_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => VirtualDns::is_virtual_ip(v4),
            _ => false,
        }
    }

    // ─── Protocol Detection ──────────────────────────────────────────────

    /// Detects protocol from the first bytes of a connection.
    pub fn detect_protocol(&self, data: &[u8]) -> Option<protocol_detect::ProtocolMatch> {
        let result = protocol_detect::detect_protocol(data);
        if result.is_some() {
            if let Ok(mut m) = self.metrics.write() {
                m.protocols_detected += 1;
            }
        }
        result
    }

    // ─── Proxy URI Parsing ───────────────────────────────────────────────

    /// Parses a proxy URI into a ProxyNode.
    pub fn parse_proxy_uri(&self, uri: &str) -> Result<ProxyNode, ParseError> {
        crate::proxy::parse_proxy_uri(uri)
    }

    /// Parses a subscription list.
    pub fn parse_subscription(&self, content: &str) -> Vec<ProxyNode> {
        crate::proxy::parse_subscription(content)
    }

    // ─── Metrics ─────────────────────────────────────────────────────────

    /// Returns a snapshot of current metrics.
    pub fn metrics(&self) -> EngineMetrics {
        self.metrics.read().unwrap().clone()
    }

    /// Increments the total requests counter.
    pub fn record_request(&self) {
        if let Ok(mut m) = self.metrics.write() {
            m.total_requests += 1;
        }
    }

    /// Increments the evasion requests counter.
    pub fn record_evasion(&self) {
        if let Ok(mut m) = self.metrics.write() {
            m.evasion_requests += 1;
        }
    }
}

impl Default for LumiNetEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for LumiNetEngine {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            evasion: EvasionEngine {
                fingerprint: self.config.fingerprint,
                ..EvasionEngine::default()
            },
            cdn_sessions: CdnSessionStore::new(3600),
            dns_cache: DnsCache::new(self.config.dns_cache_size, self.config.dns_cache_max_ttl),
            blocklist: DomainBlocklist::new(),
            virtual_dns: VirtualDns::new(None),
            metrics: std::sync::RwLock::new(EngineMetrics::default()),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = LumiNetEngine::new();
        assert_eq!(engine.fingerprint_name(), "firefox120");
    }

    #[test]
    fn test_engine_chrome() {
        let engine = LumiNetEngine::chrome();
        assert_eq!(engine.fingerprint_name(), "chrome120");
    }

    #[test]
    fn test_engine_firefox() {
        let engine = LumiNetEngine::firefox();
        assert_eq!(engine.fingerprint_name(), "firefox120");
    }

    #[test]
    fn test_engine_stealth_preset() {
        let engine = LumiNetEngine::from_preset(EnginePreset::Stealth);
        assert_eq!(engine.config.fingerprint, BrowserFingerprint::Chrome120);
        assert!(engine.config.enable_sni_spoof);
        assert!(engine.config.enable_tls_fragment);
        assert!(engine.config.enable_desync);
    }

    #[test]
    fn test_engine_iran_preset() {
        let engine = LumiNetEngine::from_preset(EnginePreset::Iran);
        assert!(engine.config.enable_sni_spoof);
        assert!(engine.config.enable_desync);
        assert_eq!(engine.config.desync_split_position, 3);
    }

    #[test]
    fn test_safe_ip() {
        let engine = LumiNetEngine::new();
        assert!(engine.is_safe_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!engine.is_safe_ip(&"10.0.0.1".parse().unwrap()));
        assert!(!engine.is_safe_ip(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn test_government_ip() {
        let engine = LumiNetEngine::new();
        assert!(engine.is_government_ip(&"193.232.128.1".parse().unwrap()));
        assert!(!engine.is_government_ip(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_virtual_dns() {
        let engine = LumiNetEngine::new();
        let ip = engine.resolve_virtual("example.com").unwrap();
        assert!(engine.is_virtual_ip(&ip));
        assert!(engine.reverse_virtual(&ip).is_some());
    }

    #[test]
    fn test_protocol_detection() {
        let engine = LumiNetEngine::new();
        let http_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        let result = engine.detect_protocol(http_data);
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, "http");
    }

    #[test]
    fn test_metrics() {
        let engine = LumiNetEngine::new();
        engine.record_request();
        engine.record_request();
        engine.record_evasion();
        let metrics = engine.metrics();
        assert_eq!(metrics.total_requests, 2);
        assert_eq!(metrics.evasion_requests, 1);
    }

    #[test]
    fn test_cdn_challenge_detection() {
        let engine = LumiNetEngine::new();
        let body = "<html>__arcsjs __arcsjsc Transferring to the website</html>";
        let result = engine.detect_cdn_challenge(body);
        assert_eq!(result, CdnChallengeType::ArvanCloud);
    }

    #[test]
    fn test_classify_network() {
        let engine = LumiNetEngine::new();
        assert_eq!(
            engine.classify_network(14061, "DIGITALOCEAN"),
            NetworkType::Hosting
        );
        assert_eq!(
            engine.classify_network(0, "NordVPN Services"),
            NetworkType::VPN
        );
    }
}
