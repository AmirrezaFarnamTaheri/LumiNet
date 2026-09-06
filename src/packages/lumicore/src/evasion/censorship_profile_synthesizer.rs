//! Censorship Profile Synthesizer
//!
//! Synthesizes regional anti-censorship configurations (e.g. for aggressive DPI in China, Iran, Russia)
//! with tailored DNS fragmentation chains, TCP MSS clamping, TLS decoy padding, and serverless multiplexing.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CensorshipRegion {
    China,
    Iran,
    Russia,
    DefaultGlobal,
}

#[derive(Debug, Clone)]
pub struct RegionalEvasionProfile {
    pub region: CensorshipRegion,
    pub dns_fragmentation_enabled: bool,
    pub dns_fragment_size: usize,
    pub tcp_mss_clamp: u16,
    pub tls_record_padding_range: (usize, usize),
    pub enable_parallel_dns_queries: bool,
    pub preferred_dns_servers: Vec<String>,
}

pub struct CensorshipProfileSynthesizer {
    profiles: HashMap<CensorshipRegion, RegionalEvasionProfile>,
}

impl CensorshipProfileSynthesizer {
    pub fn new() -> Self {
        let mut profiles = HashMap::new();

        profiles.insert(
            CensorshipRegion::China,
            RegionalEvasionProfile {
                region: CensorshipRegion::China,
                dns_fragmentation_enabled: true,
                dns_fragment_size: 40,
                tcp_mss_clamp: 1200,
                tls_record_padding_range: (100, 500),
                enable_parallel_dns_queries: true,
                preferred_dns_servers: vec![
                    "https://cloudflare-dns.com/dns-query".to_string(),
                    "https://dns.google/dns-query".to_string(),
                ],
            },
        );

        profiles.insert(
            CensorshipRegion::Iran,
            RegionalEvasionProfile {
                region: CensorshipRegion::Iran,
                dns_fragmentation_enabled: true,
                dns_fragment_size: 32,
                tcp_mss_clamp: 1100,
                tls_record_padding_range: (256, 1024),
                enable_parallel_dns_queries: true,
                preferred_dns_servers: vec![
                    "https://sky.rethinkdns.com/dns-query".to_string(),
                    "https://dns.quad9.net/dns-query".to_string(),
                    "h2c://1.1.1.1/dns-query".to_string(),
                ],
            },
        );

        profiles.insert(
            CensorshipRegion::Russia,
            RegionalEvasionProfile {
                region: CensorshipRegion::Russia,
                dns_fragmentation_enabled: false,
                dns_fragment_size: 0,
                tcp_mss_clamp: 1300,
                tls_record_padding_range: (64, 256),
                enable_parallel_dns_queries: true,
                preferred_dns_servers: vec![
                    "https://1.1.1.1/dns-query".to_string(),
                    "https://dns.google/dns-query".to_string(),
                ],
            },
        );

        profiles.insert(
            CensorshipRegion::DefaultGlobal,
            RegionalEvasionProfile {
                region: CensorshipRegion::DefaultGlobal,
                dns_fragmentation_enabled: false,
                dns_fragment_size: 0,
                tcp_mss_clamp: 1460,
                tls_record_padding_range: (0, 0),
                enable_parallel_dns_queries: false,
                preferred_dns_servers: vec!["https://1.1.1.1/dns-query".to_string()],
            },
        );

        Self { profiles }
    }

    pub fn get_profile(&self, region: CensorshipRegion) -> RegionalEvasionProfile {
        self.profiles
            .get(&region)
            .cloned()
            .unwrap_or_else(|| self.profiles[&CensorshipRegion::DefaultGlobal].clone())
    }

    pub fn register_custom_profile(&mut self, profile: RegionalEvasionProfile) {
        self.profiles.insert(profile.region, profile);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_censorship_profile_synthesis() {
        let synth = CensorshipProfileSynthesizer::new();
        let iran = synth.get_profile(CensorshipRegion::Iran);
        assert!(iran.dns_fragmentation_enabled);
        assert_eq!(iran.dns_fragment_size, 32);
        assert_eq!(iran.tcp_mss_clamp, 1100);

        let china = synth.get_profile(CensorshipRegion::China);
        assert_eq!(china.tcp_mss_clamp, 1200);

        let global = synth.get_profile(CensorshipRegion::DefaultGlobal);
        assert!(!global.dns_fragmentation_enabled);
        assert_eq!(global.tcp_mss_clamp, 1460);
    }
}
