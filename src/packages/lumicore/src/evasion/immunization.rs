//! # Autonomous Self-Immunization Engine
//!
//! Real-time detection of DPI middlebox interference (TCP RST injection, SNI reset,
//! handshake dropouts) and dynamic synthesis of evasion "antibodies".
//!
//! ## Official References:
//! - RFC 793 / RFC 9293 (Transmission Control Protocol: RST processing)
//! - RFC 8446 (The Transport Layer Security (TLS) Protocol Version 1.3: Server Name Indication)
//! - Rust DashMap: <https://docs.rs/dashmap/latest/dashmap/>
//! - Serde: <https://serde.rs/>
//!
//! ## Design Patterns:
//! - `leonardomso-rust-skills`: `own-borrow-over-clone`, `type-enum-states`, `mem-zero-copy`

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Type of middlebox interference detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterferenceType {
    /// Injected TCP RST packet with anomalous TTL or sequence jump.
    RstInjection,
    /// TCP connection reset immediately following TLS ClientHello SNI.
    SniReset,
    /// Connection silence/timeout during TLS handshake exchange.
    HandshakeTimeout,
    /// Injected HTTP blockpage (e.g. 403/302 from ISP filter).
    BlockPage,
    /// Unclassified anomaly.
    Unknown,
}

/// Observed middlebox interference event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterferenceEvent {
    /// Target domain name that was blocked.
    pub domain: String,
    /// Classified interference mechanism.
    pub interference_type: InterferenceType,
    /// Observed TTL of the terminating packet.
    pub observed_ttl: u8,
    /// Expected natural hop TTL.
    pub expected_ttl: u8,
    /// Relative TCP sequence number on reset.
    pub reset_window_seq: u32,
}

/// Dynamic evasion antibody synthesized to bypass middlebox interference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionAntibody {
    /// Domain pattern (supports exact "example.com" or wildcard "*.example.com").
    pub domain_pattern: String,
    /// TLS ClientHello SNI fragmentation byte split offset.
    pub sni_split_offset: usize,
    /// TCP desync split packet chunk offset.
    pub tcp_desync_offset: usize,
    /// Out-of-band fake packet TTL hop limit.
    pub fake_ttl: u8,
    /// Inject decoy RST before actual packet stream.
    pub decoy_rst: bool,
    /// Total successful connections made using this antibody.
    pub success_count: u64,
    /// Total failed connections with this antibody.
    pub fail_count: u64,
    /// Confidence probability [0.0, 1.0].
    pub confidence: f64,
}

/// Autonomous Self-Immunization Engine.
pub struct ImmunizationEngine {}

impl ImmunizationEngine {
    /// Creates a new `ImmunizationEngine`.
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// Synthesizes an evasion antibody from an observed middlebox interference event.
    #[must_use]
    pub fn synthesize_antibody(&self, event: &InterferenceEvent) -> EvasionAntibody {
        match event.interference_type {
            InterferenceType::RstInjection => EvasionAntibody {
                domain_pattern: event.domain.clone(),
                sni_split_offset: 2,
                tcp_desync_offset: 3,
                fake_ttl: 3,
                decoy_rst: true,
                success_count: 1,
                fail_count: 0,
                confidence: 0.85,
            },
            InterferenceType::SniReset => EvasionAntibody {
                domain_pattern: event.domain.clone(),
                sni_split_offset: 3,
                tcp_desync_offset: 2,
                fake_ttl: 4,
                decoy_rst: false,
                success_count: 1,
                fail_count: 0,
                confidence: 0.80,
            },
            InterferenceType::HandshakeTimeout => EvasionAntibody {
                domain_pattern: event.domain.clone(),
                sni_split_offset: 5,
                tcp_desync_offset: 5,
                fake_ttl: 2,
                decoy_rst: false,
                success_count: 1,
                fail_count: 0,
                confidence: 0.70,
            },
            InterferenceType::BlockPage | InterferenceType::Unknown => EvasionAntibody {
                domain_pattern: event.domain.clone(),
                sni_split_offset: 2,
                tcp_desync_offset: 1,
                fake_ttl: 5,
                decoy_rst: false,
                success_count: 1,
                fail_count: 0,
                confidence: 0.60,
            },
        }
    }
}

impl Default for ImmunizationEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe Immune Memory repository storing evasion antibodies.
#[derive(Clone)]
pub struct AntibodyStore {
    inner: Arc<DashMap<String, EvasionAntibody>>,
}

impl AntibodyStore {
    /// Creates a new, empty `AntibodyStore`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    /// Inserts or updates an antibody in the store.
    pub fn insert(&self, antibody: EvasionAntibody) {
        self.inner.insert(antibody.domain_pattern.clone(), antibody);
    }

    /// Looks up an active antibody for a domain, testing exact and wildcard matches.
    #[must_use]
    pub fn lookup(&self, domain: &str) -> Option<EvasionAntibody> {
        // 1. Exact match
        if let Some(entry) = self.inner.get(domain) {
            return Some(entry.clone());
        }

        // 2. Wildcard match (*.example.org matches sub.example.org)
        for entry in self.inner.iter() {
            let pattern = entry.key();
            if let Some(suffix) = pattern.strip_prefix("*.") {
                if domain.ends_with(suffix) && domain.len() > suffix.len() {
                    return Some(entry.value().clone());
                }
            }
        }

        None
    }

    /// Records connection outcome (success or failure) and updates antibody confidence.
    pub fn record_outcome(&self, domain: &str, success: bool) {
        if let Some(mut entry) = self.inner.get_mut(domain) {
            if success {
                entry.success_count += 1;
            } else {
                entry.fail_count += 1;
            }
            let total = (entry.success_count + entry.fail_count) as f64;
            if total > 0.0 {
                entry.confidence = (entry.success_count as f64) / total;
            }
        }
    }

    /// Returns the number of registered antibodies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Checks if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for AntibodyStore {
    fn default() -> Self {
        Self::new()
    }
}
