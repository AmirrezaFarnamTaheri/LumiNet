//! # Combined Bypass Engine & Domain Evasion Evaluator
//!
//! Implements the combined multi-technique DPI evasion strategy (low-TTL decoy trick +
//! real ClientHello SNI-split fragmentation with micro-delays) and autonomous domain
//! unblocking capability assessment.
//!

use serde::{Deserialize, Serialize};
use std::time::Duration;
use super::tls_fragmenter::{TlsFragmentStrategy, TlsFragmenter};

/// Strategy options for combined DPI evasion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BypassMode {
    Direct,
    FakeSniDecoy,
    SniFragment,
    CombinedTtlDecoy,
    CombinedRawDesync,
}

/// Configuration for combined multi-layer bypass execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedBypassConfig {
    pub mode: BypassMode,
    pub fake_sni: String,
    pub use_ttl_trick: bool,
    pub ttl_hops: u8,
    pub fragment_strategy: String,
    pub fragment_delay_ms: u64,
}

impl Default for CombinedBypassConfig {
    fn default() -> Self {
        Self {
            mode: BypassMode::CombinedTtlDecoy,
            fake_sni: "auth.vercel.com".to_string(),
            use_ttl_trick: true,
            ttl_hops: 2,
            fragment_strategy: "sni_split".to_string(),
            fragment_delay_ms: 10,
        }
    }
}

/// Prepared sequence of frames or packets to be transmitted for combined evasion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedEvasionPlan {
    pub ttl_decoy_probe: Option<DecoyProbeSpec>,
    pub real_fragments: Vec<FragmentSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoyProbeSpec {
    pub ttl: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentSpec {
    pub payload: Vec<u8>,
    pub delay_ms: u64,
}

/// Planner creating combined evasion execution sequences.
pub struct CombinedBypassPlanner;

impl CombinedBypassPlanner {
    /// Builds a multi-layer evasion plan for a target ClientHello payload.
    pub fn plan(
        real_client_hello: &[u8],
        fake_client_hello: &[u8],
        config: &CombinedBypassConfig,
    ) -> PreparedEvasionPlan {
        let ttl_decoy_probe = if config.use_ttl_trick || config.mode == BypassMode::CombinedTtlDecoy {
            Some(DecoyProbeSpec {
                ttl: config.ttl_hops,
                payload: fake_client_hello.to_vec(),
            })
        } else {
            None
        };

        let strategy = match config.fragment_strategy.as_str() {
            "sni_split" => TlsFragmentStrategy::SniSplit,
            "sni_boundary" => TlsFragmentStrategy::SniBoundary,
            "half" => TlsFragmentStrategy::Half,
            "tls_record" => TlsFragmentStrategy::TlsRecordFrag,
            _ => TlsFragmentStrategy::SniSplit,
        };

        let raw_frags = TlsFragmenter::fragment(real_client_hello, strategy);
        let mut real_fragments = Vec::with_capacity(raw_frags.len());

        for (i, frag) in raw_frags.into_iter().enumerate() {
            let delay = if i == 0 { 0 } else { config.fragment_delay_ms };
            real_fragments.push(FragmentSpec {
                payload: frag,
                delay_ms: delay,
            });
        }

        PreparedEvasionPlan {
            ttl_decoy_probe,
            real_fragments,
        }
    }
}

/// Outcome of evaluating a domain against a bypass strategy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DomainEvaluationResult {
    pub domain: String,
    pub mode: BypassMode,
    pub success: bool,
    pub latency_ms: u64,
    pub http_status: Option<u16>,
    pub error: Option<String>,
}

/// Evaluator comparing domain reachability across multiple evasion strategies.
pub struct DomainBypassEvaluator;

impl DomainBypassEvaluator {
    /// Determines the best (lowest overhead, functional) bypass mode from a set of test results.
    pub fn select_optimal_mode(results: &[DomainEvaluationResult]) -> Option<BypassMode> {
        // Hierarchy of preference: Direct -> SniFragment -> FakeSniDecoy -> CombinedTtlDecoy -> CombinedRawDesync
        let order = [
            BypassMode::Direct,
            BypassMode::SniFragment,
            BypassMode::FakeSniDecoy,
            BypassMode::CombinedTtlDecoy,
            BypassMode::CombinedRawDesync,
        ];

        for mode in &order {
            if let Some(r) = results.iter().find(|res| res.mode == *mode && res.success) {
                return Some(r.mode.clone());
            }
        }

        None
    }
}
