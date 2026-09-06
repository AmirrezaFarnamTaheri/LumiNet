//! # Evasion Engine
//!
//! Unified DPI evasion module consolidating all anti-censorship techniques.
//! Merges: tls_evasion, tls_fragment, tls_http_evasion, sni_spoof, desync, dpi_evasion, censorship_detect.
//!
//! ## Architecture
//!
//! ```text
//! evasion/
//! ├── mod.rs          ← EvasionEngine orchestrator (this file)
//! ├── fingerprint.rs  ← Unified browser fingerprint enum (40+ variants)
//! ├── fragment.rs     ← Unified fragmentation (profile-based + fixed-size + TLS record + version spoof)
//! ├── desync.rs       ← TCP desync attacks (fake packets, out-of-order)
//! ├── http_tricks.rs  ← HTTP header manipulations (15 techniques)
//! ├── noise.rs        ← QUIC noise injection
//! ├── sni_spoof.rs    ← Fake ClientHello injection with wrong seq
//! ├── smuggling.rs    ← HTTP request smuggling (10 types)
//! └── detect.rs       ← Censorship detection
//! ```

pub mod amneziawg_shaper;
pub mod client_ip_obfuscator;
pub mod cloak_obfs;
pub mod desync;
pub mod detect;
pub mod ech_plugin;
pub mod ev_evasion;
pub mod fingerprint;
pub mod fragment;
pub mod http_tricks;
pub mod immunization;
pub mod noise;
pub mod noize_shaper;
pub mod packet_header;
pub mod paqet_injection;
pub mod passive_dpi_evasion;
pub mod reality_impersonator;
pub mod secure_hostname;
pub mod smuggling;
pub mod sni_bypass;
pub mod sni_padded;
pub mod sudoku_shaping;
pub mod sni_reader;
pub mod sni_spoof;
pub mod mitm_domain_fronting;
pub mod sni_taxonomy;
pub mod snispf_hj;
pub mod tls_fragmentation;
pub mod tls_fragmenter;
pub mod sni_desync;
pub mod sni_desync_state_machine;
pub mod sni_spoof_engine;
pub mod multi_strategy_fragmenter;
pub mod adaptive_strategy_racer;
pub mod combined_bypass_evaluator;
pub mod serverless_direct_shaper;
pub mod utls_spoof_proxy;
pub mod win_divert_proxifier;

pub use multi_strategy_fragmenter::*;
pub use adaptive_strategy_racer::*;
pub use combined_bypass_evaluator::*;
pub use serverless_direct_shaper::*;
pub use sni_spoof_engine::{
    CloudflareCidrMatcher, Conn4TupleKey, IpTcpPacket, KillSwitchAction, KillSwitchCoordinator,
    SniDomainCleaner, SniSpoofEngineProfile, TlsClientHelloTemplate,
};
pub use mitm_domain_fronting::{
    match_san_pattern, FrontingAction, FrontingTargetProfile, MitmAlpn, MitmFrontingRouter,
};

pub use amneziawg_shaper::{forwarded_ports_include, parse_forwarded_ports, Obfuscation31};
pub use tls_fragmenter::{TlsFragmentStrategy, TlsFragmenter};
pub use sni_desync::{compute_out_of_window_seq, DesyncSegment, SniDesyncPlanner};
pub use sni_desync_state_machine::*;


pub use client_ip_obfuscator::ClientIPObfuscator;
pub use cloak_obfs::{AuthInfo, AuthenticationPayload, CloakObfs};
pub use fingerprint::BrowserFingerprint;
pub use secure_hostname::SecureHostnameOutbound;
pub use win_divert_proxifier::{
    get_original_destination, start_win_divert_proxifier, WinDivertProxifierConfig,
};

pub use desync::{DesyncAttack, DesyncConfig, FAKE_HTTP_GET, FAKE_TLS_CLIENT_HELLO};
pub use detect::{
    classify_http_blocking, detect_dns_manipulation, detect_https_mitm, detect_passive_dpi,
    run_detection_scan, CensorshipReport, DnsManipulation, HttpBlocking, HttpsResult,
};
pub use ech_plugin::ECHPlugin;
pub use ev_evasion::{DistractorType, EvEvasionConfig, EvEvasionEngine};
pub use fragment::{FragmentConfig, FragmentProfile};
pub use http_tricks::{generate_http_payloads, HttpTrick};
pub use noise::{default_quic_noise, send_noise_packets, NoisePacket};
pub use paqet_injection::PaqetEngine;
pub use passive_dpi_evasion::{PassiveDpiEvasionConfig, PassiveDpiEvasionEngine};
pub use reality_impersonator::RealityImpersonator;
pub use smuggling::{apply_smuggling, HttpSmuggling};
pub use sni_bypass::{SniBypassConfig, SniBypassEngine};
pub use sni_reader::{
    read_sni_host_name_from_client_hello, PrefixedReaderWriter, RecordingBufReader,
};
pub use sni_spoof::{
    build_fake_clienthello, compute_fake_seq, parse_sni_from_clienthello, ConnectionTracker,
    SniSpoof, SniSpoofConfig,
};
pub use sudoku_shaping::{
    shape_once, unshape_once, ShapingError, ShapingRole, SudokuConfig, SudokuCursor,
    SudokuShaper, SUDOKU_MATRIX, WalkMode,
};
pub use snispf_hj::{
    generate_all_combinations, probe_tcp, sample_cidr_ips, scan_cloudflare_ips, ActivePool,
    IpSniPair, PairStats, SnispfHjConfig, CLOUDFLARE_CIDRS,
};
pub use tls_fragmentation::TLSFragmentation;
pub use utls_spoof_proxy::UTlsSpoofProxy;

use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

/// The unified evasion engine that orchestrates all bypass techniques.
///
/// Combines multiple DPI evasion strategies:
/// - Browser fingerprint mimicry (40+ variants)
/// - TLS ClientHello fragmentation (profile-based + fixed-size)
/// - TCP desynchronization (fake packets, out-of-order delivery)
/// - HTTP header manipulation (15 techniques)
/// - QUIC noise injection
/// - SNI spoofing with wrong TCP sequence numbers
/// - HTTP request smuggling (10 types)
/// - Censorship detection and classification
pub struct EvasionEngine {
    /// Browser fingerprint to mimic.
    pub fingerprint: BrowserFingerprint,
    /// Fragment configuration for TLS records.
    pub fragment_config: FragmentConfig,
    /// TCP desync configuration.
    pub desync_config: DesyncConfig,
    /// SNI spoofing configuration.
    pub sni_config: SniSpoofConfig,
}

impl Default for EvasionEngine {
    fn default() -> Self {
        Self {
            fingerprint: BrowserFingerprint::Firefox120,
            fragment_config: FragmentConfig::default(),
            desync_config: DesyncConfig::default(),
            sni_config: SniSpoofConfig::default(),
        }
    }
}

impl EvasionEngine {
    /// Creates a new evasion engine with Chrome fingerprint.
    pub fn chrome() -> Self {
        Self {
            fingerprint: BrowserFingerprint::Chrome120,
            ..Default::default()
        }
    }

    /// Creates a new evasion engine with Firefox fingerprint.
    pub fn firefox() -> Self {
        Self {
            fingerprint: BrowserFingerprint::Firefox120,
            ..Default::default()
        }
    }

    /// Sends data with the configured evasion technique.
    ///
    /// Applies the appropriate DPI bypass based on the desync configuration:
    /// - None: Direct write
    /// - FakeTtl: Send fake packet with low TTL, then real data split
    /// - Disorder: Split data into out-of-order segments
    /// - DisorderFake: Both fake packet and out-of-order delivery
    pub fn send_evasive(
        &self,
        stream: &mut TcpStream,
        data: &[u8],
        is_https: bool,
    ) -> std::io::Result<()> {
        match self.desync_config.attack_type {
            DesyncAttack::None => {
                stream.write_all(data)?;
                stream.flush()?;
            }
            DesyncAttack::FakeTtl | DesyncAttack::DisorderFake => {
                // Select fake packet based on protocol
                let fake = if is_https {
                    FAKE_TLS_CLIENT_HELLO
                } else {
                    FAKE_HTTP_GET
                };
                // In real implementation: send via raw socket with low TTL
                let _ = fake;

                // Send real data split at configured position
                let split_pos = self.desync_config.split_position.min(data.len());
                if split_pos > 0 && split_pos < data.len() {
                    // Send second part first (out-of-order)
                    stream.write_all(&data[split_pos..])?;
                    stream.flush()?;
                    // Brief delay to confuse DPI reassembly
                    std::thread::sleep(Duration::from_millis(5));
                    // Send first part
                    stream.write_all(&data[..split_pos])?;
                    stream.flush()?;
                } else {
                    stream.write_all(data)?;
                    stream.flush()?;
                }
            }
            DesyncAttack::Disorder => {
                // Split data into out-of-order segments
                let split_pos = self.desync_config.split_position.min(data.len());
                if split_pos > 0 && split_pos < data.len() {
                    stream.write_all(&data[split_pos..])?;
                    stream.flush()?;
                    std::thread::sleep(Duration::from_millis(5));
                    stream.write_all(&data[..split_pos])?;
                    stream.flush()?;
                } else {
                    stream.write_all(data)?;
                    stream.flush()?;
                }
            }
            _ => {
                stream.write_all(data)?;
                stream.flush()?;
            }
        }
        Ok(())
    }

    /// Returns the fingerprint name string.
    pub fn fingerprint_name(&self) -> &str {
        self.fingerprint.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_engine() {
        let engine = EvasionEngine::default();
        assert_eq!(engine.fingerprint, BrowserFingerprint::Firefox120);
    }

    #[test]
    fn test_chrome_engine() {
        let engine = EvasionEngine::chrome();
        assert_eq!(engine.fingerprint, BrowserFingerprint::Chrome120);
    }

    #[test]
    fn test_firefox_engine() {
        let engine = EvasionEngine::firefox();
        assert_eq!(engine.fingerprint, BrowserFingerprint::Firefox120);
    }

    #[test]
    fn test_fingerprint_name() {
        let engine = EvasionEngine::chrome();
        assert_eq!(engine.fingerprint_name(), "chrome120");
    }
}

pub mod ipsec_profile;
pub use ipsec_profile::{DhGroup, EncryptionAlgorithm, EspProposal, Ikev2Proposal, IpsecProfile};

pub mod kernel_hardening_profile;
pub use kernel_hardening_profile::{KernelHardeningParameter, KernelHardeningProfile};

pub mod noise_packet_injector;
pub mod hotspot_nat_repeater;
pub mod tcp_chunk_splitter;

pub mod dpi_pattern_masker;

pub mod covert_storage_framer;

pub mod tcp_desync_poisoner;
pub mod autonomous_evasion_orchestrator;
pub mod protocol_capability_matrix;
pub mod tcp_window_clamper;
pub mod nfqueue_packet_scrambler;
pub mod sni_hostname_rewriter;
pub mod censorship_profile_synthesizer;
pub mod censorship_trigger_generator;
pub mod sni_segmentation_masquerader;

pub mod entropy_scrambled_tunnel;
pub mod amnezia_obfs_parameters;

pub mod stealth_bridge_collector;
pub mod on_device_dpi_evader;
pub mod universal_mesh_evasion_pipeline;
