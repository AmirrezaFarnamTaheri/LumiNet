//! # Adaptive Protocol Matrix (Second-Order Convergence)
//!
//! Synthesizes anomaly probing, protocol capability matrix, TCP window clamping,
//! OverTLS framing, SNI fragmentation, and dual-backend control into a resilient,
//! self-healing transport decision engine.

use crate::diagnostics::censorship_anomaly_prober::{AnomalyType, CensorshipAnomalyProber, InterferenceSignature};
use crate::evasion::protocol_capability_matrix::{EvasionCapability, ProtocolCapabilityMatrix};
use crate::evasion::tcp_window_clamper::{TcpWindowClamper, WindowClampMode};
use crate::sni::sni_fragmentation_injector::{SniFragmentationInjector, SniInjectionMode};
use crate::transport::dual_backend_controller::{BackendEngineKind, DualBackendController, EngineSwitchPolicy};

#[derive(Debug, Clone)]
pub struct TransportActionProfile {
    pub recommended_protocol: String,
    pub active_backend: BackendEngineKind,
    pub sni_injection: SniInjectionMode,
    pub window_clamp_size: u16,
    pub mitigation_applied: String,
}

#[derive(Debug, Clone)]
pub struct AdaptiveProtocolMatrix {
    prober: CensorshipAnomalyProber,
    capability_matrix: ProtocolCapabilityMatrix,
    backend_controller: DualBackendController,
    clamper: TcpWindowClamper,
    sni_injector: SniFragmentationInjector,
}

impl Default for AdaptiveProtocolMatrix {
    fn default() -> Self {
        Self {
            prober: CensorshipAnomalyProber::new(),
            capability_matrix: ProtocolCapabilityMatrix::default(),
            backend_controller: DualBackendController::new(EngineSwitchPolicy::ActiveActiveRttRace),
            clamper: TcpWindowClamper::default(),
            sni_injector: SniFragmentationInjector::default(),
        }
    }
}

impl AdaptiveProtocolMatrix {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingests an observed network anomaly and adapts the transport posture.
    pub fn adapt_to_anomaly(&mut self, anomaly: &InterferenceSignature) -> TransportActionProfile {
        match anomaly.anomaly_type {
            AnomalyType::SniReset => {
                // Adapt SNI injection and window clamping
                self.sni_injector.mode = SniInjectionMode::SplitAtSniExtension;
                self.clamper = TcpWindowClamper::new(WindowClampMode::HandshakeOnly(2));
                let required = vec![EvasionCapability::SniFragmentation, EvasionCapability::TlsFingerprintSpoofing];
                let proto = self.capability_matrix.recommend_protocol(&required)
                    .map(|p| p.name)
                    .unwrap_or_else(|| "Trojan-SNI-Fragment".to_string());

                TransportActionProfile {
                    recommended_protocol: proto,
                    active_backend: self.backend_controller.select_engine(),
                    sni_injection: SniInjectionMode::SplitAtSniExtension,
                    window_clamp_size: 2,
                    mitigation_applied: "SNI Extension Split + Window Clamping to 2 bytes".to_string(),
                }
            }
            AnomalyType::UdpBlackhole => {
                // Switch backend to TCP-based or tunnel fallback
                self.backend_controller.record_health(BackendEngineKind::KcpRawSocket, 999, 1.0, false);
                let required = vec![EvasionCapability::EarlyDataReplayDefense, EvasionCapability::RecordPadding];
                let proto = self.capability_matrix.recommend_protocol(&required)
                    .map(|p| p.name)
                    .unwrap_or_else(|| "VLESS-Reality".to_string());

                TransportActionProfile {
                    recommended_protocol: proto,
                    active_backend: self.backend_controller.select_engine(),
                    sni_injection: self.sni_injector.mode,
                    window_clamp_size: self.clamper.clamped_window_size,
                    mitigation_applied: "Demoted UDP/KCP backend, transitioned to VLESS-Reality TCP stream".to_string(),
                }
            }
            AnomalyType::TcpRstInjection => {
                let required = vec![EvasionCapability::TcpDesyncImmunity, EvasionCapability::TlsFingerprintSpoofing];
                let proto = self.capability_matrix.recommend_protocol(&required)
                    .map(|p| p.name)
                    .unwrap_or_else(|| "Trojan-SNI-Fragment".to_string());

                TransportActionProfile {
                    recommended_protocol: proto,
                    active_backend: BackendEngineKind::ViolatedTcpQuic,
                    sni_injection: SniInjectionMode::SplitInMiddle,
                    window_clamp_size: 4,
                    mitigation_applied: "Enabled Violated TCP/QUIC injection with RST poison filtering".to_string(),
                }
            }
            _ => {
                let default_proto = self.capability_matrix.recommend_protocol(&[])
                    .map(|p| p.name)
                    .unwrap_or_else(|| "Hysteria2".to_string());

                TransportActionProfile {
                    recommended_protocol: default_proto,
                    active_backend: self.backend_controller.select_engine(),
                    sni_injection: self.sni_injector.mode,
                    window_clamp_size: self.clamper.clamped_window_size,
                    mitigation_applied: "Standard baseline transport maintained".to_string(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_protocol_matrix_sni_reset() {
        let mut matrix = AdaptiveProtocolMatrix::new();
        let anomaly = InterferenceSignature {
            anomaly_type: AnomalyType::SniReset,
            confidence: 0.95,
            details: "RST on ClientHello".to_string(),
        };

        let profile = matrix.adapt_to_anomaly(&anomaly);
        assert_eq!(profile.sni_injection, SniInjectionMode::SplitAtSniExtension);
        assert_eq!(profile.window_clamp_size, 2);
        assert!(profile.mitigation_applied.contains("SNI Extension Split"));
    }

    #[test]
    fn test_adaptive_protocol_matrix_udp_blackhole() {
        let mut matrix = AdaptiveProtocolMatrix::new();
        let anomaly = InterferenceSignature {
            anomaly_type: AnomalyType::UdpBlackhole,
            confidence: 0.92,
            details: "100% UDP drop".to_string(),
        };

        let profile = matrix.adapt_to_anomaly(&anomaly);
        assert_ne!(profile.active_backend, BackendEngineKind::KcpRawSocket);
        assert!(profile.mitigation_applied.contains("Demoted UDP/KCP"));
    }
}
