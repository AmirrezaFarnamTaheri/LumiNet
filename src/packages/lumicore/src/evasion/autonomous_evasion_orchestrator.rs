//! Autonomous Evasion Orchestrator
//!
//! Synthesizes and coordinates multi-layer traffic obfuscation tactics:
//! DPI pattern fragmentation, fake Desync poisoning, noise record injection,
//! and SNI domain fronting.

use crate::evasion::dpi_pattern_masker::DpiPatternMasker;
use crate::evasion::tcp_desync_poisoner::{DesyncTactic, TcpDesyncPoisoner};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvasionTacticalProfile {
    PassiveFragment,
    AggressiveDesync,
    FullStealth,
}

#[derive(Debug)]
pub struct AutonomousEvasionOrchestrator {
    pub profile: EvasionTacticalProfile,
    masker: DpiPatternMasker,
    poisoner: TcpDesyncPoisoner,
}

impl AutonomousEvasionOrchestrator {
    pub fn new(profile: EvasionTacticalProfile) -> Self {
        let (split_off, insert_noise, desync) = match profile {
            EvasionTacticalProfile::PassiveFragment => (8, false, DesyncTactic::SplitPayload),
            EvasionTacticalProfile::AggressiveDesync => (4, true, DesyncTactic::FakeRst),
            EvasionTacticalProfile::FullStealth => (3, true, DesyncTactic::CorruptedChecksum),
        };

        Self {
            profile,
            masker: DpiPatternMasker::new(split_off, insert_noise),
            poisoner: TcpDesyncPoisoner::new(desync, 3),
        }
    }

    /// Obfuscates an outgoing stream payload according to the tactical profile
    pub fn process_outbound(&self, payload: &[u8]) -> Vec<Vec<u8>> {
        self.masker.fragment_payload(payload)
    }

    /// Generates pre-flight desync poisoning header if aggressive or stealth profile is engaged
    pub fn generate_poison_header(&self, src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Option<Vec<u8>> {
        match self.profile {
            EvasionTacticalProfile::PassiveFragment => None,
            EvasionTacticalProfile::AggressiveDesync | EvasionTacticalProfile::FullStealth => {
                Some(self.poisoner.create_poison_header(src_port, dst_port, seq, ack))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autonomous_evasion_orchestrator() {
        let orch = AutonomousEvasionOrchestrator::new(EvasionTacticalProfile::AggressiveDesync);
        let poison = orch.generate_poison_header(5000, 443, 100, 200);
        assert!(poison.is_some());
        assert_eq!(poison.unwrap().len(), 20);

        let data = vec![0x16, 0x03, 0x01, 0x00, 0x20, 0x01, 0x02, 0x03];
        let frags = orch.process_outbound(&data);
        assert!(frags.len() >= 2);
    }
}
