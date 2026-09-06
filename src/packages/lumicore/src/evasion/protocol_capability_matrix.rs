//! # Protocol Capability & Evasion Matrix
//!
//! Evaluates protocol evasion traits, overhead characteristics, and resistance
//! ratings across known censorship evasion primitives.
//! Ported and enhanced from aturl/awesome-anti-gfw.

use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvasionCapability {
    TlsFingerprintSpoofing,
    RecordPadding,
    SniFragmentation,
    MultipathUdp,
    EarlyDataReplayDefense,
    TcpDesyncImmunity,
    DnsPoisonResistance,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProtocolProfile {
    pub name: String,
    pub capabilities: HashSet<EvasionCapability>,
    pub overhead_ratio: f32,
    pub resistance_score: u32,
}

#[derive(Debug, Clone)]
pub struct ProtocolCapabilityMatrix {
    profiles: Vec<ProtocolProfile>,
}

impl Default for ProtocolCapabilityMatrix {
    fn default() -> Self {
        let mut matrix = Self { profiles: Vec::new() };
        matrix.populate_standard_profiles();
        matrix
    }
}

impl ProtocolCapabilityMatrix {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn populate_standard_profiles(&mut self) {
        // Hysteria 2 / QUIC
        let mut hy2_caps = HashSet::new();
        hy2_caps.insert(EvasionCapability::MultipathUdp);
        hy2_caps.insert(EvasionCapability::RecordPadding);
        hy2_caps.insert(EvasionCapability::TlsFingerprintSpoofing);
        self.profiles.push(ProtocolProfile {
            name: "Hysteria2".to_string(),
            capabilities: hy2_caps,
            overhead_ratio: 1.08,
            resistance_score: 95,
        });

        // VLESS-XTLS-Reality
        let mut reality_caps = HashSet::new();
        reality_caps.insert(EvasionCapability::TlsFingerprintSpoofing);
        reality_caps.insert(EvasionCapability::EarlyDataReplayDefense);
        reality_caps.insert(EvasionCapability::RecordPadding);
        self.profiles.push(ProtocolProfile {
            name: "VLESS-Reality".to_string(),
            capabilities: reality_caps,
            overhead_ratio: 1.02,
            resistance_score: 92,
        });

        // Shadowsocks-2022
        let mut ss2022_caps = HashSet::new();
        ss2022_caps.insert(EvasionCapability::EarlyDataReplayDefense);
        ss2022_caps.insert(EvasionCapability::RecordPadding);
        self.profiles.push(ProtocolProfile {
            name: "Shadowsocks-2022".to_string(),
            capabilities: ss2022_caps,
            overhead_ratio: 1.03,
            resistance_score: 80,
        });

        // Trojan-Go with SNI Fragmentation
        let mut trojan_frag_caps = HashSet::new();
        trojan_frag_caps.insert(EvasionCapability::SniFragmentation);
        trojan_frag_caps.insert(EvasionCapability::TcpDesyncImmunity);
        trojan_frag_caps.insert(EvasionCapability::TlsFingerprintSpoofing);
        self.profiles.push(ProtocolProfile {
            name: "Trojan-SNI-Fragment".to_string(),
            capabilities: trojan_frag_caps,
            overhead_ratio: 1.05,
            resistance_score: 88,
        });
    }

    pub fn register_protocol(&mut self, profile: ProtocolProfile) {
        self.profiles.retain(|p| p.name != profile.name);
        self.profiles.push(profile);
    }

    pub fn recommend_protocol(&self, required: &[EvasionCapability]) -> Option<ProtocolProfile> {
        let req_set: HashSet<EvasionCapability> = required.iter().copied().collect();
        let mut matching: Vec<&ProtocolProfile> = self
            .profiles
            .iter()
            .filter(|p| req_set.is_subset(&p.capabilities))
            .collect();

        // Sort by resistance score desc, then overhead asc
        matching.sort_by(|a, b| {
            b.resistance_score
                .cmp(&a.resistance_score)
                .then_with(|| a.overhead_ratio.partial_cmp(&b.overhead_ratio).unwrap())
        });

        matching.first().map(|p| (*p).clone())
    }

    pub fn get_score(&self, proto_name: &str) -> Option<u32> {
        self.profiles.iter().find(|p| p.name == proto_name).map(|p| p.resistance_score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_matrix_recommendation() {
        let matrix = ProtocolCapabilityMatrix::default();
        let required = vec![EvasionCapability::MultipathUdp];
        let rec = matrix.recommend_protocol(&required).unwrap();
        assert_eq!(rec.name, "Hysteria2");
        assert_eq!(rec.resistance_score, 95);

        let sni_req = vec![EvasionCapability::SniFragmentation];
        let rec2 = matrix.recommend_protocol(&sni_req).unwrap();
        assert_eq!(rec2.name, "Trojan-SNI-Fragment");
    }
}
