//! # Hardened IPsec & IKEv2 Proposal Profile Builder
//!
//! Provides cryptographically hardened IKEv2 and IPsec ESP cipher suite proposals,
//! Diffie-Hellman group parameters, and NAT-Traversal keepalive packet generation.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    Aes256Gcm16,
    ChaCha20Poly1305,
    Aes256Cbc,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityAlgorithm {
    Sha384,
    Sha512,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhGroup {
    Modp3072, // Group 15
    Modp4096, // Group 16
    Curve25519, // Group 31
    Ecp384,   // Group 20
}

#[derive(Debug, Clone)]
pub struct Ikev2Proposal {
    pub enc: EncryptionAlgorithm,
    pub prf: IntegrityAlgorithm,
    pub dh: DhGroup,
    pub lifetime_seconds: u32,
}

#[derive(Debug, Clone)]
pub struct EspProposal {
    pub enc: EncryptionAlgorithm,
    pub auth: IntegrityAlgorithm,
    pub dh: Option<DhGroup>,
    pub lifetime_seconds: u32,
}

#[derive(Debug, Clone)]
pub struct IpsecProfile {
    pub ike_proposals: Vec<Ikev2Proposal>,
    pub esp_proposals: Vec<EspProposal>,
    pub nat_traversal_keepalive_seconds: u32,
    pub dpd_delay_seconds: u32,
    pub dpd_timeout_seconds: u32,
}

impl IpsecProfile {
    pub fn build_hardened_profile() -> Self {
        Self {
            ike_proposals: vec![
                Ikev2Proposal {
                    enc: EncryptionAlgorithm::Aes256Gcm16,
                    prf: IntegrityAlgorithm::Sha384,
                    dh: DhGroup::Curve25519,
                    lifetime_seconds: 14400,
                },
                Ikev2Proposal {
                    enc: EncryptionAlgorithm::ChaCha20Poly1305,
                    prf: IntegrityAlgorithm::Sha512,
                    dh: DhGroup::Modp3072,
                    lifetime_seconds: 14400,
                },
            ],
            esp_proposals: vec![
                EspProposal {
                    enc: EncryptionAlgorithm::Aes256Gcm16,
                    auth: IntegrityAlgorithm::Sha384,
                    dh: Some(DhGroup::Curve25519),
                    lifetime_seconds: 3600,
                },
                EspProposal {
                    enc: EncryptionAlgorithm::ChaCha20Poly1305,
                    auth: IntegrityAlgorithm::Sha512,
                    dh: Some(DhGroup::Modp3072),
                    lifetime_seconds: 3600,
                },
            ],
            nat_traversal_keepalive_seconds: 20,
            dpd_delay_seconds: 30,
            dpd_timeout_seconds: 120,
        }
    }

    /// Generates RFC 3948 NAT-Keepalive payload (single byte 0xFF sent on UDP 4500)
    pub fn build_nat_keepalive_packet() -> [u8; 1] {
        [0xFF]
    }

    /// Formats StrongSwan / Libreswan proposal string
    pub fn to_ike_proposal_string(&self) -> String {
        let mut parts = Vec::new();
        for p in &self.ike_proposals {
            let enc_str = match p.enc {
                EncryptionAlgorithm::Aes256Gcm16 => "aes256gcm16",
                EncryptionAlgorithm::ChaCha20Poly1305 => "chacha20poly1305",
                EncryptionAlgorithm::Aes256Cbc => "aes256",
            };
            let prf_str = match p.prf {
                IntegrityAlgorithm::Sha384 => "prfsha384",
                IntegrityAlgorithm::Sha512 => "prfsha512",
                IntegrityAlgorithm::Sha256 => "prfsha256",
            };
            let dh_str = match p.dh {
                DhGroup::Curve25519 => "curve25519",
                DhGroup::Modp3072 => "modp3072",
                DhGroup::Modp4096 => "modp4096",
                DhGroup::Ecp384 => "ecp384",
            };
            parts.push(format!("{}-{}-{}", enc_str, prf_str, dh_str));
        }
        parts.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipsec_profile_generation() {
        let profile = IpsecProfile::build_hardened_profile();
        assert_eq!(profile.nat_traversal_keepalive_seconds, 20);
        let proposal_str = profile.to_ike_proposal_string();
        assert!(proposal_str.contains("aes256gcm16-prfsha384-curve25519"));
        assert_eq!(IpsecProfile::build_nat_keepalive_packet(), [0xFF]);
    }
}
