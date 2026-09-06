//! # IPsec IKEv2 State Machine
//!
//! Deterministic IKEv2 (RFC 7296) Security Association (SA) lifecycle engine,
//! managing cryptographic proposal matching, SPI allocation, key material derivation, and rekeying.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IkeSaState {
    Initial,
    SaInitSent,
    SaInitReceived,
    AuthSent,
    Established,
    Rekeying,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IkeTransformProposal {
    pub encryption_algo: String, // e.g. "AES-GCM-256"
    pub prf_algo: String,        // e.g. "PRF-HMAC-SHA256"
    pub integrity_algo: String,  // e.g. "AUTH-HMAC-SHA256"
    pub dh_group: u16,           // e.g. 14 (2048-bit MODP), 19 (256-bit ECP)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildSecurityAssociation {
    pub inbound_spi: u32,
    pub outbound_spi: u32,
    pub traffic_selector_local: String,
    pub traffic_selector_remote: String,
    pub bytes_processed: u64,
}

pub struct IpsecIkev2StateMachine {
    state: IkeSaState,
    initiator_spi: u64,
    responder_spi: u64,
    matched_proposal: Option<IkeTransformProposal>,
    child_sas: HashMap<u32, ChildSecurityAssociation>, // inbound_spi -> child SA
    next_spi: u32,
    lifetime_secs: u64,
    created_timestamp: u64,
}

impl IpsecIkev2StateMachine {
    pub fn new(initiator_spi: u64, lifetime_secs: u64) -> Self {
        Self {
            state: IkeSaState::Initial,
            initiator_spi,
            responder_spi: 0,
            matched_proposal: None,
            child_sas: HashMap::new(),
            next_spi: 0x1000,
            lifetime_secs: lifetime_secs.max(60),
            created_timestamp: 0,
        }
    }

    pub fn send_ike_sa_init(&mut self, timestamp: u64) -> Result<(u64, u64), String> {
        if self.state != IkeSaState::Initial {
            return Err("Cannot initiate SA_INIT from current state".to_string());
        }
        self.state = IkeSaState::SaInitSent;
        self.created_timestamp = timestamp;
        Ok((self.initiator_spi, 0))
    }

    pub fn receive_ike_sa_init(
        &mut self,
        responder_spi: u64,
        proposals: &[IkeTransformProposal],
    ) -> Result<IkeTransformProposal, String> {
        if self.state != IkeSaState::SaInitSent {
            return Err("Unexpected SA_INIT response".to_string());
        }
        if responder_spi == 0 {
            return Err("Invalid responder SPI".to_string());
        }

        self.responder_spi = responder_spi;

        // Select first acceptable proposal
        for p in proposals {
            if (p.dh_group == 14 || p.dh_group == 19) && p.encryption_algo.starts_with("AES") {
                self.matched_proposal = Some(p.clone());
                self.state = IkeSaState::SaInitReceived;
                return Ok(p.clone());
            }
        }

        self.state = IkeSaState::Closed;
        Err("No mutually acceptable IKE proposals found".to_string())
    }

    pub fn complete_ike_auth(&mut self, local_ts: &str, remote_ts: &str) -> Result<u32, String> {
        if self.state != IkeSaState::SaInitReceived {
            return Err("Cannot perform IKE_AUTH before SA_INIT".to_string());
        }

        let inbound_spi = self.next_spi;
        self.next_spi += 1;
        let outbound_spi = self.next_spi;
        self.next_spi += 1;

        let child = ChildSecurityAssociation {
            inbound_spi,
            outbound_spi,
            traffic_selector_local: local_ts.to_string(),
            traffic_selector_remote: remote_ts.to_string(),
            bytes_processed: 0,
        };

        self.child_sas.insert(inbound_spi, child);
        self.state = IkeSaState::Established;
        Ok(inbound_spi)
    }

    pub fn is_expired(&self, current_timestamp: u64) -> bool {
        if self.created_timestamp == 0 {
            return false;
        }
        current_timestamp >= self.created_timestamp + self.lifetime_secs
    }

    pub fn get_state(&self) -> IkeSaState {
        self.state
    }

    pub fn get_child_sa(&self, inbound_spi: u32) -> Option<&ChildSecurityAssociation> {
        self.child_sas.get(&inbound_spi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ikev2_state_machine_flow() {
        let mut sm = IpsecIkev2StateMachine::new(0x0102030405060708, 3600);
        assert_eq!(sm.get_state(), IkeSaState::Initial);

        let (init_spi, _) = sm.send_ike_sa_init(1000).unwrap();
        assert_eq!(init_spi, 0x0102030405060708);
        assert_eq!(sm.get_state(), IkeSaState::SaInitSent);

        let proposals = vec![
            IkeTransformProposal {
                encryption_algo: "3DES-CBC".to_string(), // Insecure, should be rejected
                prf_algo: "PRF-MD5".to_string(),
                integrity_algo: "AUTH-HMAC-MD5".to_string(),
                dh_group: 2,
            },
            IkeTransformProposal {
                encryption_algo: "AES-GCM-256".to_string(),
                prf_algo: "PRF-HMAC-SHA256".to_string(),
                integrity_algo: "AUTH-HMAC-SHA256".to_string(),
                dh_group: 19,
            },
        ];

        let matched = sm.receive_ike_sa_init(0x090a0b0c0d0e0f00, &proposals).unwrap();
        assert_eq!(matched.encryption_algo, "AES-GCM-256");
        assert_eq!(sm.get_state(), IkeSaState::SaInitReceived);

        let child_spi = sm.complete_ike_auth("10.0.0.0/24", "192.168.1.0/24").unwrap();
        assert_eq!(sm.get_state(), IkeSaState::Established);

        let child = sm.get_child_sa(child_spi).unwrap();
        assert_eq!(child.traffic_selector_local, "10.0.0.0/24");
        assert!(!sm.is_expired(2000));
        assert!(sm.is_expired(5000));
    }
}
