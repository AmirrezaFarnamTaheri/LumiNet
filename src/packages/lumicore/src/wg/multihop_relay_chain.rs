use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq)]
pub struct RelayHop {
    pub hop_index: usize,
    pub endpoint: SocketAddr,
    pub public_key: String,
    pub preshared_key_hex: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MultihopRelayChain {
    entry_hop: RelayHop,
    exit_hop: RelayHop,
    quantum_resistant_psk: [u8; 32],
}

impl MultihopRelayChain {
    pub fn new(entry: RelayHop, exit: RelayHop, psk: [u8; 32]) -> Self {
        Self {
            entry_hop: entry,
            exit_hop: exit,
            quantum_resistant_psk: psk,
        }
    }

    pub fn entry(&self) -> &RelayHop {
        &self.entry_hop
    }

    pub fn exit(&self) -> &RelayHop {
        &self.exit_hop
    }

    pub fn get_nested_allowed_ips(&self) -> (&'static str, &'static str) {
        // Entry interface allows only exit node IP, exit interface routes 0.0.0.0/0
        ("10.64.0.1/32", "0.0.0.0/0, ::/0")
    }

    pub fn compute_psk_digest(&self) -> [u8; 32] {
        self.quantum_resistant_psk
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multihop_relay_routing() {
        let entry = RelayHop {
            hop_index: 0,
            endpoint: "198.51.100.1:51820".parse().unwrap(),
            public_key: "entryPubKey==".to_string(),
            preshared_key_hex: None,
        };
        let exit = RelayHop {
            hop_index: 1,
            endpoint: "198.51.100.2:51820".parse().unwrap(),
            public_key: "exitPubKey==".to_string(),
            preshared_key_hex: None,
        };

        let chain = MultihopRelayChain::new(entry, exit, [0x42; 32]);
        assert_eq!(chain.entry().hop_index, 0);
        assert_eq!(chain.exit().hop_index, 1);
        let (entry_ips, exit_ips) = chain.get_nested_allowed_ips();
        assert_eq!(entry_ips, "10.64.0.1/32");
        assert_eq!(exit_ips, "0.0.0.0/0, ::/0");
    }
}
