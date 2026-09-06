//! TCP Desync RST and FIN State Machine Poisoner
//!
//! Generates out-of-order fake TCP RST / FIN packets with corrupt checksums or
//! TTL manipulation to confuse stateful DPI firewalls without terminating genuine endpoint sockets.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesyncTactic {
    FakeRst,
    FakeFin,
    CorruptedChecksum,
    SplitPayload,
}

#[derive(Debug, Clone)]
pub struct TcpDesyncPoisoner {
    pub tactic: DesyncTactic,
    pub fake_ttl: u8,
}

impl Default for TcpDesyncPoisoner {
    fn default() -> Self {
        Self {
            tactic: DesyncTactic::FakeRst,
            fake_ttl: 4, // Short TTL drops before reaching server, poisoning local DPI
        }
    }
}

impl TcpDesyncPoisoner {
    pub fn new(tactic: DesyncTactic, fake_ttl: u8) -> Self {
        Self { tactic, fake_ttl }
    }

    /// Synthesizes a 20-byte fake TCP header with specified flags and sequence number
    pub fn create_poison_header(&self, src_port: u16, dst_port: u16, seq: u32, ack: u32) -> Vec<u8> {
        let mut hdr = vec![0u8; 20];
        hdr[0..2].copy_from_slice(&src_port.to_be_bytes());
        hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
        hdr[4..8].copy_from_slice(&seq.to_be_bytes());
        hdr[8..12].copy_from_slice(&ack.to_be_bytes());
        hdr[12] = 0x50; // Data offset: 5 * 4 = 20 bytes

        let flags = match self.tactic {
            DesyncTactic::FakeRst => 0x04, // RST
            DesyncTactic::FakeFin => 0x01, // FIN
            DesyncTactic::CorruptedChecksum | DesyncTactic::SplitPayload => 0x18, // PSH + ACK
        };
        hdr[13] = flags;
        hdr[14..16].copy_from_slice(&65535u16.to_be_bytes()); // Window size

        if self.tactic == DesyncTactic::CorruptedChecksum {
            hdr[16..18].copy_from_slice(&0xDEADu16.to_be_bytes()); // Bad checksum
        }

        hdr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_desync_poisoner() {
        let poisoner = TcpDesyncPoisoner::new(DesyncTactic::FakeRst, 3);
        let hdr = poisoner.create_poison_header(12345, 443, 1000, 2000);

        assert_eq!(hdr.len(), 20);
        assert_eq!(hdr[13], 0x04); // RST flag
        assert_eq!(u16::from_be_bytes([hdr[0], hdr[1]]), 12345);
        assert_eq!(u16::from_be_bytes([hdr[2], hdr[3]]), 443);
    }
}
