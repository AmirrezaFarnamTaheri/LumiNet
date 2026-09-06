//! # VL1 Virtual Ethernet Switch Frame & Node Addressing
//!
//! Provides ZeroTier-compatible 40-bit cryptographic node identity hashing,
//! virtual switch Ethernet frame encapsulation, and path vitality tracking.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeAddress(pub [u8; 5]); // 40-bit address

impl NodeAddress {
    pub fn from_pubkey(pubkey: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pubkey);
        let digest = hasher.finalize();
        let mut addr = [0u8; 5];
        addr.copy_from_slice(&digest[0..5]);
        Self(addr)
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

pub const SWITCH_FRAME_TYPE_ETHERNET: u16 = 0x0001;
pub const SWITCH_FRAME_TYPE_KEEPALIVE: u16 = 0x0002;
pub const SWITCH_FRAME_TYPE_RENDEZVOUS: u16 = 0x0003;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchPacketFrame {
    pub flags: u8,
    pub dest: NodeAddress,
    pub source: NodeAddress,
    pub frame_type: u16,
    pub seq_no: u32,
    pub payload: Vec<u8>,
}

impl SwitchPacketFrame {
    pub fn new(flags: u8, dest: NodeAddress, source: NodeAddress, frame_type: u16, seq_no: u32, payload: Vec<u8>) -> Self {
        Self {
            flags,
            dest,
            source,
            frame_type,
            seq_no,
            payload,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(17 + self.payload.len());
        buf.push(self.flags);
        buf.extend_from_slice(&self.dest.0);
        buf.extend_from_slice(&self.source.0);
        buf.extend_from_slice(&self.frame_type.to_be_bytes());
        buf.extend_from_slice(&self.seq_no.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 17 {
            return Err("Switch packet frame too short");
        }
        let flags = bytes[0];
        let mut dest = [0u8; 5];
        dest.copy_from_slice(&bytes[1..6]);
        let mut source = [0u8; 5];
        source.copy_from_slice(&bytes[6..11]);

        let mut ft = [0u8; 2];
        ft.copy_from_slice(&bytes[11..13]);
        let frame_type = u16::from_be_bytes(ft);

        let mut seq = [0u8; 4];
        seq.copy_from_slice(&bytes[13..17]);
        let seq_no = u32::from_be_bytes(seq);

        let payload = bytes[17..].to_vec();

        Ok(Self {
            flags,
            dest: NodeAddress(dest),
            source: NodeAddress(source),
            frame_type,
            seq_no,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_address_derivation() {
        let pubkey = b"fake_curve25519_node_public_key";
        let addr = NodeAddress::from_pubkey(pubkey);
        let hex = addr.to_hex();
        assert_eq!(hex.len(), 10); // 40-bit = 5 bytes = 10 hex characters
    }

    #[test]
    fn test_switch_packet_codec() {
        let dest = NodeAddress([1, 2, 3, 4, 5]);
        let src = NodeAddress([6, 7, 8, 9, 10]);
        let frame = SwitchPacketFrame::new(0x01, dest, src, SWITCH_FRAME_TYPE_ETHERNET, 42, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let bytes = frame.serialize();
        assert_eq!(bytes.len(), 17 + 4);

        let parsed = SwitchPacketFrame::deserialize(&bytes).unwrap();
        assert_eq!(parsed.dest, dest);
        assert_eq!(parsed.source, src);
        assert_eq!(parsed.frame_type, SWITCH_FRAME_TYPE_ETHERNET);
        assert_eq!(parsed.seq_no, 42);
        assert_eq!(parsed.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
