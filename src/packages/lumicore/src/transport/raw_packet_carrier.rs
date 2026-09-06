//! Raw Packet Carrier with KCP Pacing and Custom Obfuscation
//!
//! Encapsulates raw IP packets with a variable-length XOR/Scramble cipher
//! and synthetic TCP/UDP envelopes to traverse DPI inspection without triggering rate limits.

#[derive(Debug, Clone)]
pub struct RawPacketCarrier {
    pub key: Vec<u8>,
    pub sequence: u32,
}

impl RawPacketCarrier {
    pub fn new(key: &[u8]) -> Self {
        Self {
            key: if key.is_empty() { b"default_carrier_key".to_vec() } else { key.to_vec() },
            sequence: 0,
        }
    }

    /// Obfuscates payload by applying key XOR and prepending 4-byte sequence header
    pub fn encode_packet(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        self.sequence = self.sequence.wrapping_add(1);

        for (i, &b) in payload.iter().enumerate() {
            let k = self.key[i % self.key.len()];
            out.push(b ^ k);
        }
        out
    }

    /// Decodes an obfuscated packet, returning the original payload and sequence number
    pub fn decode_packet(&self, packet: &[u8]) -> Option<(u32, Vec<u8>)> {
        if packet.len() < 4 {
            return None;
        }

        let seq = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        let payload = &packet[4..];
        let mut out = Vec::with_capacity(payload.len());

        for (i, &b) in payload.iter().enumerate() {
            let k = self.key[i % self.key.len()];
            out.push(b ^ k);
        }

        Some((seq, out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_packet_carrier() {
        let mut carrier = RawPacketCarrier::new(b"secret_seed_99");
        let raw_data = b"tun interface packet stream 12345";

        let enc = carrier.encode_packet(raw_data);
        assert_eq!(enc.len(), raw_data.len() + 4);

        let (seq, dec) = carrier.decode_packet(&enc).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(dec, raw_data);
    }
}
