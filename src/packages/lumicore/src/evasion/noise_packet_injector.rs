#[derive(Debug, Clone)]
pub struct NoisePattern {
    pub min_padding: usize,
    pub max_padding: usize,
    pub header_magic: Vec<u8>,
}

impl Default for NoisePattern {
    fn default() -> Self {
        Self {
            min_padding: 8,
            max_padding: 64,
            header_magic: vec![0x17, 0x03, 0x03], // TLS 1.2 application data mimic
        }
    }
}

#[derive(Debug)]
pub struct NoisePacketInjector {
    pattern: NoisePattern,
}

impl NoisePacketInjector {
    pub fn new(pattern: NoisePattern) -> Self {
        Self { pattern }
    }

    pub fn synthesize_noise_frame(&self, seed: u64) -> Vec<u8> {
        let span = self.pattern.max_padding.saturating_sub(self.pattern.min_padding).max(1);
        let pad_len = self.pattern.min_padding + ((seed as usize) % span);
        let mut frame = self.pattern.header_magic.clone();
        
        let length_bytes = (pad_len as u16).to_be_bytes();
        frame.extend_from_slice(&length_bytes);

        // Pseudorandom payload deterministic from seed
        let mut cur = seed;
        for _ in 0..pad_len {
            cur = cur.wrapping_mul(6364136223846793005).wrapping_add(1);
            frame.push((cur >> 32) as u8);
        }

        frame
    }

    pub fn prepend_noise(&self, payload: &[u8], seed: u64) -> (Vec<u8>, Vec<u8>) {
        let noise = self.synthesize_noise_frame(seed);
        (noise, payload.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_packet_injection() {
        let injector = NoisePacketInjector::new(NoisePattern::default());
        let (noise, orig) = injector.prepend_noise(b"handshake-packet", 12345);

        assert!(!noise.is_empty());
        assert_eq!(noise[0..3], [0x17, 0x03, 0x03]);
        assert_eq!(orig, b"handshake-packet");
    }
}
