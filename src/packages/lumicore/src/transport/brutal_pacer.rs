//! # Brutal Congestion Pacer & Salamander XOR Obfuscator
//!
//! Provides linear bandwidth pacing with loss compensation and rolling-key XOR
//! packet whitening for QUIC/UDP proxy transports.

pub struct BrutalPacer {
    target_bitrate_bps: u64,
    loss_compensation_factor: f32,
}

impl BrutalPacer {
    pub fn new(target_bitrate_bps: u64, loss_compensation_factor: f32) -> Self {
        Self {
            target_bitrate_bps,
            loss_compensation_factor: loss_compensation_factor.clamp(1.0, 3.0),
        }
    }

    /// Calculates transmission rate (bytes per second) given acknowledged loss rate (0.0 .. 1.0)
    pub fn calculate_pacing_rate_bps(&self, loss_rate: f32) -> u64 {
        let safe_loss = loss_rate.clamp(0.0, 0.9);
        // Formula: TargetBitrate * (1 + loss_rate * compensation_factor)
        let multiplier = 1.0 + (safe_loss * self.loss_compensation_factor);
        (self.target_bitrate_bps as f64 * multiplier as f64).round() as u64
    }

    /// Computes pacing interval in microseconds for a packet of given size
    pub fn packet_send_interval_micros(&self, packet_bytes: usize, loss_rate: f32) -> u64 {
        let rate_bps = self.calculate_pacing_rate_bps(loss_rate);
        if rate_bps == 0 {
            return 1000;
        }
        let packet_bits = (packet_bytes as u64) * 8;
        (packet_bits * 1_000_000) / rate_bps
    }
}

pub struct SalamanderObfuscator {
    key: Vec<u8>,
}

impl SalamanderObfuscator {
    pub fn new(secret: &[u8]) -> Self {
        let mut key = Vec::with_capacity(secret.len().max(16));
        if secret.is_empty() {
            key.extend_from_slice(b"luminet_salamander_default_key");
        } else {
            key.extend_from_slice(secret);
        }
        Self { key }
    }

    /// In-place rolling XOR obfuscation using variable salt
    pub fn obfuscate_packet(&self, packet: &mut [u8], salt: u8) {
        let key_len = self.key.len();
        for (i, byte) in packet.iter_mut().enumerate() {
            let k = self.key[(i + salt as usize) % key_len] ^ salt;
            *byte ^= k;
        }
    }

    /// De-obfuscate packet is identical to obfuscate in symmetric XOR
    pub fn deobfuscate_packet(&self, packet: &mut [u8], salt: u8) {
        self.obfuscate_packet(packet, salt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brutal_pacing_calculation() {
        let pacer = BrutalPacer::new(10_000_000, 1.5); // 10 Mbps
        let zero_loss_rate = pacer.calculate_pacing_rate_bps(0.0);
        assert_eq!(zero_loss_rate, 10_000_000);

        let ten_percent_loss = pacer.calculate_pacing_rate_bps(0.10);
        assert_eq!(ten_percent_loss, 11_500_000); // 10M * (1 + 0.15) = 11.5M

        let interval = pacer.packet_send_interval_micros(1500, 0.0);
        assert!(interval > 0);
    }

    #[test]
    fn test_salamander_xor_symmetric() {
        let obfs = SalamanderObfuscator::new(b"secret_key_hysteria");
        let original = b"Hello, Censorship-Free Internet!".to_vec();
        let mut buf = original.clone();

        obfs.obfuscate_packet(&mut buf, 42);
        assert_ne!(buf, original);

        obfs.deobfuscate_packet(&mut buf, 42);
        assert_eq!(buf, original);
    }
}
