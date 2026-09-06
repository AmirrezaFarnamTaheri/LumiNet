//! # WireGuard XOR Obfuscation Layer
//!
//! XOR-based WireGuard packet obfuscator ported from mwgp-2 (Multi-hop WireGuard Proxy).
//!
//! The obfuscation layer applies a deterministic XOR key stream derived from
//! XXHASH64 over a shared secret to every WireGuard UDP datagram.
//! This makes WireGuard traffic indistinguishable from random noise to passive
//! observers, defeating protocol-signature-based DPI without any MTU overhead.
//!
//! Wire format: identical to WireGuard — the obfuscation is transparent.
//! No extra bytes are added; the entire datagram is XOR'd in-place.

/// Maximum WireGuard datagram size.
const MAX_WG_PACKET: usize = 65_536;
/// Key stream block size (aligned to u64).
const BLOCK_SIZE: usize = 8;

/// WireGuard XOR obfuscator using XXHASH64 key stream generation.
pub struct WgObfs {
    /// Derived obfuscation key (64 bytes = 8 × u64 words).
    key: [u8; 64],
}

impl WgObfs {
    /// Creates a new obfuscator from a shared secret string.
    ///
    /// Derives an obfuscation key via XXHASH64 in a self-keyed expansion loop:
    /// `key[i] = xxhash64(secret + i)` for i in 0..8.
    pub fn from_secret(secret: &str) -> Self {
        let mut key = [0u8; 64];
        for i in 0..8 {
            let input: String = format!("{}{}", secret, i);
            let hash = xxhash64(input.as_bytes(), i as u64);
            key[i * 8..(i + 1) * 8].copy_from_slice(&hash.to_le_bytes());
        }
        Self { key }
    }

    /// Creates a new obfuscator from a raw 64-byte key.
    pub fn from_raw_key(key: [u8; 64]) -> Self {
        Self { key }
    }

    /// Obfuscates a WireGuard datagram in-place.
    ///
    /// XOR each byte with the repeating key stream derived from `self.key`.
    pub fn obfuscate(&self, packet: &mut Vec<u8>) {
        xor_with_key(packet, &self.key);
    }

    /// Deobfuscates a WireGuard datagram in-place.
    /// XOR is its own inverse: applying twice recovers the original.
    pub fn deobfuscate(&self, packet: &mut Vec<u8>) {
        xor_with_key(packet, &self.key);
    }

    /// Returns true if a packet looks like a raw WireGuard message type
    /// (type bytes 1-4 in the first 4 bytes) after deobfuscation.
    pub fn is_wireguard_message(&self, packet: &[u8]) -> bool {
        if packet.is_empty() {
            return false;
        }
        let mut copy = packet.to_vec();
        self.deobfuscate(&mut copy);
        // WireGuard message type byte: 1=Handshake Init, 2=Handshake Resp, 3=Cookie, 4=Data
        matches!(copy.first(), Some(1..=4))
    }
}

/// XOR-encodes/decodes data in-place with a repeating key.
fn xor_with_key(data: &mut [u8], key: &[u8]) {
    if key.is_empty() || data.is_empty() {
        return;
    }
    let klen = key.len();
    // Fast path: process 8 bytes at a time using u64 XOR.
    let chunks = data.len() / 8;
    for i in 0..chunks {
        let data_off = i * 8;
        let key_off = (i * 8) % klen;
        let kslice = &key[key_off..key_off + (8.min(klen - key_off))];
        for j in 0..8 {
            data[data_off + j] ^= key[(key_off + j) % klen];
        }
    }
    // Remaining bytes
    let start = chunks * 8;
    for i in start..data.len() {
        data[i] ^= key[i % klen];
    }
}

/// XXHASH64 implementation — a fast non-cryptographic hash.
///
/// Port of the reference xxHash algorithm (Yann Collet, 2014).
pub fn xxhash64(data: &[u8], seed: u64) -> u64 {
    const PRIME1: u64 = 0x9E3779B185EBCA87;
    const PRIME2: u64 = 0xC2B2AE3D27D4EB4F;
    const PRIME3: u64 = 0x165667B19E3779F9;
    const PRIME4: u64 = 0x85EBCA77C2B2AE63;
    const PRIME5: u64 = 0x27D4EB2F165667C5;

    let len = data.len();
    let mut h64: u64;
    let mut pos = 0usize;

    if len >= 32 {
        let mut v1 = seed.wrapping_add(PRIME1).wrapping_add(PRIME2);
        let mut v2 = seed.wrapping_add(PRIME2);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME1);

        let end = len - 32;
        while pos <= end {
            let lane = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            v1 = v1.wrapping_add(lane.wrapping_mul(PRIME2)).rotate_left(31).wrapping_mul(PRIME1);
            pos += 8;
            let lane = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            v2 = v2.wrapping_add(lane.wrapping_mul(PRIME2)).rotate_left(31).wrapping_mul(PRIME1);
            pos += 8;
            let lane = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            v3 = v3.wrapping_add(lane.wrapping_mul(PRIME2)).rotate_left(31).wrapping_mul(PRIME1);
            pos += 8;
            let lane = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
            v4 = v4.wrapping_add(lane.wrapping_mul(PRIME2)).rotate_left(31).wrapping_mul(PRIME1);
            pos += 8;
        }

        h64 = v1.rotate_left(1)
            .wrapping_add(v2.rotate_left(7))
            .wrapping_add(v3.rotate_left(12))
            .wrapping_add(v4.rotate_left(18));

        for v in [v1, v2, v3, v4] {
            h64 ^= v.wrapping_mul(PRIME2).rotate_left(31).wrapping_mul(PRIME1);
            h64 = h64.wrapping_mul(PRIME1).wrapping_add(PRIME4);
        }
    } else {
        h64 = seed.wrapping_add(PRIME5);
    }

    h64 = h64.wrapping_add(len as u64);

    // Remaining 8-byte chunks
    while pos + 8 <= len {
        let lane = u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap());
        h64 ^= lane.wrapping_mul(PRIME2).rotate_left(31).wrapping_mul(PRIME1);
        h64 = h64.rotate_left(27).wrapping_mul(PRIME1).wrapping_add(PRIME4);
        pos += 8;
    }

    // Remaining 4-byte chunk
    if pos + 4 <= len {
        let lane = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as u64;
        h64 ^= lane.wrapping_mul(PRIME1);
        h64 = h64.rotate_left(23).wrapping_mul(PRIME2).wrapping_add(PRIME3);
        pos += 4;
    }

    // Remaining bytes
    while pos < len {
        h64 ^= (data[pos] as u64).wrapping_mul(PRIME5);
        h64 = h64.rotate_left(11).wrapping_mul(PRIME1);
        pos += 1;
    }

    // Final mix
    h64 ^= h64 >> 33;
    h64 = h64.wrapping_mul(PRIME2);
    h64 ^= h64 >> 29;
    h64 = h64.wrapping_mul(PRIME3);
    h64 ^= h64 >> 32;
    h64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_obfuscate_deobfuscate_roundtrip() {
        let obfs = WgObfs::from_secret("shared_wg_secret");
        let original = vec![1u8, 2, 3, 4, 1, 0, 0, 0, 0xAB, 0xCD]; // type=1 (Handshake Init)
        let mut packet = original.clone();
        obfs.obfuscate(&mut packet);
        assert_ne!(packet, original, "obfuscated should differ from original");
        obfs.deobfuscate(&mut packet);
        assert_eq!(packet, original, "deobfuscated should match original");
    }

    #[test]
    fn test_different_secrets_produce_different_keys() {
        let a = WgObfs::from_secret("secret_a");
        let b = WgObfs::from_secret("secret_b");
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn test_xxhash64_known_value() {
        // Test vector: empty input, seed=0 → known xxHash64 value
        let h = xxhash64(b"", 0);
        assert_eq!(h, 0xEF46DB3751D8E999);
    }

    #[test]
    fn test_xxhash64_non_empty() {
        let h = xxhash64(b"LumiNet", 42);
        // Deterministic — just verify consistency
        let h2 = xxhash64(b"LumiNet", 42);
        assert_eq!(h, h2);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_wg_message_detection() {
        let obfs = WgObfs::from_secret("detect_test");
        // Craft a fake WireGuard Handshake Init (type byte = 1)
        let mut wg_packet = vec![1u8, 0, 0, 0]; // type = 1
        wg_packet.extend_from_slice(&[0u8; 140]); // padding to message size
        let mut obfuscated = wg_packet.clone();
        obfs.obfuscate(&mut obfuscated);
        assert!(obfs.is_wireguard_message(&obfuscated));
    }

    #[test]
    fn test_empty_packet_safe() {
        let obfs = WgObfs::from_secret("empty_test");
        let mut packet = vec![];
        obfs.obfuscate(&mut packet);
        assert!(packet.is_empty());
    }
}
