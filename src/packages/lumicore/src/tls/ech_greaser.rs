use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub const ECH_EXT_TYPE: u16 = 0xFE0D;

pub struct EchGreaseConfig {
    /// Seed for deterministic GREASE (for testing). None = random.
    pub seed: Option<[u8; 32]>,
    /// Minimum payload length in bytes (padded to multiple of 32).
    pub min_payload: usize,
    /// KDF algorithm ID (1 = HKDF-SHA256).
    pub kdf_id: u16,
    /// AEAD algorithm ID (1 = AES-128-GCM).
    pub aead_id: u16,
}

impl Default for EchGreaseConfig {
    fn default() -> Self {
        Self {
            seed: None,
            min_payload: 128, // realistic payload size to mimic real ECH
            kdf_id: 1,
            aead_id: 1,
        }
    }
}

/// Generates a complete ECH GREASE TLS extension (type + length + data).
/// Returns Vec<u8> ready to append to ClientHello extensions.
pub fn generate_ech_grease(cfg: &EchGreaseConfig) -> Vec<u8> {
    let mut rng: Box<dyn RngCore> = match cfg.seed {
        Some(seed) => Box::new(ChaCha20Rng::from_seed(seed)),
        None => Box::new(rand::thread_rng()),
    };

    // random config_id (1 byte)
    let config_id: u8 = rng.gen();
    // random enc (32 bytes X25519 public key)
    let mut enc = [0u8; 32];
    rng.fill_bytes(&mut enc);
    // payload: random, padded to multiple of 32
    let payload_len = pad_to_multiple(cfg.min_payload, 32);
    let mut payload = vec![0u8; payload_len];
    rng.fill_bytes(&mut payload);

    // inner = type(1) + cipher_suite(4) + config_id(1) + enc_len(2) + enc(32) + payload_len(2) + payload
    let inner_len = 1 + 4 + 1 + 2 + 32 + 2 + payload_len;
    let mut buf = Vec::with_capacity(4 + inner_len);

    // Extension type: 0xFE0D
    buf.extend_from_slice(&ECH_EXT_TYPE.to_be_bytes());
    // Extension data length
    buf.extend_from_slice(&(inner_len as u16).to_be_bytes());
    // type = outer (0)
    buf.push(0u8);
    // cipher_suite: kdf_id + aead_id
    buf.extend_from_slice(&cfg.kdf_id.to_be_bytes());
    buf.extend_from_slice(&cfg.aead_id.to_be_bytes());
    // config_id
    buf.push(config_id);
    // enc: 2-byte length + 32 bytes
    buf.extend_from_slice(&32u16.to_be_bytes());
    buf.extend_from_slice(&enc);
    // payload: 2-byte length + random bytes
    buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
    buf.extend_from_slice(&payload);

    buf
}

fn pad_to_multiple(n: usize, m: usize) -> usize {
    n.div_ceil(m) * m
}
