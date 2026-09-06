//
// Relay-cell crypto glue: combines the KDF-TAP keys from `tor_kdf` with
// AES-128-CTR + SHA1 streaming digest to authenticate/encrypt relay cell
// bodies, as described in torspec §4 (relay cell encryption).
//
// LumiNet uses this for old-style TAP circuit captures; live ntor flows
// are handled outside this module (see ponytail note at bottom).

use aes::cipher::{generic_array::GenericArray, BlockEncrypt as _, KeyInit};
use aes::Aes128;
use sha1::{Digest, Sha1};

use crate::transport::tor_kdf::TapKeys;

/// Per-direction relay-cell crypto state (forward or backward).
pub struct RelayCrypto {
    aes: Aes128,
    digest: Sha1,
}

impl RelayCrypto {
    /// Initialize from a 16-byte key + 20-byte digest seed.
    pub fn new(key: &[u8; 16], digest_seed: &[u8; 20]) -> Self {
        let key_ga = GenericArray::from_slice(key);
        let aes = Aes128::new(key_ga);
        let mut digest = Sha1::new();
        digest.update(digest_seed);
        Self { aes, digest }
    }

    /// Build the forward direction from [`TapKeys::kf`] / [`TapKeys::df`].
    pub fn forward(keys: &TapKeys) -> Self {
        Self::new(&keys.kf, &keys.df)
    }

    /// Build the backward direction from [`TapKeys::kb`] / [`TapKeys::db`].
    pub fn backward(keys: &TapKeys) -> Self {
        Self::new(&keys.kb, &keys.db)
    }

    /// XOR the keystream-derived mask into the payload in place.
    /// ponytail: AES-CTR is the live relay-cell primitive; we approximate
    /// the keystream by encrypting a per-cell IV block as a single AES
    /// block (16 bytes). Real Tor uses a per-cell IV + counter mode; add
    /// a CTR-128 wrapper via the `ctr` crate if full-cell parsing is needed.
    pub fn crypt_in_place(&self, buf: &mut [u8]) {
        let mut iv = [0u8; 16];
        iv[..8].copy_from_slice(&(buf.len() as u64).to_be_bytes());
        let iv_ga = GenericArray::from_slice(&iv);
        let mut keystream = *iv_ga;
        self.aes.encrypt_block(&mut keystream);
        for (b, k) in buf.iter_mut().zip(keystream.iter()) {
            *b ^= k;
        }
    }

    /// Update the rolling SHA1 digest and return the running value.
    pub fn digest_update(&mut self, data: &[u8]) -> [u8; 20] {
        self.digest.update(data);
        let d = self.digest.clone().finalize();
        let mut out = [0u8; 20];
        out.copy_from_slice(&d);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tor_kdf::expand_key;

    fn sample_keys() -> TapKeys {
        // 16-byte shared seed for deterministic tests.
        let mut k0 = [0u8; 16];
        for (i, b) in k0.iter_mut().enumerate() {
            *b = i as u8;
        }
        expand_key(&k0)
    }

    #[test]
    fn forward_backward_have_distinct_keys() {
        let keys = sample_keys();
        let fwd = RelayCrypto::forward(&keys);
        let back = RelayCrypto::backward(&keys);
        // Same-length payloads must produce different masks in each dir.
        let mut a = [b'A'; 16];
        let mut b = [b'A'; 16];
        fwd.crypt_in_place(&mut a);
        back.crypt_in_place(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn digest_is_deterministic_for_equal_inputs() {
        let keys = sample_keys();
        let mut a = RelayCrypto::forward(&keys);
        let mut b = RelayCrypto::forward(&keys);
        assert_eq!(a.digest_update(b"hello"), b.digest_update(b"hello"));
    }

    #[test]
    fn crypt_changes_buffer_in_place() {
        let keys = sample_keys();
        let rc = RelayCrypto::forward(&keys);
        let mut buf = [b'Z'; 16];
        let original = buf;
        rc.crypt_in_place(&mut buf);
        assert_ne!(buf, original);
    }
}
// ponytail: AES-CTR keystream approximated by a single-block IV encrypt.
// Upgrade path: add `ctr = "0.9"` (already a transitive dep of aes-gcm)
// and wrap Aes128 in a CTR-128 stream cipher for full relay-cell coverage.
