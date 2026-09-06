// SPDX-License-Identifier: MIT
//
// Deep-link subscription-URL codec: encode subscription URLs into
// `incy://crypt1/<base64url>` deep links (and back) using AES-256-GCM.
//
// that file). LumiNet does not ship the upstream's per-installation
// keymat (the 8 KiB of base64 `KEYMAT_A_B64` + `KEYMAT_B_B64` asset
// bytes) - that material is the actual obfuscation value, and the
// upstream itself documents that it can be reconstructed from the
// shipped INCY clients anyway. Instead, this module ports the
// *algorithm* and *wire format* with a caller-supplied 32-byte key
// so a LumiNet user can either:
//
//   1. Hard-code the upstream keymat via derive_key_from_keymat() to
//      round-trip with INCY iOS/Android/Desktop clients, or
//   2. Plug in their own 32-byte key for a private scheme.
//
// Wire format (all base64url, no padding):
//   `incy://crypt1/<base64url( iv(12) || ciphertext || gcm_tag(16) )>`
//
// Plaintext JSON shape (sortedCompactJson):
//   { "url": "<subscription-url>", "v": 1, "n"?: "<display-name>" }

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

pub const SCHEME: &str = "incy";
pub const HOST: &str = "crypt1";
pub const IV_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
/// Upstream constants used by the SHA-256 KDF. They live as four
/// separate strings in the source so a single-file grep doesn't reveal
/// the full salt at once (upstream design).
pub const SALT_P1: &[u8] = b"incy";
pub const SALT_P2: &[u8] = b"deep";
pub const SALT_P3: &[u8] = b"crypt1";
pub const SALT_P4: &[u8] = b"v2026.06";
/// Upstream keymat offsets (4 KiB opaque blobs, base64 inlined in TS).
pub const KEYMAT_A_OFFSET: usize = 1024;
pub const KEYMAT_B_OFFSET: usize = 2048;
pub const KEYMAT_KEY_LEN: usize = 32;

/// `derive_key_from_keymat` mirrors the upstream SHA-256 KDF: SHA-256
/// each 32-byte slice (with the same salt parts appended) and XOR the
/// two digests. Returns Err if either keymat is too short.
pub fn derive_key_from_keymat(keymat_a: &[u8], keymat_b: &[u8]) -> Result<[u8; KEY_LEN], &'static str> {
    if keymat_a.len() < KEYMAT_A_OFFSET + KEYMAT_KEY_LEN {
        return Err("keymat_a too short");
    }
    if keymat_b.len() < KEYMAT_B_OFFSET + KEYMAT_KEY_LEN {
        return Err("keymat_b too short");
    }
    let mut h = Sha256::new();
    h.update(&keymat_a[KEYMAT_A_OFFSET..KEYMAT_A_OFFSET + KEYMAT_KEY_LEN]);
    h.update(SALT_P1);
    h.update(SALT_P2);
    h.update(SALT_P3);
    h.update(SALT_P4);
    let half_a: [u8; 32] = h.finalize().into();
    let mut h = Sha256::new();
    h.update(&keymat_b[KEYMAT_B_OFFSET..KEYMAT_B_OFFSET + KEYMAT_KEY_LEN]);
    h.update(SALT_P1);
    h.update(SALT_P2);
    h.update(SALT_P3);
    h.update(SALT_P4);
    let half_b: [u8; 32] = h.finalize().into();
    let mut k = [0u8; KEY_LEN];
    for i in 0..KEY_LEN {
        k[i] = half_a[i] ^ half_b[i];
    }
    Ok(k)
}

/// Build the canonical sorted-key JSON payload (matches the upstream
/// `sortedCompactJson` helper).
fn sorted_compact_json(payload: &serde_json::Map<String, serde_json::Value>) -> String {
    let mut entries: Vec<_> = payload.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    let mut s = String::from("{");
    for (i, (k, v)) in entries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('"');
        s.push_str(k);
        s.push_str("\":");
        let vstr = serde_json::to_string(v).unwrap_or_else(|_| "null".to_string());
        s.push_str(&vstr);
    }
    s.push('}');
    s
}

fn build_plaintext(url: &str, name: Option<&str>) -> Result<Vec<u8>, &'static str> {
    use serde_json::json;
    if url.is_empty() {
        return Err("url is empty");
    }
    let mut m = serde_json::Map::new();
    m.insert("url".to_string(), json!(url));
    m.insert("v".to_string(), json!(1));
    if let Some(n) = name {
        if n.is_empty() {
            return Err("name is empty when provided");
        }
        if n.len() > 128 {
            return Err("name exceeds 128 bytes");
        }
        m.insert("n".to_string(), json!(n));
    }
    Ok(sorted_compact_json(&m).into_bytes())
}
/// Result of `decode_link`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLink {
    pub url: String,
    pub name: Option<String>,
}

fn encrypt_aes_gcm_256(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "aes-gcm key init")?;
    let nonce = Nonce::from_slice(iv);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "aes-gcm seal failed")?;
    let mut wire = Vec::with_capacity(IV_LEN + ct.len());
    wire.extend_from_slice(iv);
    wire.extend_from_slice(&ct);
    Ok(wire)
}

fn decrypt_aes_gcm_256(
    key: &[u8; KEY_LEN],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, &'static str> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "aes-gcm key init")?;
    let mut nonce_arr = [0u8; 12];
    if iv.len() != IV_LEN {
        return Err("iv length mismatch");
    }
    nonce_arr.copy_from_slice(iv);
    let nonce = Nonce::from(nonce_arr);
    let mut ct = ciphertext.to_vec();
    ct.extend_from_slice(tag);
    cipher
        .decrypt(&nonce, ct.as_slice())
        .map_err(|_| "aes-gcm open failed")
}

/// `encode_link` produces the canonical `incy://crypt1/<payload>` deep
/// link. `iv` must be 12 random bytes (caller's responsibility, since
/// RNG injection is a common test seam); in production use `OsRng`.
pub fn encode_link(
    key: &[u8; KEY_LEN],
    iv: &[u8; IV_LEN],
    url: &str,
    name: Option<&str>,
) -> Result<String, &'static str> {
    let pt = build_plaintext(url, name)?;
    encrypt_aes_gcm_256(key, iv, &pt).map(|wire| {
        let enc = URL_SAFE_NO_PAD.encode(&wire);
        format!("{SCHEME}://{HOST}/{enc}")
    })
}

/// `decode_link` parses an `incy://crypt1/<payload>` link and returns
/// the embedded subscription URL + optional name. Returns `Err` on
/// authentication failure (wrong key / tampered ciphertext).
pub fn decode_link(key: &[u8; KEY_LEN], link: &str) -> Result<DecodedLink, &'static str> {
    let prefix = format!("{SCHEME}://{HOST}/");
    let body = link
        .strip_prefix(&prefix)
        .ok_or("missing incy://crypt1/ prefix")?
        .trim_end_matches('/');
    if body.is_empty() {
        return Err("empty payload");
    }
    let wire = URL_SAFE_NO_PAD
        .decode(body.as_bytes())
        .map_err(|_| "base64url decode")?;
    if wire.len() < IV_LEN + TAG_LEN + 1 {
        return Err("payload too short");
    }
    let iv = &wire[..IV_LEN];
    let body = &wire[IV_LEN..];
    let tag = &body[body.len() - TAG_LEN..];
    let ct = &body[..body.len() - TAG_LEN];
    let pt = decrypt_aes_gcm_256(key, iv, ct, tag)?;
    let val: serde_json::Value = serde_json::from_slice(&pt).map_err(|_| "malformed json")?;
    let obj = val.as_object().ok_or("plaintext is not an object")?;
    let url = obj
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("missing url field")?;
    if url.is_empty() {
        return Err("empty url");
    }
    let name = obj
        .get("n")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    Ok(DecodedLink {
        url: url.to_string(),
        name,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_LEN] {
        // Deterministic test key, NOT the upstream production keymat.
        let mut k = [0u8; KEY_LEN];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        k
    }

    fn test_iv() -> [u8; IV_LEN] {
        [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
    }

    #[test]
    fn keymat_kdf_is_deterministic_and_different_from_a() {
        // Build a 2 * 4 KiB buffer pair at the upstream offsets.
        let mut a = vec![0u8; KEYMAT_A_OFFSET + KEYMAT_KEY_LEN + 8];
        let mut b = vec![0u8; KEYMAT_B_OFFSET + KEYMAT_KEY_LEN + 8];
        for (i, x) in a.iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(3);
        }
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8).wrapping_add(7);
        }
        let k1 = derive_key_from_keymat(&a, &b).unwrap();
        let k2 = derive_key_from_keymat(&a, &b).unwrap();
        assert_eq!(k1, k2);
        assert_ne!(k1, [0u8; KEY_LEN]);
    }

    #[test]
    fn keymat_kdf_rejects_short_blobs() {
        let short = vec![0u8; 100];
        let long = vec![0u8; 8192];
        assert!(derive_key_from_keymat(&short, &long).is_err());
        assert!(derive_key_from_keymat(&long, &short).is_err());
    }

    #[test]
    fn encode_decode_roundtrip_without_name() {
        let key = test_key();
        let iv = test_iv();
        let url = "vless://abcdef@host.example.com:443?type=tcp#my-server";
        let link = encode_link(&key, &iv, url, None).unwrap();
        assert!(link.starts_with("incy://crypt1/"));
        let out = decode_link(&key, &link).unwrap();
        assert_eq!(out.url, url);
        assert_eq!(out.name, None);
    }

    #[test]
    fn encode_decode_roundtrip_with_name() {
        let key = test_key();
        let iv = test_iv();
        let url = "ss://YWVzLTI1Ni1nY206cGFzcw@host:8388#name";
        let link = encode_link(&key, &iv, url, Some("My Server 1")).unwrap();
        let out = decode_link(&key, &link).unwrap();
        assert_eq!(out.url, url);
        assert_eq!(out.name.as_deref(), Some("My Server 1"));
    }

    #[test]
    fn decode_rejects_wrong_key() {
        let key = test_key();
        let mut bad = key;
        bad[0] ^= 0x42;
        let link = encode_link(&key, &test_iv(), "vless://abc", None).unwrap();
        assert!(decode_link(&bad, &link).is_err());
    }

    #[test]
    fn decode_rejects_missing_prefix() {
        let key = test_key();
        let err = decode_link(&key, "https://example.com").unwrap_err();
        assert!(err.contains("prefix"));
    }

    #[test]
    fn decode_rejects_truncated_body() {
        let key = test_key();
        let link = encode_link(&key, &test_iv(), "vless://abc", None).unwrap();
        // chop the last 5 base64url chars
        let truncated = link[..link.len() - 5].to_string();
        assert!(decode_link(&key, &truncated).is_err());
    }

    #[test]
    fn name_validation_rejects_empty_and_oversize() {
        let key = test_key();
        let iv = test_iv();
        assert!(encode_link(&key, &iv, "vless://x", Some("")).is_err());
        let big = "a".repeat(200);
        assert!(encode_link(&key, &iv, "vless://x", Some(&big)).is_err());
    }

    #[test]
    fn wire_format_starts_with_iv_and_ends_with_tag() {
        // Wire layout: `iv(12) || ciphertext(plaintext) || tag(16)`.
        // We can't predict the exact ciphertext size (it depends on the
        // JSON envelope length), so verify the two fixed end markers.
        let key = test_key();
        let iv = test_iv();
        let url = "vless://abc";
        let link = encode_link(&key, &iv, url, None).unwrap();
        let body = link.strip_prefix("incy://crypt1/").unwrap();
        let wire = URL_SAFE_NO_PAD.decode(body.as_bytes()).unwrap();
        // IV prefix matches.
        assert_eq!(&wire[..IV_LEN], &iv[..]);
        // Tail is the 16-byte GCM tag - flipping a single bit at the tag
        // position must cause decryption to fail (this is the property
        // the upstream relies on for tamper detection).
        let last = wire.len() - 1;
        let mut tampered = wire;
        tampered[last] ^= 0x01;
        let tampered_b64 = URL_SAFE_NO_PAD.encode(&tampered);
        let tampered_link = format!("incy://crypt1/{tampered_b64}");
        assert!(decode_link(&key, &tampered_link).is_err());
    }
}
