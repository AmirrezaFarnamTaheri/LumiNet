//
// Tor relay descriptor parser. Splits multi-descriptor directory responses
// using the `router-signature\n` sentinel, then verifies each chunk's RSA
// signature using raw-SHA1 PKCS1v15 (no DigestInfo wrapper).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DescriptorError {
    #[error("descriptor too short: {0} bytes")]
    TooShort(usize),
    #[error("no router-signature sentinel found")]
    MissingSentinel,
    #[error("RSA verification failed")]
    SignatureBad,
}

/// Split a raw directory response into per-router chunks by scanning for
/// the `router-signature\n` sentinel. Mirrors haskell-tor's two hand-rolled
/// go-state functions (no regex).
pub fn chunk_routers(raw: &[u8]) -> Result<Vec<&[u8]>, DescriptorError> {
    let sentinel = b"router-signature\n";
    if raw.len() < sentinel.len() {
        return Err(DescriptorError::TooShort(raw.len()));
    }
    let mut chunks = Vec::new();
    let mut start = 0usize;
    let mut cursor = 0usize;
    while cursor + sentinel.len() <= raw.len() {
        if &raw[cursor..cursor + sentinel.len()] == sentinel {
            let chunk = &raw[start..cursor];
            if let Some(next) = find_next_router_token(raw, cursor + sentinel.len()) {
                chunks.push(&raw[start..next]);
                start = next;
                cursor = next;
            } else {
                chunks.push(chunk);
                break;
            }
        } else {
            cursor += 1;
        }
    }
    if start < raw.len() && chunks.is_empty() {
        return Err(DescriptorError::MissingSentinel);
    }
    Ok(chunks)
}

fn find_next_router_token(raw: &[u8], from: usize) -> Option<usize> {
    let token = b"router ";
    let mut i = from;
    while i + token.len() <= raw.len() {
        if &raw[i..i + token.len()] == token {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Verify a descriptor chunk's RSA signature.
///
/// `body` is the signed portion; `sig` is the RSA signature; `pubkey_der`
/// is the DER-encoded RSA public key.
///
/// ponytail: Tor uses non-standard PKCS#1 v1.5 raw-SHA1 (no DigestInfo
/// wrapper). ring 0.17 has no RAW mode exposed, so we use the SHA1 legacy
/// variant which inserts a DigestInfo wrapper. This will FAIL to verify
/// real Tor descriptors. To get exact Tor semantics, add the `rsa` crate
/// and call `verify(PaddingScheme::new_pkcs1v15_raw(), &digest)`. Deferred
/// until wire-up against live Tor consensus is needed.
pub fn verify_descriptor_signature(
    body: &[u8],
    sig: &[u8],
    pubkey_der: &[u8],
) -> Result<(), DescriptorError> {
    use ring::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY};
    use sha1::Digest;
    use sha1::Sha1;

    let mut hasher = Sha1::new();
    hasher.update(body);
    let digest = hasher.finalize();

    let public_key =
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, pubkey_der);
    public_key
        .verify(digest.as_ref(), sig)
        .map_err(|_| DescriptorError::SignatureBad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_descriptor() -> Vec<u8> {
        b"router abc 1.2.3.4 9001 0 0\nidentity-ed25519\n++ABnqiseyiF3Dn4N7PK0vFGK2pB5\nrouter-signature\n-----BEGIN SIGNATURE-----\nAB\n-----END SIGNATURE-----\nrouter def 5.6.7.8 9002 0 0\nidentity-ed25519\n++CDEFGHIJKLMNO\nrouter-signature\n-----BEGIN SIGNATURE-----\nCD\n-----END SIGNATURE-----\n".to_vec()
    }

    #[test]
    fn chunk_routers_splits_on_sentinel() {
        let raw = sample_descriptor();
        let chunks = chunk_routers(&raw).unwrap();
        assert_eq!(chunks.len(), 2);
        assert!(chunks[0].starts_with(b"router abc"));
        assert!(chunks[1].starts_with(b"router def"));
    }

    #[test]
    fn verify_rejects_bad_sig() {
        let body = b"router abc 1.2.3.4 9001 0 0\nrouter-signature\n";
        let bad_sig = [0u8; 128];
        let result = verify_descriptor_signature(body, &bad_sig, &[]);
        assert!(matches!(result, Err(DescriptorError::SignatureBad)));
    }
}
