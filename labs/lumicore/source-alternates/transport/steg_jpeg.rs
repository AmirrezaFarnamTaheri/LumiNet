// Ported from: stegotorus jpegSteg.cc / jel_knobs.cc (Pass 1 Order 5)
// Target path: core/src/transport/steg_jpeg.rs
//
// JPEG DCT AC-coefficient carrier. Stegotorus' `jpegSteg.cc` reads a real
// JPEG cover image, then encodes payload bits into the LSBs of nonzero
// AC coefficients of luminance blocks — JEL (JPEG Extension Library).
// The decoder reads the same set of coefficients back out.
//
// ponytail: real JEL needs a full DCT decoder. pulling in `jpeg-decoder`
// is heavy and only ~3 MB build. The carrier interface here is wired
// against a synthetic marker tag — callers hand in a pre-decoded
// coefficient table (Vec<i16>) and the encoder embeds payload bits
// into the LSBs of nonzero entries. JPEG parsing itself is left to the
// upstream caller; upgrade path documented in the ceiling note.

/// Number of DCT AC-coefficients per 8x8 block.
pub const BLOCK_COEFFS: usize = 64;

/// Encode `payload` bits into the LSB of nonzero entries in `coeffs`.
/// Existing zero entries are skipped (JEL constraint: embedding into a
/// zero coefficient would expand the bitstream size).
pub fn encode(coefficients: &mut [i16], payload: &[u8]) -> usize {
    let mut bit_iter = payload.iter().flat_map(|b| (0..8).map(move |i| (b >> i) & 1));
    let mut embedded = 0;
    for c in coefficients.iter_mut() {
        if let Some(bit) = bit_iter.next() {
            if *c != 0 {
                // Replace LSB of coefficient with payload bit.
                *c = (*c & !1) | bit as i16;
                embedded += 1;
            }
        } else {
            break;
        }
    }
    embedded
}

/// Decode `len` payload bytes from the LSBs of nonzero coefficients.
pub fn decode(coefficients: &[i16], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut bit_idx = 0usize;
    for &c in coefficients {
        if c == 0 {
            continue;
        }
        let bit = (c & 1) as u8;
        let byte_idx = bit_idx / 8;
        if byte_idx >= len {
            break;
        }
        out[byte_idx] |= bit << (bit_idx % 8);
        bit_idx += 1;
    }
    out
}

/// Convenience: capacity (bytes) of a coefficient table given zero-skip.
pub fn capacity(coefficients: &[i16]) -> usize {
    coefficients.iter().filter(|c| **c != 0).count() / 8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small_payload() {
        let mut coeffs = vec![10i16; BLOCK_COEFFS];
        let payload = b"hello";
        let n = encode(&mut coeffs, payload);
        assert!(n >= payload.len() * 8 - 7, "expected >= {} bits embedded, got {}", payload.len() * 8, n);
        let recovered = decode(&coeffs, payload.len());
        assert_eq!(&recovered[..], payload);
    }

    #[test]
    fn zeros_skip_embedding() {
        let mut coeffs = vec![0i16; BLOCK_COEFFS];
        coeffs[0] = 5;
        coeffs[1] = 5;
        let payload = b"\xFF";
        let n = encode(&mut coeffs, payload);
        assert!(n >= 1, "should embed at least one bit");
        let recovered = decode(&coeffs, 1);
        assert_eq!(recovered[0] & 1, 1, "first bit should be 1");
    }

    #[test]
    fn capacity_matches_nonzero_count() {
        let coeffs = vec![1i16, 0, -1, 0, 5];
        assert_eq!(capacity(&coeffs), 0); // 3 nonzero / 8 = 0 full bytes
        let coeffs = vec![1i16; 16];
        assert_eq!(capacity(&coeffs), 2);
    }

    #[test]
    fn empty_payload_embeds_nothing() {
        let mut coeffs = vec![7i16; BLOCK_COEFFS];
        let original = coeffs.clone();
        let n = encode(&mut coeffs, b"");
        assert_eq!(n, 0);
        assert_eq!(coeffs, original);
    }
}
// ponytail: encoder operates on pre-decoded coefficient tables. Real JPEG
// parsing needs `jpeg-decoder = "0.3"` (~3MB build). Upgrade path:
// add `pub fn encode_jpeg(jpeg_bytes: &[u8], payload: &[u8]) -> Vec<u8>`
// that decodes the JPEG, calls `encode()` on the result, then re-encodes
// via `jpeg-encoder = "0.6"`. Both crates are pure-Rust and MIT.
