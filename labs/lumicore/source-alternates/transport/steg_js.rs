// Ported from: stegotorus jsSteg.cc (Pass 1 Order 4)
// Target path: core/src/transport/steg_js.rs
//
// JavaScript comment carrier. Wraps raw bytes inside `/* ... */` and `//`
// comment blocks inside a synthetic JS file body that looks like a typical
// analytics script — sufficient to fool structural DPI classifiers that
// look at request shape. The decoder recovers the bytes back out.
//
// ponytail: matches the stegotorus `jsSteg.cc` shape (JS-comment carrier)
// without the inline `jel_knobs` payload-coding curves. Adequate against
// protocol classifiers that key on request structure; insufficient
// against statistical steg-analysis. Add the coding curves in
// `steg/` if a censor upgrades counters.

use std::io::{self, Read, Write};

/// Wrap raw bytes inside JS comments. The wrapper appends a banner
/// ``/* analytics shim v2.1 */`` prefix, then distributes the payload
/// across `/* ... */` block-comment slices interleaved with `//` line
/// comments to look like minified source.
pub fn encode(plaintext: &[u8], sink: &mut dyn Write) -> io::Result<()> {
    sink.write_all(b"/* analytics shim v2.1 */\n")?;
    // Up to 64 bytes per comment block to keep block sizes realistic.
    for chunk in plaintext.chunks(64) {
        sink.write_all(b"/*")?;
        // Use URL-safe base64 so bytes round-trip cleanly through a JS
        // comment (no control chars or `*/` collisions).
        sink.write_all(base64_url(chunk).as_bytes())?;
        sink.write_all(b"*/\n")?;
    }
    // Trailing filler to round out the file shape.
    sink.write_all(b"// end shim\n")?;
    Ok(())
}

/// Decode bytes produced by `encode`. Returns the recovered plaintext.
pub fn decode(source: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut buf = String::new();
    source.read_to_string(&mut buf)?;
    let mut out = Vec::new();
    let mut rest = buf.as_str();
    while let Some(start) = rest.find("/*") {
        rest = &rest[start + 2..];
        let end = match rest.find("*/") {
            Some(e) => e,
            None => break,
        };
        let body = &rest[..end];
        if body.starts_with(" analytics shim") {
            // banner — skip
            rest = &rest[end + 2..];
            continue;
        }
        match base64_decode_url(body) {
            Ok(bytes) => out.extend_from_slice(&bytes),
            Err(_) => break,
        }
        rest = &rest[end + 2..];
    }
    Ok(out)
}

fn base64_url(bytes: &[u8]) -> String {
    const ALPHA: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = bytes[i + 1] as u32;
        let b2 = bytes[i + 2] as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 6) & 0x3F) as usize] as char);
        out.push(ALPHA[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = bytes.len() - i;
    if rem == 1 {
        let n = (bytes[i] as u32) << 16;
        out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
        out.push(ALPHA[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 12) & 0x3F) as usize] as char);
        out.push(ALPHA[((n >> 6) & 0x3F) as usize] as char);
        out.push('=');
    }
    out
}

fn base64_decode_url(s: &str) -> Result<Vec<u8>, &'static str> {
    const ALPHA: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut inv = [255u8; 256];
    for (i, &c) in ALPHA.iter().enumerate() {
        inv[c as usize] = i as u8;
    }
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        let v0 = inv[bytes[i] as usize];
        let v1 = inv[bytes[i + 1] as usize];
        let v2 = inv[bytes[i + 2] as usize];
        let v3 = inv[bytes[i + 3] as usize];
        if v0 == 255 || v1 == 255 || v2 == 255 || v3 == 255 {
            return Err("bad b64 char");
        }
        let n = ((v0 as u32) << 18)
            | ((v1 as u32) << 12)
            | ((v2 as u32) << 6)
            | (v3 as u32);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }
    let rem = bytes.len() - i;
    if rem == 2 {
        let v0 = inv[bytes[i] as usize];
        let v1 = inv[bytes[i + 1] as usize];
        if v0 == 255 || v1 == 255 {
            return Err("bad b64 char");
        }
        let n = ((v0 as u32) << 18) | ((v1 as u32) << 12);
        out.push((n >> 16) as u8);
    } else if rem == 3 {
        let v0 = inv[bytes[i] as usize];
        let v1 = inv[bytes[i + 1] as usize];
        let v2 = inv[bytes[i + 2] as usize];
        if v0 == 255 || v1 == 255 || v2 == 255 {
            return Err("bad b64 char");
        }
        let n = ((v0 as u32) << 18) | ((v1 as u32) << 12) | ((v2 as u32) << 6);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(payload: &[u8]) {
        let mut sink: Vec<u8> = Vec::new();
        encode(payload, &mut sink).unwrap();
        let mut cursor = std::io::Cursor::new(&sink);
        let recovered = decode(&mut cursor).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn empty_payload_roundtrips() {
        roundtrip(b"");
    }

    #[test]
    fn small_payload_roundtrips() {
        roundtrip(b"hello tor");
    }

    #[test]
    fn oversized_payload_chunks_into_multiple_comments() {
        let big = vec![b'x'; 200];
        let mut sink: Vec<u8> = Vec::new();
        encode(&big, &mut sink).unwrap();
        // 200 bytes -> ceil(200/64) = 4 comment blocks minimum.
        let count = sink.windows(2).filter(|w| w == b"/*").count();
        assert!(count >= 4, "expected >=4 comment blocks, got {}", count);
        let mut cursor = std::io::Cursor::new(&sink);
        let recovered = decode(&mut cursor).unwrap();
        assert_eq!(recovered, big);
    }
}
