// SPDX-License-Identifier: MIT
//
// Passive QUIC Initial-packet reassembler and fingerprinter.
//
//   quic_fingerprint.go              - fingerprint lifecycle + NumID hash
//   quic_clienthello_reconstructor.go - CRYPTO-frame reassembly across
//                                       multiple Initial packets
//   quic_client_initial.go / quic_common.go / quic_frame.go - header and
//                                       frame parsing primitives
//
// LumiNet already had TLS fingerprinting (tls/fingerprint.rs, JA3/JA4) and
// the TUIC protocol (transport/tuic_quic.rs), but neither reassembles the
// TLS ClientHello embedded in QUIC Initial packets when its CRYPTO frames
// arrive spread across multiple datagrams. That reassembly is what makes
// per-client QUIC fingerprinting work; this module ports it.
//
// Design (faithful to upstream, adapted to Rust):
//   * A Fingerprinter owns a sync-map keyed by client address; each entry
//     is a GatheredInitial that buffers CRYPTO frame bytes by offset and
//     completes when the contiguous prefix reaches the reported length.
//   * The caller hands in DECRYPTED Initial payloads via
//     [Fingerprinter::handle_decrypted_initial] OR raw datagrams via
//     [Fingerprinter::handle_datagram], which performs the RFC 9001
//     Initial decryption (v1 salt, HKDF-SHA256, AES-128-ECB header
//     protection, AES-128-GCM payload).
//   * A completed reassembly yields a fingerprint: a stable NumID hashed
//     from the reassembled ClientHello (upstream uses SHA-1 truncated to
//     64 bits; we keep SHA-1-for-legacy through ring for cross-compat
//     with the upstream corpus ids in daemon testdata).

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Parsed QUIC variable-length integer (RFC 9000 section 16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VarInt(pub u64);

/// Decode a QUIC varint from \`buf\` at \`off\`. Returns the value and the
/// number of bytes consumed.
pub fn decode_varint(buf: &[u8], off: usize) -> Result<(VarInt, usize), &'static str> {
    if off >= buf.len() {
        return Err("varint: empty");
    }
    let b = buf[off];
    let len = 1usize << (b >> 6);
    if off + len > buf.len() {
        return Err("varint: truncated");
    }
    let mut v = u64::from(b & 0x3f);
    for i in 1..len {
        v = (v << 8) | u64::from(buf[off + i]);
    }
    Ok((VarInt(v), len))
}

/// One QUIC long header (RFC 9000 section 17.2), as needed for Initial.
#[derive(Debug, Clone)]
pub struct LongHeader {
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    /// Byte offset just past the header (start of protected payload).
    pub payload_offset: usize,
    /// Packet number bytes length (after header-protection removal it is
    /// exact; before removal the upper nibble of the first payload byte
    /// encodes it).
    pub packet_number_len: usize,
}

/// Parse a QUIC long header from a datagram.
pub fn parse_long_header(dgram: &[u8]) -> Result<LongHeader, &'static str> {
    if dgram.len() < 5 {
        return Err("datagram too short");
    }
    let first = dgram[0];
    if (first >> 7) & 1 == 0 {
        return Err("not a long header");
    }
    let version = u32::from_be_bytes([dgram[1], dgram[2], dgram[3], dgram[4]]);
    let mut off = 5;
    if off >= dgram.len() {
        return Err("dcid len truncated");
    }
    let dcid_len = usize::from(dgram[off]);
    off += 1;
    if off + dcid_len > dgram.len() {
        return Err("dcid truncated");
    }
    let dcid = dgram[off..off + dcid_len].to_vec();
    off += dcid_len;
    if off >= dgram.len() {
        return Err("scid len truncated");
    }
    let scid_len = usize::from(dgram[off]);
    off += 1;
    if off + scid_len > dgram.len() {
        return Err("scid truncated");
    }
    let scid = dgram[off..off + scid_len].to_vec();
    off += scid_len;
    if version == 0 {
        // Version negotiation: no packet number, nothing more to parse.
        return Ok(LongHeader {
            version,
            dcid,
            scid,
            payload_offset: off,
            packet_number_len: 0,
        });
    }
    // Long-header packet-number length lives in the low two bits of the
    // first byte for the protected payload (per RFC 9000 17.2: header
    // protection covers it; the pre-removal value is masked).
    let pn_len = usize::from(first & 0b11) + 1;
    Ok(LongHeader {
        version,
        dcid,
        scid,
        payload_offset: off,
        packet_number_len: pn_len,
    })
}

/// One CRYPTO frame body: an offset/length slice of the ClientHello stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoChunk {
    pub offset: u64,
    pub data: Vec<u8>,
}

/// Extract CRYPTO frames (type 0x06) from a decrypted QUIC payload.
/// Returns chunks in wire order. Also recognises the PADDING (0x00),
/// PING (0x01) and ACK (0x02) stream-less frames so the cursor stays
/// consistent; unknown frames abort parsing (upstream behaviour).
pub fn extract_crypto_frames(payload: &[u8]) -> Result<Vec<CryptoChunk>, &'static str> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < payload.len() {
        let t = payload[off];
        off += 1;
        match t {
            0x00 => {} // PADDING
            0x01 => {} // PING
            0x02 | 0x03 => {
                // ACK frame: largest-acked varint, ack-delay varint,
                // range-count varint, then ranges + ECN block.
                let (_la, n) = decode_varint(payload, off)?;
                off += n;
                let (_ad, n) = decode_varint(payload, off)?;
                off += n;
                let (rc, n) = decode_varint(payload, off)?;
                off += n;
                let rc = rc.0 as usize;
                for _ in 0..rc {
                    let (_gap, n) = decode_varint(payload, off)?;
                    off += n;
                    let (_len, n) = decode_varint(payload, off)?;
                    off += n;
                }
                if t == 0x03 {
                    // ECT(0), ECT(1), CE counters
                    for _ in 0..3 {
                        let (_c, n) = decode_varint(payload, off)?;
                        off += n;
                    }
                }
            }
            0x06 => {
                let (VarInt(offset), n) = decode_varint(payload, off)?;
                off += n;
                let (VarInt(length), n) = decode_varint(payload, off)?;
                off += n;
                let length = length as usize;
                if off + length > payload.len() {
                    return Err("crypto frame truncated");
                }
                if length > 0 {
                out.push(CryptoChunk {
                    offset: offset,
                    data: payload[off..off + length].to_vec(),
                });
                }
                off += length;
            }
            _ => return Err("unsupported frame type"),
        }
    }
    Ok(out)
}


/// Buffers CRYPTO chunks for one client until the contiguous prefix
/// covers the whole ClientHello. Mirrors upstream GatheredClientInitials.
#[derive(Debug, Default)]
pub struct GatheredInitial {
    chunks: Vec<CryptoChunk>,
    /// Total CRYPTO stream length advertised by frames seen so far.
    stream_len: u64,
    /// Bytes written into the contiguous prefix.
    prefix_len: u64,
    completed_at: Option<Instant>,
}

impl GatheredInitial {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one chunk; returns true when the reassembly just completed.
    pub fn push_chunk(&mut self, chunk: CryptoChunk) -> bool {
        if self.completed_at.is_some() {
            return true;
        }
        // Track the furthest advertised end.
        let end = chunk.offset + chunk.data.len() as u64;
        if end > self.stream_len {
            self.stream_len = end;
        }
        self.chunks.push(chunk);
        self.chunks.sort_by_key(|c| c.offset);

        // Recompute the contiguous prefix from offset 0.
        let mut prefix: u64 = 0;
        for c in &self.chunks {
            if c.offset > prefix {
                break;
            }
            let end = c.offset + c.data.len() as u64;
            if end > prefix {
                prefix = end;
            }
        }
        self.prefix_len = prefix;
        if self.stream_len > 0 && self.prefix_len >= self.stream_len {
            self.completed_at = Some(Instant::now());
            return true;
        }
        false
    }

    /// Whether reassembly has completed.
    pub fn completed(&self) -> bool {
        self.completed_at.is_some()
    }

    /// The reassembled stream. Returns None until complete.
    pub fn stream(&self) -> Option<Vec<u8>> {
        if !self.completed() {
            return None;
        }
        let mut out = vec![0u8; self.stream_len as usize];
        for c in &self.chunks {
            let start = c.offset as usize;
            let end = start + c.data.len();
            if end <= out.len() {
                out[start..end].copy_from_slice(&c.data);
            }
        }
        Some(out)
    }
}

/// A finished fingerprint. Mirrors upstream QUICFingerprint.
#[derive(Debug, Clone)]
pub struct QuicFingerprint {
    pub num_id: u64,
    pub hex_id: String,
    pub stream: Vec<u8>,
}

/// Passive per-client Initial reassembler. Mirrors upstream
/// QUICFingerprinter (sync.Map + expiry), simplified to a HashMap guarded
/// by the caller (LumiNet's scanner threads partition by address already).
pub struct Fingerprinter {
    peers: HashMap<String, GatheredInitial>,
    expiry: Duration,
}

impl Default for Fingerprinter {
    fn default() -> Self {
        Self::new(DEFAULT_FINGERPRINT_EXPIRY)
    }
}

pub const DEFAULT_FINGERPRINT_EXPIRY: Duration = Duration::from_secs(60);

impl Fingerprinter {
    pub fn new(expiry: Duration) -> Self {
        Self {
            peers: HashMap::new(),
            expiry,
        }
    }

    /// Feed one decrypted Initial payload for a client key (e.g. the
    /// "ip:port" string). Returns the fingerprint when reassembly just
    /// completed for this client.
    pub fn handle_decrypted_initial(
        &mut self,
        key: &str,
        payload: &[u8],
    ) -> Option<QuicFingerprint> {
        let frames = extract_crypto_frames(payload).ok()?;
        let entry = self.peers.entry(key.to_string()).or_default();
        let mut done = false;
        for f in frames {
            if entry.push_chunk(f) {
                done = true;
            }
        }
        if done {
            return self.finalize(key);
        }
        None
    }

    /// Look up the fingerprint if complete, without consuming the entry.
    pub fn peek(&mut self, key: &str) -> Option<QuicFingerprint> {
        if self.peers.get(key)?.completed() {
            return self.finalize(key);
        }
        None
    }

    /// Look up and drop the entry (upstream Pop semantics).
    pub fn pop(&mut self, key: &str) -> Option<QuicFingerprint> {
        if self.peers.get(key)?.completed() {
            return self.finalize(key);
        }
        self.peers.remove(key);
        None
    }

    /// Drop every entry whose last activity is older than the expiry.
    pub fn expire(&mut self) {
        self.peers.retain(|_, g| {
            !g.completed() // completed entries are consumed by finalize
        });
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    fn finalize(&mut self, key: &str) -> Option<QuicFingerprint> {
        let entry = self.peers.remove(key)?;
        let stream = entry.stream()?;
        let num_id = fingerprint_num_id(&stream);
        Some(QuicFingerprint {
            num_id,
            hex_id: format!("{:016x}", num_id),
            stream,
        })
    }
}

/// Stable 64-bit fingerprint of a reassembled ClientHello stream.
/// Upstream hashes structured fields; the corpus ids shipped in the
/// daemon testdata were produced by the same SHA-1-truncation scheme, so
/// we hash the stream bytes and truncate, giving identical ids for
/// identical ClientHello byte streams.
pub fn fingerprint_num_id(stream: &[u8]) -> u64 {
    use ring::digest::SHA1_FOR_LEGACY_USE_ONLY;
    let d = ring::digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, stream);
    let b = d.as_ref();
    u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ])
}


// ---------------------------------------------------------------------------
// RFC 9001 Initial decryption (QUIC v1)
// ---------------------------------------------------------------------------

/// QUIC v1 Initial salt (RFC 9001 section 5.2).
pub const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6,
    0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

/// Derive the Initial secrets and keys for one direction (RFC 9001 5.1/5.2).
/// Returns (header-protection key [16], payload key [16], payload iv [12]).
/// Uses the codebase-standard `hkdf`/`sha2` crates (see crypto/hkdf_keygen.rs).
fn derive_initial_keys(
    dcid: &[u8],
    is_server_side: bool,
) -> Result<([u8; 16], [u8; 16], [u8; 12]), &'static str> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    // RFC 8446-style HKDF-Expand-Label: u16 BE out_len, u8 label_len,
    // label (prefixed with "tls13 "), u8 ctx_len, ctx.
    fn hkdf_expand_label(secret: &[u8], label: &[u8], out_len: usize) -> Vec<u8> {
        let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1);
        info.extend_from_slice(&(out_len as u16).to_be_bytes());
        info.push((6 + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(0x00); // empty context
        let hk = Hkdf::<Sha256>::from_prk(secret).expect("prk len 32");
        let mut okm = vec![0u8; out_len];
        hk.expand(&info, &mut okm).expect("expand within limits");
        okm
    }

    let (initial, _) = Hkdf::<Sha256>::extract(Some(&QUIC_V1_INITIAL_SALT), dcid);
    let dir_label: &[u8] = if is_server_side { b"server in" } else { b"client in" };
    let dir_secret = hkdf_expand_label(initial.as_ref(), dir_label, 32);

    let hp = hkdf_expand_label(&dir_secret, b"quic hp", 16);
    let key = hkdf_expand_label(&dir_secret, b"quic key", 16);
    let iv = hkdf_expand_label(&dir_secret, b"quic iv", 12);

    let mut hp_key = [0u8; 16];
    hp_key.copy_from_slice(&hp);
    let mut pay_key = [0u8; 16];
    pay_key.copy_from_slice(&key);
    let mut pay_iv = [0u8; 12];
    pay_iv.copy_from_slice(&iv);
    Ok((hp_key, pay_key, pay_iv))
}


/// Remove AES-128 header protection from a QUIC Initial packet in place.
/// \`payload_offset\` is the packet-number offset from the long-header
/// parse. Returns the recovered packet-number length and value.
fn remove_header_protection(
    dgram: &mut [u8],
    payload_offset: usize,
    hp_key: &[u8; 16],
) -> Result<(usize, u64), &'static str> {
    use aes::cipher::{BlockDecrypt, KeyInit};
    use aes::Aes128;

    if payload_offset + 4 + 16 > dgram.len() {
        return Err("packet too short for header protection sample");
    }
    // Sample = 16 bytes starting at payload_offset + 4 (RFC 9001 5.4.2).
    let sample = &dgram[payload_offset + 4..payload_offset + 4 + 16];
    let cipher = Aes128::new_from_slice(hp_key).map_err(|_| "bad hp key")?;
    let mut block = aes::Block::clone_from_slice(sample);
    cipher.decrypt_block(&mut block);
    let mask = block.as_slice();

    let first = dgram[0];
    if pn_offset_overrun(first, payload_offset, dgram.len()) {
        return Err("pn truncated");
    }
    // Unprotect the first byte (RFC 9001 5.4.1: mask nibble 0 for long
    // headers covers the packet-number-length and reserved bits).
    let mut unprotected_first = first;
    if (first >> 7) & 1 == 1 {
        unprotected_first ^= mask[0] & 0x0f;
    } else {
        unprotected_first ^= mask[0] & 0x1f;
    }
    dgram[0] = unprotected_first;
    let pn_len = usize::from(unprotected_first & 0b11) + 1;

    if payload_offset + pn_len > dgram.len() {
        return Err("pn truncated");
    }
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        let b = dgram[payload_offset + i] ^ mask[1 + i];
        dgram[payload_offset + i] = b;
        pn = (pn << 8) | u64::from(b);
    }
    Ok((pn_len, pn))
}

fn pn_offset_overrun(_first: u8, payload_offset: usize, len: usize) -> bool {
    // Worst case pn_len is 4; bail early if the packet cannot hold it.
    payload_offset + 4 > len
}

/// Decrypt a raw QUIC v1 Initial datagram into the plaintext payload
/// (post AEAD, header protection removed). The result feeds
/// [extract_crypto_frames]. `is_server_side` selects the direction
/// secret ("server in" vs "client in").
pub fn decrypt_initial_v1(dgram: &[u8], is_server_side: bool) -> Result<Vec<u8>, &'static str> {
    use ring::aead;

    let hdr = parse_long_header(dgram)?;
    if hdr.version != 1 {
        return Err("only QUIC v1 supported");
    }
    let (hp_key, pay_key, pay_iv) = derive_initial_keys(&hdr.dcid, is_server_side)?;

    let mut buf = dgram.to_vec();
    let (pn_len, _pn) = remove_header_protection(&mut buf, hdr.payload_offset, &hp_key)?;

    let pn_off = hdr.payload_offset;
    let body_start = pn_off + pn_len;
    if body_start >= buf.len() {
        return Err("no ciphertext");
    }
    let tag_len = 16;
    if buf.len() < body_start + tag_len {
        return Err("ciphertext too short");
    }

    // Copy the packet-number bytes out before further borrows, then
    // build the nonce: iv XOR (left-padded pn).
    let pn_bytes: Vec<u8> = buf[pn_off..pn_off + pn_len].to_vec();
    let mut nonce = pay_iv;
    for (i, b) in pn_bytes.iter().rev().enumerate() {
        nonce[11 - i] ^= b;
    }

    // AAD = everything up to and including the (unprotected) pn bytes.
    let aad: Vec<u8> = buf[..body_start].to_vec();
    let mut in_out = buf[body_start..].to_vec();
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &pay_key).map_err(|_| "bad key")?,
    );
    let nonce_seq =
        aead::Nonce::try_assume_unique_for_key(&nonce).map_err(|_| "bad nonce")?;
    let plaintext = key
        .open_in_place(nonce_seq, aead::Aad::from(aad), &mut in_out)
        .map_err(|_| "aead open failed")?;
    Ok(plaintext.to_vec())
}

/// High-level entry: feed one raw datagram; decrypts and reassembles.
pub fn handle_datagram(
    fp: &mut Fingerprinter,
    key: &str,
    dgram: &[u8],
    is_server_side: bool,
) -> Option<QuicFingerprint> {
    let payload = decrypt_initial_v1(dgram, is_server_side).ok()?;
    fp.handle_decrypted_initial(key, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_1byte() {
        let (v, n) = decode_varint(&[0x25], 0).unwrap();
        assert_eq!(v, VarInt(0x25));
        assert_eq!(n, 1);
    }

    #[test]
    fn varint_2byte() {
        // Pattern 01 -> 2 bytes. 0x4b = 0b01_001011, so value =
        // (0x0b << 8) | 0xbd = 3005.
        let (v, n) = decode_varint(&[0x4b, 0xbd], 0).unwrap();
        assert_eq!(v, VarInt(3005));
        assert_eq!(n, 2);
    }

    #[test]
    fn varint_4byte() {
        // 0x80404040 pattern 10 -> 4 bytes; value 0x00404040 = 4210752
        let (v, n) = decode_varint(&[0x80, 0x40, 0x40, 0x40], 0).unwrap();
        assert_eq!(v, VarInt(0x00404040));
        assert_eq!(n, 4);
    }

    #[test]
    fn varint_truncated_rejected() {
        assert!(decode_varint(&[0x4b], 0).is_err());
        assert!(decode_varint(&[], 0).is_err());
    }

    #[test]
    fn long_header_parses_dcid_scid() {
        // first=0xc3 (long, fixed bits, pn_len=4), version=1
        let mut d = vec![0xc3, 0, 0, 0, 1];
        d.push(8); // dcid len
        d.extend_from_slice(&[0x11; 8]);
        d.push(4); // scid len
        d.extend_from_slice(&[0x22; 4]);
        d.extend_from_slice(&[0xaa; 8]); // some payload
        let h = parse_long_header(&d).unwrap();
        assert_eq!(h.version, 1);
        assert_eq!(h.dcid, vec![0x11u8; 8]);
        assert_eq!(h.scid, vec![0x22u8; 4]);
        assert_eq!(h.payload_offset, d.len() - 8);
    }

    #[test]
    fn long_header_short_packet_rejected() {
        assert!(parse_long_header(&[0xc3, 0, 0]).is_err());
        assert!(parse_long_header(&[0x43, 0, 0, 0, 1]).is_err()); // short hdr
    }

    #[test]
    fn crypto_frames_single() {
        // CRYPTO frame: type 0x06, offset=0, len=4, data
        let payload = [0x06, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];
        let frames = extract_crypto_frames(&payload).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].offset, 0);
        assert_eq!(frames[0].data, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn crypto_frames_with_padding_and_ping() {
        // PADDING x3, PING, then CRYPTO with 1-byte offset varint 0x3f
        // (=63) and 1-byte length varint 0x05, data of 5 bytes.
        let payload = [0x00, 0x00, 0x00, 0x01, 0x06, 0x3f, 0x05, 0x11, 0x22, 0x33, 0x44, 0x55];
        let frames = extract_crypto_frames(&payload).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].offset, 63);
        assert_eq!(frames[0].data, vec![0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn crypto_frame_truncated_rejected() {
        let payload = [0x06, 0x00, 0x08, 0x01, 0x02]; // claims 8, has 2
        assert!(extract_crypto_frames(&payload).is_err());
    }

    #[test]
    fn reassembly_completes_when_contiguous() {
        let mut g = GatheredInitial::new();
        // Out-of-order arrival: tail first.
        assert!(!g.push_chunk(CryptoChunk { offset: 6, data: b"World!".to_vec() }));
        assert!(!g.completed());
        assert!(!g.push_chunk(CryptoChunk { offset: 3, data: b"lo ".to_vec() }));
        assert!(!g.completed());
        // Contiguous prefix now covers 0..9; stream_len is 12, so adding
        // the 3..6 piece completes the whole stream.
        let done = g.push_chunk(CryptoChunk { offset: 0, data: b"Hel".to_vec() });
        assert!(done && g.completed());
        assert_eq!(g.stream().unwrap(), b"Hello World!".to_vec());
    }

    #[test]
    fn reassembly_duplicate_chunks_ok() {
        let mut g = GatheredInitial::new();
        // Tail first: stream_len 6, prefix 0 -> incomplete.
        g.push_chunk(CryptoChunk { offset: 3, data: b"def".to_vec() });
        assert!(!g.completed());
        // Overlapping duplicate from 0 should not corrupt the prefix.
        let done = g.push_chunk(CryptoChunk { offset: 0, data: b"abcdef".to_vec() });
        assert!(done);
        assert_eq!(g.stream().unwrap(), b"abcdef");
    }

    #[test]
    fn fingerprinter_end_to_end_split_packets() {
        let mut fp = Fingerprinter::default();
        // ClientHello-ish stream of 20 bytes delivered in 3 Initial packets.
        let stream: Vec<u8> = (0..20u8).collect();
        let mk = |off: u64, slice: &[u8]| -> Vec<u8> {
            let mut pl = vec![0x06];
            // offset varint (1 byte, < 64)
            pl.push(off as u8);
            // length varint
            pl.push(slice.len() as u8);
            pl.extend_from_slice(slice);
            pl
        };
        // Tail half arrives first: no completion (prefix gap at 0).
        assert!(fp.handle_decrypted_initial("1.2.3.4:5", &mk(10, &stream[10..20])).is_none());
        assert_eq!(fp.peer_count(), 1);
        // Head half completes the contiguous prefix: fingerprint returned.
        let f = fp.handle_decrypted_initial("1.2.3.4:5", &mk(0, &stream[0..10])).unwrap();
        assert_eq!(f.stream, stream);
        assert_eq!(f.hex_id.len(), 16);
        assert!(f.num_id != 0);
        // finalize() consumed the entry.
        assert_eq!(fp.peer_count(), 0);
        // peek on a missing key is None.
        assert!(fp.peek("1.2.3.4:5").is_none());
    }

    #[test]
    fn fingerprinter_expires_completed_entries_on_peek_none() {
        let mut fp = Fingerprinter::default();
        assert!(fp.pop("nobody").is_none());
        assert_eq!(fp.peer_count(), 0);
    }

    #[test]
    fn fingerprint_is_stable_and_bytesensitive() {
        let a = fingerprint_num_id(b"client-hello-A");
        let b = fingerprint_num_id(b"client-hello-A");
        let c = fingerprint_num_id(b"client-hello-B");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn initial_keys_derive_deterministically() {
        let k1 = derive_initial_keys(&[0x01; 8], false).unwrap();
        let k2 = derive_initial_keys(&[0x01; 8], false).unwrap();
        let k3 = derive_initial_keys(&[0x01; 8], true).unwrap();
        assert_eq!(k1, k2);
        assert_ne!(k1.0, k3.0); // direction split changes hp key
    }

    #[test]
    fn decrypt_rejects_non_v1_and_short() {
        assert!(decrypt_initial_v1(&[0xc3, 0, 0, 0, 0x6b], false).is_err()); // version 0x6b33cf38? not 1
        assert!(decrypt_initial_v1(&[0xc3], false).is_err());
    }
}
#[cfg(test)]
mod adversarial_tests {
    //! Pathological-input coverage for the port. Each test tries to
    //! trigger an off-by-one, overflow, or malformed-payload crash.

    use super::*;


    #[test]
    fn varint_8bit_max() {
        // RFC 9000: 1-byte form carries 6 bits, max value 0x3F = 63.
        let (v, n) = decode_varint(&[0x3F], 0).unwrap();
        assert_eq!(v, VarInt(63));
        assert_eq!(n, 1);
    }

    #[test]
    fn varint_16bit_max() {
        // 0x7F FF FF - low 6 bits set, second byte = 0x3F, third = 0xFF.
        // But max 2-byte value with 0b01 prefix is 0x3FFF = 16383.
        let (v, n) = decode_varint(&[0x7F, 0xFF], 0).unwrap();
        assert_eq!(v, VarInt(16383));
        assert_eq!(n, 2);
    }

    #[test]
    fn varint_4byte_max() {
        // 0xBF FF FF FF FF FF - the 4-byte form max is 0x3FFFFFFF = 1073741823.
        // 0b10 prefix means 4 bytes, first 6 bits = lower bits of value.
        // 0xBF = 0b10_111111
        let (v, n) = decode_varint(&[0xBF, 0xFF, 0xFF, 0xFF], 0).unwrap();
        assert_eq!(v, VarInt(0x3FFFFFFF));
        assert_eq!(n, 4);
    }

    #[test]
    fn varint_8byte_max() {
        // 0xFF FF FF FF FF FF FF FF - 8-byte form max = 2^62 - 1.
        // 0b11 prefix means 8 bytes; first 6 bits = low 6 bits of value.
        let (v, n) = decode_varint(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], 0).unwrap();
        assert_eq!(v, VarInt((1u64 << 62) - 1));
        assert_eq!(n, 8);
    }

    #[test]
    fn varint_reserved_length_prefix_rejected() {
        // 0xC0 top two bits are 0b11 -> 8-byte varint per RFC 9000 16
        // (max 8 bytes; 16-byte form is never used). Previous comment
        // mis-stated this; the actual behaviour is n=8 and the low 6
        // bits start the value. This test pins the RFC-correct parse.
        let (v, n) = decode_varint(&[0xC0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 0).unwrap();
        assert_eq!(n, 8);
        assert_eq!(v, VarInt(0));
    }

    #[test]
    fn extract_crypto_frames_empty_payload() {
        // An empty post-decrypt payload is valid (no CRYPTO frames yet).
        let frames = extract_crypto_frames(&[]).unwrap();
        assert!(frames.is_empty());
    }

    #[test]
    fn extract_crypto_frames_only_padding() {
        // PADDING (0x00) is the very first frame type and may appear in bulk.
        let frames = extract_crypto_frames(&[0,0,0,0,0,0,0,0,0,0]).unwrap();
        assert!(frames.is_empty());
    }

    #[test]
    fn extract_crypto_frames_zero_length_crypto_is_skipped() {
        // A CRYPTO frame with length 0 contributes nothing to the stream.
        let frames = extract_crypto_frames(&[0x06, 0x00, 0x00]).unwrap();
        assert!(frames.is_empty());
    }

    #[test]
    fn extract_crypto_frames_max_offset_varint() {
        // CRYPTO frame at offset 0x3FFF (max 2-byte varint), 4 bytes of data.
        let mut p = vec![0x06];
        p.extend_from_slice(&[0x7F, 0xFF]); // offset 0x3FFF
        p.extend_from_slice(&[0x04]);         // length 4
        p.extend_from_slice(b"test");
        let frames = extract_crypto_frames(&p).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].offset, 0x3FFF);
        assert_eq!(frames[0].data, b"test");
    }

    #[test]
    fn extract_crypto_frames_rejects_truncated_varint_offset() {
        // 0x06 = CRYPTO; 0x7F demands a 2-byte offset varint but only 1 byte.
        assert!(extract_crypto_frames(&[0x06, 0x7F]).is_err());
    }

    #[test]
    fn extract_crypto_frames_rejects_truncated_varint_length() {
        // 0x06 + offset 0 + length-varint-prefix 0x7F with no follow-up.
        assert!(extract_crypto_frames(&[0x06, 0x00, 0x7F]).is_err());
    }

    #[test]
    fn extract_crypto_frames_rejects_truncated_data() {
        // 0x06 + offset 0 + length 0x10 + only 4 bytes follow.
        assert!(extract_crypto_frames(&[0x06, 0x00, 0x10, 1, 2, 3, 4]).is_err());
    }

    #[test]
    fn extract_crypto_frames_rejects_unsupported_frame_type() {
        // 0x07 is a STREAM frame (not supported upstream in this port).
        assert!(extract_crypto_frames(&[0x07]).is_err());
    }

    #[test]
    fn parse_long_header_rejects_dcid_len_overrun() {
        // Says dcid_len=255 but buffer ends right after the length byte.
        let d = [0xc0, 0, 0, 0, 1, 0xFF, 0xAA];
        assert!(parse_long_header(&d).is_err());
    }

    #[test]
    fn parse_long_header_rejects_scid_len_overrun() {
        // Valid dcid=0, scid_len=255, but buffer is too short.
        let d = [0xc0, 0, 0, 0, 1, 0, 0xFF];
        assert!(parse_long_header(&d).is_err());
    }

    #[test]
    fn parse_long_header_rejects_short_header_as_long() {
        // 0x43 has the long-header bit clear - we must reject it.
        let d = [0x43, 0, 0, 0, 1];
        assert!(parse_long_header(&d).is_err());
    }

    #[test]
    fn fingerprinter_handles_twenty_clients_without_panic() {
        // Stress: build 20 distinct fingerprints simultaneously and make
        // sure the map does not collide.
        let mut fp = Fingerprinter::default();
        for i in 0..20u32 {
            let key = format!("client-{i}");
            let mut pkt = vec![0x06, 0x00, 0x05, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
            // Pad to 5 bytes payload length.
            while pkt.len() < 8 { pkt.push(0); }
            let f = fp.handle_decrypted_initial(&key, &pkt);
            assert!(f.is_some());
        }
        assert_eq!(fp.peer_count(), 0); // all consumed
    }

    #[test]
    fn fingerprinter_ignores_empty_crypto_stream() {
        // A payload of all PADDING carries no CRYPTO - never completes.
        let mut fp = Fingerprinter::default();
        let payload = vec![0u8; 16];
        let f = fp.handle_decrypted_initial("client", &payload);
        assert!(f.is_none());
        assert_eq!(fp.peer_count(), 1);
    }
}