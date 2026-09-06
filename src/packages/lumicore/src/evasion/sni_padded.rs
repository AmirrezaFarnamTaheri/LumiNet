//! # RFC 7685 Constant-Size Padded TLS ClientHello Generator
//!
//! Generates deterministic 517-byte TLS ClientHello packets regardless of SNI length.
//! Defeats DPI packet-length profiling and fingerprinting.
//! Ported and elevated from `sni-spoofing-rust-main`.

pub const CLIENT_HELLO_CONSTANT_SIZE: usize = 517;
pub const EXTENSION_SERVER_NAME: u16 = 0x0000;
pub const EXTENSION_PADDING: u16 = 0x0015; // RFC 7685

/// Builds a deterministic TLS 1.3 ClientHello of exactly `CLIENT_HELLO_CONSTANT_SIZE` bytes (517 bytes).
///
/// If `sni` length exceeds maximum padding capacity (> 215 bytes), an error is returned.
pub fn build_padded_client_hello(sni: &str) -> Result<Vec<u8>, &'static str> {
    let sni_bytes = sni.as_bytes();
    if sni_bytes.is_empty() {
        return Err("SNI must not be empty");
    }
    if sni_bytes.len() > 215 {
        return Err("SNI too long for constant 517-byte ClientHello");
    }

    // Baseline unpadded ClientHello without SNI or Padding extensions
    // Record Header (5) + Handshake Header (4) + Version (2) + Random (32)
    // + Session ID (1 + 32) + Cipher Suites (2 + 4) + Compression (1 + 1) + Extensions Length (2)
    // Standard base length = 84 bytes.
    //
    // SNI extension structure:
    // ext_type (2) + ext_len (2) + list_len (2) + name_type (1) + name_len (2) + name (sni_len)
    // = 9 + sni_len.
    //
    // Other modern TLS 1.3 extensions:
    // - Supported Groups (8)
    // - EC Point Formats (6)
    // - Signature Algorithms (16)
    // - Supported Versions (7)
    // - Key Share (X25519) (42)
    // Base extensions total ~ 180 bytes.
    //
    // RFC 7685 Padding extension structure:
    // ext_type (2) + ext_len (2) + padding_zeros (pad_len)
    // = 4 + pad_len.

    let mut extensions = Vec::with_capacity(400);

    // 1. SNI Extension (0x0000)
    let sni_ext_len = (5 + sni_bytes.len()) as u16;
    extensions.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
    extensions.extend_from_slice(&sni_ext_len.to_be_bytes());
    extensions.extend_from_slice(&((3 + sni_bytes.len()) as u16).to_be_bytes()); // list len
    extensions.push(0x00); // host_name type
    extensions.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    extensions.extend_from_slice(sni_bytes);

    // 2. Supported Versions (0x002B) -> TLS 1.3 (0x0304), TLS 1.2 (0x0303)
    extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);

    // 3. Supported Groups (0x000A) -> X25519 (0x001D), secp256r1 (0x0017)
    extensions.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);

    // 4. Key Share (0x0033) -> X25519 public key (32 bytes zeroed/dummy)
    extensions.extend_from_slice(&[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    extensions.extend_from_slice(&[0xaa; 32]);

    // 5. Signature Algorithms (0x000D)
    extensions.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
    ]);

    // Fixed pre-padding record + handshake size calculation
    // Record header: 5 bytes
    // Handshake header: 4 bytes
    // Total fixed prefix = 5 (record) + 4 (handshake) + 2 (version) + 32 (random)
    // + 33 (session_id) + 6 (ciphers) + 2 (compression) + 2 (extensions_len) = 86 bytes.
    let base_len = 86 + extensions.len();
    if base_len + 4 > CLIENT_HELLO_CONSTANT_SIZE {
        return Err("Payload exceeds constant size limit");
    }

    let pad_len = CLIENT_HELLO_CONSTANT_SIZE - (base_len + 4);
    // Append Padding Extension (0x0015)
    extensions.extend_from_slice(&EXTENSION_PADDING.to_be_bytes());
    extensions.extend_from_slice(&(pad_len as u16).to_be_bytes());
    extensions.resize(extensions.len() + pad_len, 0x00);

    // Build the complete ClientHello frame
    let mut packet = Vec::with_capacity(CLIENT_HELLO_CONSTANT_SIZE);

    // TLS Record Header (5 bytes)
    packet.push(0x16); // ContentType: Handshake
    packet.extend_from_slice(&[0x03, 0x01]); // Legacy TLS 1.0 version
    let record_payload_len = (CLIENT_HELLO_CONSTANT_SIZE - 5) as u16;
    packet.extend_from_slice(&record_payload_len.to_be_bytes());

    // Handshake Header (4 bytes)
    packet.push(0x01); // HandshakeType: ClientHello
    let handshake_len = (CLIENT_HELLO_CONSTANT_SIZE - 9) as u32;
    packet.push((handshake_len >> 16) as u8);
    packet.push((handshake_len >> 8) as u8);
    packet.push(handshake_len as u8);

    // Client Version (2 bytes)
    packet.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

    // Client Random (32 bytes)
    packet.extend_from_slice(&[0x55; 32]);

    // Legacy Session ID (1 + 32 bytes)
    packet.push(32);
    packet.extend_from_slice(&[0x77; 32]);

    // Cipher Suites (2 + 4 bytes): TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
    packet.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);

    // Compression Methods (1 + 1 bytes): null compression
    packet.extend_from_slice(&[0x01, 0x00]);

    // Extensions Length (2 bytes)
    packet.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    packet.extend_from_slice(&extensions);

    assert_eq!(packet.len(), CLIENT_HELLO_CONSTANT_SIZE);
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padded_client_hello_exact_length_across_snis() {
        let test_snis = [
            "a.com",
            "cloudflare.com",
            "very-long-subdomain-for-testing-purposes.irancell.ir",
            "edge.google.com",
            "t.me",
        ];

        for sni in test_snis {
            let pkt = build_padded_client_hello(sni).expect("build should succeed");
            assert_eq!(pkt.len(), CLIENT_HELLO_CONSTANT_SIZE);
            assert_eq!(pkt[0], 0x16); // Handshake
            assert_eq!(pkt[5], 0x01); // ClientHello
        }
    }
}
