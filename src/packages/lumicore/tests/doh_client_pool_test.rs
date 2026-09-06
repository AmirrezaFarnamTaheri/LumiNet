use lumicore::dns::{
    find_sni_hostname_offset, split_client_hello, validate_doh_response,
};

#[test]
fn test_validate_doh_response() {
    // Valid minimal DNS response (12 bytes, QR flag bit = 1: 0x81 0x80)
    let valid_resp = vec![
        0x12, 0x34, // ID
        0x81, 0x80, // Flags (QR=1, RD=1, RA=1)
        0x00, 0x01, // QDCOUNT
        0x00, 0x01, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    assert!(validate_doh_response(&valid_resp).is_ok());

    // Query packet (QR bit = 0: 0x01 0x00)
    let query_pkt = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Flags (QR=0)
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert!(validate_doh_response(&query_pkt).is_err());

    // Truncated packet
    assert!(validate_doh_response(&[0x12, 0x34]).is_err());
}

#[test]
fn test_find_sni_hostname_offset_and_sni_split() {
    // Construct a synthetic ClientHello with an SNI extension
    let mut hello = Vec::new();
    // 1. Record Header (5 bytes)
    hello.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x00]); // length placeholder at [3..5]

    // 2. Handshake Header (4 bytes)
    let hs_start = hello.len();
    hello.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // handshake type ClientHello (0x01)

    // 3. Client Version (2 bytes)
    hello.extend_from_slice(&[0x03, 0x03]);

    // 4. Client Random (32 bytes)
    hello.extend_from_slice(&[0x42; 32]);

    // 5. Session ID (1 byte len + 0 bytes)
    hello.push(0x00);

    // 6. Cipher Suites (2 bytes len + 2 bytes cipher)
    hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);

    // 7. Compression Methods (1 byte len + 1 byte method)
    hello.extend_from_slice(&[0x01, 0x00]);

    // 8. Extensions
    let sni_hostname = b"cloudflare.com";
    let sni_ext_data_len = 2 + 1 + 2 + sni_hostname.len(); // list_len (2) + type (1) + host_len (2) + host
    let mut ext_buf = Vec::new();
    // Extension Type 0x0000 (SNI)
    ext_buf.extend_from_slice(&[0x00, 0x00]);
    ext_buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    // ServerNameList length
    ext_buf.extend_from_slice(&((sni_hostname.len() + 3) as u16).to_be_bytes());
    // NameType host_name (0)
    ext_buf.push(0x00);
    // HostName length
    ext_buf.extend_from_slice(&(sni_hostname.len() as u16).to_be_bytes());
    // HostName
    ext_buf.extend_from_slice(sni_hostname);

    hello.extend_from_slice(&(ext_buf.len() as u16).to_be_bytes());
    hello.extend_from_slice(&ext_buf);

    // Fix record length and handshake length
    let hs_len = (hello.len() - hs_start - 4) as u32;
    hello[hs_start + 1] = ((hs_len >> 16) & 0xFF) as u8;
    hello[hs_start + 2] = ((hs_len >> 8) & 0xFF) as u8;
    hello[hs_start + 3] = (hs_len & 0xFF) as u8;

    let rec_len = (hello.len() - 5) as u16;
    hello[3] = (rec_len >> 8) as u8;
    hello[4] = (rec_len & 0xFF) as u8;

    // Scan for SNI offset
    let found = find_sni_hostname_offset(&hello);
    assert!(found.is_some());
    let (offset, len) = found.unwrap();
    assert_eq!(len, sni_hostname.len());
    assert_eq!(&hello[offset..offset + len], sni_hostname);

    // Test sni_split strategy
    let frags = split_client_hello(&hello, "sni_split");
    assert_eq!(frags.len(), 2);
    let mut reconstructed = Vec::new();
    for f in frags {
        reconstructed.extend_from_slice(&f);
    }
    assert_eq!(reconstructed, hello);
}

#[test]
fn test_split_client_hello_strategies() {
    let payload = b"12345678901234567890123456789012345678901234567890";

    // Half
    let half_frags = split_client_hello(payload, "half");
    assert_eq!(half_frags.len(), 2);
    assert_eq!(half_frags[0].len(), payload.len() / 2);
    assert_eq!([half_frags[0].as_slice(), half_frags[1].as_slice()].concat(), payload);

    // Multi (24-byte chunks)
    let multi_frags = split_client_hello(payload, "multi");
    assert_eq!(multi_frags.len(), 3); // 24 + 24 + 2 = 50
    let mut rec = Vec::new();
    for f in multi_frags {
        rec.extend_from_slice(&f);
    }
    assert_eq!(rec.as_slice(), payload);
}
