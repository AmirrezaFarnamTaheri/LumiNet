use lumicore::evasion::tls_fragmenter::{TlsFragmentStrategy, TlsFragmenter};

fn create_sample_client_hello(sni: &str) -> Vec<u8> {
    let mut data = Vec::new();
    // TLS Record Header: Handshake (0x16), TLS 1.0 (0x03, 0x01), Length placeholder
    data.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x00]);

    // Handshake: ClientHello (0x01), Length placeholder
    let hs_start = data.len();
    data.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    // Client Version: TLS 1.2 (0x03, 0x03)
    data.extend_from_slice(&[0x03, 0x03]);

    // Random: 32 bytes
    data.extend_from_slice(&[0xAA; 32]);

    // Session ID: 0 length
    data.push(0x00);

    // Cipher Suites: 2 suites (4 bytes)
    data.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);

    // Compression: 1 method (null)
    data.extend_from_slice(&[0x01, 0x00]);

    // Extensions length placeholder
    let ext_len_idx = data.len();
    data.extend_from_slice(&[0x00, 0x00]);

    let ext_start = data.len();

    // SNI Extension: Type 0x0000
    data.extend_from_slice(&[0x00, 0x00]);
    let sni_bytes = sni.as_bytes();
    let server_name_list_len = (sni_bytes.len() + 3) as u16;
    let ext_data_len = (sni_bytes.len() + 5) as u16;

    data.extend_from_slice(&ext_data_len.to_be_bytes());
    data.extend_from_slice(&server_name_list_len.to_be_bytes());
    data.push(0x00); // HostName type
    data.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    data.extend_from_slice(sni_bytes);

    // Finalize extension length
    let total_ext_len = (data.len() - ext_start) as u16;
    data[ext_len_idx..ext_len_idx + 2].copy_from_slice(&total_ext_len.to_be_bytes());

    // Finalize handshake length
    let hs_body_len = (data.len() - hs_start - 4) as u32;
    data[hs_start + 1] = ((hs_body_len >> 16) & 0xFF) as u8;
    data[hs_start + 2] = ((hs_body_len >> 8) & 0xFF) as u8;
    data[hs_start + 3] = (hs_body_len & 0xFF) as u8;

    // Finalize record length
    let record_len = (data.len() - 5) as u16;
    data[3..5].copy_from_slice(&record_len.to_be_bytes());

    data
}

#[test]
fn test_tls_fragmenter_locate_sni() {
    let packet = create_sample_client_hello("restricted-target.com");
    let (offset, len) = TlsFragmenter::locate_sni(&packet).expect("locate sni");

    assert_eq!(len, "restricted-target.com".len());
    let extracted = &packet[offset..offset + len];
    assert_eq!(extracted, b"restricted-target.com");
}

#[test]
fn test_tls_fragmenter_fixed_chunks() {
    let packet = create_sample_client_hello("youtube.com");
    let chunks = TlsFragmenter::fragment(&packet, TlsFragmentStrategy::FixedChunks(20));

    assert!(chunks.len() > 1);
    for chunk in &chunks {
        assert!(chunk.len() <= 20);
    }

    let reconstructed: Vec<u8> = chunks.into_iter().flatten().collect();
    assert_eq!(reconstructed, packet);
}

#[test]
fn test_tls_fragmenter_sni_split() {
    let packet = create_sample_client_hello("target.com");
    let chunks = TlsFragmenter::fragment(&packet, TlsFragmentStrategy::SniSplit);

    assert_eq!(chunks.len(), 2);
    let reconstructed: Vec<u8> = chunks.into_iter().flatten().collect();
    assert_eq!(reconstructed, packet);
}

#[test]
fn test_tls_fragmenter_finalmask() {
    let packet = create_sample_client_hello("blocked-service.org");
    let chunks = TlsFragmenter::fragment(
        &packet,
        TlsFragmentStrategy::FinalMaskTlsHello {
            record1_payload_len: 10,
        },
    );

    assert_eq!(chunks.len(), 2);
    // Each fragment must be a valid TLS record header (0x16, 0x03, 0x01)
    assert_eq!(chunks[0][0], 0x16);
    assert_eq!(chunks[1][0], 0x16);
}
