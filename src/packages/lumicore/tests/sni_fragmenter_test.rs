use lumicore::transport::sni_fragmenter::{SniFragmentConfig, SniFragmenter};

fn build_mock_client_hello(sni_hostname: &str) -> Vec<u8> {
    let host_bytes = sni_hostname.as_bytes();
    let sni_ext_len = 2 + 1 + 2 + host_bytes.len(); // list_len(2) + type(1) + host_len(2) + host
    let ext_total_len = 4 + sni_ext_len; // ext_type(2) + ext_len(2) + body

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // Client version TLS 1.2/1.3
    body.extend_from_slice(&[0xAA; 32]);   // Client random
    body.push(0x00);                       // Session ID length = 0
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // 1 cipher suite (TLS_AES_128_GCM_SHA256)
    body.extend_from_slice(&[0x01, 0x00]); // Compression: null

    // Extensions
    body.extend_from_slice(&(ext_total_len as u16).to_be_bytes());
    body.extend_from_slice(&0x0000u16.to_be_bytes()); // SNI extension type
    body.extend_from_slice(&(sni_ext_len as u16).to_be_bytes()); // SNI extension length
    body.extend_from_slice(&((host_bytes.len() + 3) as u16).to_be_bytes()); // ServerNameList length
    body.push(0x00); // HostName type
    body.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes()); // HostName length
    body.extend_from_slice(host_bytes); // HostName

    // Handshake header
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    let hs_len = body.len();
    handshake.push(((hs_len >> 16) & 0xFF) as u8);
    handshake.push(((hs_len >> 8) & 0xFF) as u8);
    handshake.push((hs_len & 0xFF) as u8);
    handshake.extend_from_slice(&body);

    // TLS Record header
    let mut record = Vec::new();
    record.push(0x16); // Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record layer version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

#[test]
fn test_locate_and_extract_sni() {
    let packet = build_mock_client_hello("cloudflare.com");
    let sni = SniFragmenter::extract_sni(&packet);
    assert_eq!(sni, Some("cloudflare.com".to_string()));

    let (start, end, name) = SniFragmenter::locate_sni(&packet).expect("locate sni");
    assert_eq!(name, "cloudflare.com");
    assert_eq!(&packet[start..end], b"cloudflare.com");
}

#[test]
fn test_plan_3_zone_fragments_reconstruction() {
    let packet = build_mock_client_hello("subdomain.example.org");
    let config = SniFragmentConfig {
        before_sni_range: (2, 6),
        sni_range: (1, 3),
        after_sni_range: (4, 10),
        delay_ms_range: (1, 5),
    };

    let plan = SniFragmenter::plan_fragments(&packet, &config);
    assert_eq!(plan.detected_sni, Some("subdomain.example.org".to_string()));
    assert_eq!(plan.total_bytes, packet.len());

    // Verify all zones exist
    let has_before = plan.slices.iter().any(|s| s.zone == "before_sni");
    let has_sni = plan.slices.iter().any(|s| s.zone == "sni");
    assert!(has_before);
    assert!(has_sni);

    // Reconstruct byte for byte
    let mut reconstructed = Vec::new();
    for slice in &plan.slices {
        reconstructed.extend_from_slice(&slice.payload);
        assert!(slice.delay_ms >= 1 && slice.delay_ms <= 5);
    }
    assert_eq!(reconstructed, packet);
}

#[test]
fn test_non_tls_passthrough() {
    let plain_http = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let config = SniFragmentConfig::default();

    let plan = SniFragmenter::plan_fragments(plain_http, &config);
    assert_eq!(plan.detected_sni, None);
    assert_eq!(plan.slices.len(), 1);
    assert_eq!(plan.slices[0].zone, "passthrough");
    assert_eq!(plan.slices[0].payload, plain_http);
}
