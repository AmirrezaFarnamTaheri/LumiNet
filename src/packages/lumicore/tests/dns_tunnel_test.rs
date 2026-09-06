use lumicore::transport::dns_tunnel::{
    base32_decode, base32_encode, DNSTunnel, DnsTunnelConfig, DnsTunnelPreset,
    DNS_TYPE_NULL, DNS_TYPE_TXT, MAX_DNS_LABEL_LEN,
};

#[test]
fn test_dns_tunnel_base32_roundtrip() {
    let payload = b"secret covert DNS packets with numbers 1234567890 and symbols !@#$%^&*()";
    let encoded = base32_encode(payload);
    let decoded = base32_decode(&encoded).expect("valid base32");
    assert_eq!(decoded, payload);
}

#[test]
fn test_dns_tunnel_presets() {
    let avg = DnsTunnelConfig::from_preset(DnsTunnelPreset::IranAverage, "t.example.com");
    assert_eq!(avg.upload_duplication, 3);
    assert_eq!(avg.download_duplication, 7);
    assert_eq!(avg.min_upload_mtu, 40);

    let low_mtu = DnsTunnelConfig::from_preset(DnsTunnelPreset::IranLowMtu, "t.example.com");
    assert_eq!(low_mtu.upload_duplication, 4);
    assert_eq!(low_mtu.min_upload_mtu, 20);
    assert_eq!(low_mtu.max_download_mtu, 768);
}

#[test]
fn test_dns_tunnel_query_crafting() {
    let config = DnsTunnelConfig::from_preset(DnsTunnelPreset::IranAverage, "tunnel.internal");
    let tunnel = DNSTunnel::new(config);

    let raw_data = b"client_request_chunk_1";
    let qname = tunnel.format_query_name(raw_data).expect("format qname");
    assert!(qname.ends_with(".tunnel.internal"));

    // Label length constraint verification
    for label in qname.split('.') {
        assert!(label.len() <= MAX_DNS_LABEL_LEN);
    }

    let packet = tunnel
        .build_query_packet(0xABCD, &qname, DNS_TYPE_TXT)
        .expect("build query");

    assert_eq!(&packet[0..2], &[0xAB, 0xCD]); // Tx ID
    assert_eq!(&packet[2..4], &[0x01, 0x00]); // Standard query + RD

    let null_packet = tunnel
        .build_query_packet(0xABCD, &qname, DNS_TYPE_NULL)
        .expect("build null query");
    assert_eq!(&null_packet[0..2], &[0xAB, 0xCD]);
}

#[test]
fn test_dns_tunnel_null_record_roundtrip() {
    let config = DnsTunnelConfig::default();
    let tunnel = DNSTunnel::new(config);

    let mut resp = Vec::new();
    // Header: ID=0x5555, Response, NoError, QD=1, AN=1
    resp.extend_from_slice(&[0x55, 0x55, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    // Question: "q.com"
    resp.extend_from_slice(&[0x01, b'q', 0x03, b'c', b'o', b'm', 0x00]);
    resp.extend_from_slice(&[0x00, 0x0A, 0x00, 0x01]); // Type NULL (10), Class IN

    // Answer: pointer 0xC00C
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&[0x00, 0x0A, 0x00, 0x01]); // Type NULL, Class IN
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60s

    let raw_payload = b"raw binary null payload data";
    resp.extend_from_slice(&(raw_payload.len() as u16).to_be_bytes());
    resp.extend_from_slice(raw_payload);

    let extracted = tunnel.extract_response_payload(&resp).expect("extracted payload");
    assert_eq!(extracted, raw_payload);
}
