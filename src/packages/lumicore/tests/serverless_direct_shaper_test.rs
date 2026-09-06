use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use lumicore::evasion::{
    ServerlessDirectShaper, ServerlessProfile, ServerlessShaperConfig,
};

#[test]
fn test_censorship_sink_detection() {
    let sink_v4: IpAddr = "10.10.34.1".parse().unwrap();
    let sink_v4_sub: IpAddr = "10.10.34.254".parse().unwrap();
    let normal_v4: IpAddr = "1.1.1.1".parse().unwrap();

    assert!(ServerlessDirectShaper::is_censorship_sink(&sink_v4));
    assert!(ServerlessDirectShaper::is_censorship_sink(&sink_v4_sub));
    assert!(!ServerlessDirectShaper::is_censorship_sink(&normal_v4));

    let sink_v6: IpAddr = "2001:4188:2:600::1".parse().unwrap();
    let normal_v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();

    assert!(ServerlessDirectShaper::is_censorship_sink(&sink_v6));
    assert!(!ServerlessDirectShaper::is_censorship_sink(&normal_v6));
}

#[test]
fn test_shape_client_hello_low_delay() {
    // Generate a synthetic 100-byte ClientHello
    let payload = (0..100).map(|i| (i % 256) as u8).collect::<Vec<_>>();
    let config = ServerlessShaperConfig {
        profile: ServerlessProfile::LowDelay,
        tls_record_split: 5,
        sni_split_offset: 43,
        max_split_tls: 522,
        ..Default::default()
    };

    let fragments = ServerlessDirectShaper::shape_client_hello(&payload, &config);

    assert!(fragments.len() > 2);
    // First fragment is exactly record header length 5, delay 0
    assert_eq!(fragments[0].payload.len(), 5);
    assert_eq!(fragments[0].delay_ms, 0);

    // Second fragment is bytes 5..43 (length 38), delay 1ms
    assert_eq!(fragments[1].payload.len(), 38);
    assert_eq!(fragments[1].delay_ms, 1);

    // Subsequent fragments are 1 byte each with 1ms delay
    for frag in &fragments[2..] {
        assert_eq!(frag.payload.len(), 1);
        assert_eq!(frag.delay_ms, 1);
    }

    // Reconstruct and ensure bitwise equality
    let mut reconstructed = Vec::new();
    for frag in fragments {
        reconstructed.extend_from_slice(&frag.payload);
    }
    assert_eq!(reconstructed, payload);
}

#[test]
fn test_shape_client_hello_high_delay() {
    let payload = (0..80).map(|i| (i % 256) as u8).collect::<Vec<_>>();
    let config = ServerlessShaperConfig {
        profile: ServerlessProfile::HighDelay,
        tls_record_split: 5,
        sni_split_offset: 43,
        max_split_tls: 522,
        ..Default::default()
    };

    let fragments = ServerlessDirectShaper::shape_client_hello(&payload, &config);

    // Slices beyond the second (idx >= 1) will hit slice_idx = 10, which yields 400ms delay
    let has_stall = fragments.iter().any(|f| f.delay_ms == 400);
    assert!(has_stall, "HighDelay profile must include rhythmic 400ms stalls");

    let mut reconstructed = Vec::new();
    for frag in fragments {
        reconstructed.extend_from_slice(&frag.payload);
    }
    assert_eq!(reconstructed, payload);
}

#[test]
fn test_shape_tcp_stream() {
    let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let config = ServerlessShaperConfig::default();

    let fragments = ServerlessDirectShaper::shape_tcp_stream(data, &config);
    assert_eq!(fragments[0].delay_ms, 0);
    assert_eq!(fragments.len(), data.len());

    let mut reconstructed = Vec::new();
    for frag in fragments {
        reconstructed.extend_from_slice(&frag.payload);
    }
    assert_eq!(reconstructed.as_slice(), data);
}

#[test]
fn test_udp_noise_generation() {
    let mut config = ServerlessShaperConfig::default();
    config.udp_noise_enabled = true;
    config.udp_noise_min_len = 1200;
    config.udp_noise_max_len = 1230;

    let noise = ServerlessDirectShaper::generate_udp_noise(5, &config);
    assert!(noise.is_some());
    let payload = noise.unwrap();
    assert!(payload.len() >= 1200 && payload.len() <= 1230);

    // When disabled, returns None
    config.udp_noise_enabled = false;
    assert!(ServerlessDirectShaper::generate_udp_noise(5, &config).is_none());
}
