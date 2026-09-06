use lumicore::evasion::noize_shaper::{
    parse_cps, NoizeConfig, NoizeProfile,
};

#[test]
fn test_parse_cps_hex_literal() {
    let spec = "<b 0d0a0d0a>";
    let bytes = parse_cps(spec);
    assert_eq!(bytes, vec![0x0d, 0x0a, 0x0d, 0x0a]);

    let spec_with_prefix = "<b 0xdeadbeef>";
    let bytes2 = parse_cps(spec_with_prefix);
    assert_eq!(bytes2, vec![0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn test_parse_cps_timestamp_and_counter() {
    let spec = "<t><c>";
    let bytes = parse_cps(spec);
    assert_eq!(bytes.len(), 8);
    // Timestamp is 4 bytes big endian, non-zero
    let ts = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
    assert!(ts > 1700000000);
}

#[test]
fn test_parse_cps_random_ranges() {
    // Random raw bytes
    let spec_r = "<r 25-35>";
    let bytes_r = parse_cps(spec_r);
    assert!(bytes_r.len() >= 25 && bytes_r.len() <= 35);

    // Random ascii characters
    let spec_rc = "<rc 20-20>";
    let bytes_rc = parse_cps(spec_rc);
    assert_eq!(bytes_rc.len(), 20);
    for b in bytes_rc {
        assert!((b >= b'a' && b <= b'z') || (b >= b'A' && b <= b'Z'));
    }

    // Random digits
    let spec_rd = "<rd 15-15>";
    let bytes_rd = parse_cps(spec_rd);
    assert_eq!(bytes_rd.len(), 15);
    for b in bytes_rd {
        assert!(b >= b'0' && b <= b'9');
    }
}

#[test]
fn test_noize_profiles_and_junk_packets() {
    let off = NoizeConfig::from_profile(NoizeProfile::Off);
    assert!(!off.is_enabled());
    assert_eq!(off.generate_junk_packets().len(), 0);

    let light = NoizeConfig::from_profile(NoizeProfile::Light);
    assert!(light.is_enabled());
    let junk_light = light.generate_junk_packets();
    assert_eq!(junk_light.len(), light.junk_count);
    for pkt in &junk_light {
        assert!(pkt.len() >= light.junk_min_size && pkt.len() <= light.junk_max_size);
    }

    let balanced = NoizeConfig::from_profile(NoizeProfile::Balanced);
    assert!(balanced.is_enabled());
    assert!(balanced.junk_count > light.junk_count);

    let aggressive = NoizeConfig::from_profile(NoizeProfile::Aggressive);
    assert!(aggressive.is_enabled());
    assert!(aggressive.junk_count >= balanced.junk_count);
}
