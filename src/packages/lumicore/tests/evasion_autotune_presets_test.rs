use lumicore::dns::{
    chunk_resolvers_round_robin, decode_dns_profile_link, encode_dns_profile_link,
    get_preset_by_id, AutoTunePresetStability, DnsProfileRecord, AUTO_TUNE_PRESETS,
};

#[test]
fn test_auto_tune_presets_count_and_lookup() {
    assert_eq!(AUTO_TUNE_PRESETS.len(), 10);

    let default_preset = get_preset_by_id("iran-average").expect("iran-average preset exists");
    assert_eq!(default_preset.label, "Iran Default");
    assert_eq!(default_preset.min_upload_mtu, 40);
    assert_eq!(default_preset.max_upload_mtu, 140);
    assert_eq!(default_preset.min_download_mtu, 300);
    assert_eq!(default_preset.max_download_mtu, 3000);
    assert_eq!(default_preset.stability, AutoTunePresetStability::Stable);

    let agg_preset = get_preset_by_id("iran-large-download-aggressive").expect("agg preset exists");
    assert_eq!(agg_preset.stability, AutoTunePresetStability::Aggressive);
    assert_eq!(agg_preset.max_download_mtu, 6500);

    assert!(get_preset_by_id("non-existent").is_none());
}

#[test]
fn test_chunk_resolvers_round_robin() {
    let resolvers = vec![
        "1.1.1.1:53".to_string(),
        "8.8.8.8:53".to_string(),
        "9.9.9.9:53".to_string(),
        "8.8.4.4:53".to_string(),
        "1.0.0.1:53".to_string(),
    ];

    let chunks = chunk_resolvers_round_robin(&resolvers, 2);
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0], vec!["1.1.1.1:53", "9.9.9.9:53", "1.0.0.1:53"]);
    assert_eq!(chunks[1], vec!["8.8.8.8:53", "8.8.4.4:53"]);

    // Empty list check
    assert!(chunk_resolvers_round_robin(&[], 3).is_empty());
}

#[test]
fn test_dns_profile_link_encode_decode() {
    let record = DnsProfileRecord {
        name: "My Stealth DNS".to_string(),
        domain: "dns.example.com".to_string(),
        encryption_key: "secretkey12345678".to_string(),
        encryption_method: 2,
        engine: "stormdns".to_string(),
    };

    let link = encode_dns_profile_link(&record).expect("encode succeeds");
    assert!(link.starts_with("stormdns://"));

    let decoded = decode_dns_profile_link(&link).expect("decode succeeds");
    assert_eq!(decoded.name, "My Stealth DNS");
    assert_eq!(decoded.domain, "dns.example.com");
    assert_eq!(decoded.encryption_key, "secretkey12345678");
    assert_eq!(decoded.encryption_method, 2);
    assert_eq!(decoded.engine, "stormdns");
}
