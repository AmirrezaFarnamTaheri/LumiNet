//! # Autonomous Self-Immunization Engine Tests (TDD RED Phase)
//!
//! Verifies middlebox interference detection, antibody candidate ladder synthesis,
//! and thread-safe antibody store with exact and wildcard domain matching.
//!
//! Source: RFC 793 (TCP RST), RFC 8446 (TLS 1.3 SNI)
//! Best Practices: /leonardomso-rust-skills (type-enum-states, err-thiserror-lib, own-borrow-over-clone)

use lumicore::evasion::immunization::{
    AntibodyStore, EvasionAntibody, ImmunizationEngine, InterferenceEvent, InterferenceType,
};

#[test]
fn test_detect_rst_injection_interference() {
    let engine = ImmunizationEngine::new();

    let event = InterferenceEvent {
        domain: "blocked-middlebox.org".to_string(),
        interference_type: InterferenceType::RstInjection,
        observed_ttl: 48,
        expected_ttl: 56,
        reset_window_seq: 1024,
    };

    let antibody = engine.synthesize_antibody(&event);
    assert_eq!(antibody.domain_pattern, "blocked-middlebox.org");
    assert!(antibody.sni_split_offset > 0);
    assert!(antibody.tcp_desync_offset > 0);
    assert!(antibody.confidence > 0.5);
}

#[test]
fn test_antibody_store_wildcard_and_exact_matching() {
    let store = AntibodyStore::new();

    let antibody_wildcard = EvasionAntibody {
        domain_pattern: "*.example.org".to_string(),
        sni_split_offset: 2,
        tcp_desync_offset: 3,
        fake_ttl: 3,
        decoy_rst: true,
        success_count: 10,
        fail_count: 1,
        confidence: 0.9,
    };

    store.insert(antibody_wildcard);

    // Exact subdomain match
    let matched = store.lookup("news.example.org");
    assert!(matched.is_some());
    let ab = matched.unwrap();
    assert_eq!(ab.sni_split_offset, 2);
    assert_eq!(ab.tcp_desync_offset, 3);

    // Mismatched domain
    assert!(store.lookup("other-site.com").is_none());
}

#[test]
fn test_immunization_feedback_scoring() {
    let store = AntibodyStore::new();

    let antibody = EvasionAntibody {
        domain_pattern: "service.net".to_string(),
        sni_split_offset: 3,
        tcp_desync_offset: 2,
        fake_ttl: 4,
        decoy_rst: false,
        success_count: 0,
        fail_count: 0,
        confidence: 0.5,
    };

    store.insert(antibody);

    store.record_outcome("service.net", true);
    store.record_outcome("service.net", true);
    store.record_outcome("service.net", false);

    let ab = store.lookup("service.net").expect("should find antibody");
    assert_eq!(ab.success_count, 2);
    assert_eq!(ab.fail_count, 1);
    assert!(ab.confidence > 0.5);
}
