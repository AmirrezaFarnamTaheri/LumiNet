use lumicore::evasion::{
    BypassMode, CombinedBypassConfig, CombinedBypassPlanner, DomainBypassEvaluator,
    DomainEvaluationResult,
};

#[test]
fn test_combined_bypass_planner_ttl_decoy() {
    let fake_hello = b"FAKE_CLIENT_HELLO_PAYLOAD";
    let real_hello = b"\x16\x03\x01\x00\x30\x01\x00\x00\x2c\x03\x03REAL_PAYLOAD_WITH_SERVER_NAME_INDICATION";

    let config = CombinedBypassConfig {
        mode: BypassMode::CombinedTtlDecoy,
        fake_sni: "decoy.example.com".to_string(),
        use_ttl_trick: true,
        ttl_hops: 3,
        fragment_strategy: "sni_split".to_string(),
        fragment_delay_ms: 15,
    };

    let plan = CombinedBypassPlanner::plan(real_hello, fake_hello, &config);

    assert!(plan.ttl_decoy_probe.is_some());
    let probe = plan.ttl_decoy_probe.unwrap();
    assert_eq!(probe.ttl, 3);
    assert_eq!(probe.payload, fake_hello);

    assert!(!plan.real_fragments.is_empty());
    assert_eq!(plan.real_fragments[0].delay_ms, 0);
    if plan.real_fragments.len() > 1 {
        assert_eq!(plan.real_fragments[1].delay_ms, 15);
    }

    // Combined fragments reconstructed should equal original payload
    let mut reconstructed = Vec::new();
    for frag in plan.real_fragments {
        reconstructed.extend_from_slice(&frag.payload);
    }
    assert_eq!(reconstructed, real_hello);
}

#[test]
fn test_combined_bypass_planner_no_ttl() {
    let fake_hello = b"FAKE_CLIENT_HELLO_PAYLOAD";
    let real_hello = b"SIMPLE_TEST_PAYLOAD";

    let config = CombinedBypassConfig {
        mode: BypassMode::SniFragment,
        fake_sni: "decoy.example.com".to_string(),
        use_ttl_trick: false,
        ttl_hops: 1,
        fragment_strategy: "half".to_string(),
        fragment_delay_ms: 5,
    };

    let plan = CombinedBypassPlanner::plan(real_hello, fake_hello, &config);
    assert!(plan.ttl_decoy_probe.is_none());
    assert_eq!(plan.real_fragments.len(), 2);
}

#[test]
fn test_domain_bypass_evaluator_optimal_mode() {
    let results = vec![
        DomainEvaluationResult {
            domain: "target.com".to_string(),
            mode: BypassMode::Direct,
            success: false,
            latency_ms: 5000,
            http_status: None,
            error: Some("Connection timed out".to_string()),
        },
        DomainEvaluationResult {
            domain: "target.com".to_string(),
            mode: BypassMode::SniFragment,
            success: false,
            latency_ms: 4000,
            http_status: None,
            error: Some("Connection reset by peer".to_string()),
        },
        DomainEvaluationResult {
            domain: "target.com".to_string(),
            mode: BypassMode::FakeSniDecoy,
            success: true,
            latency_ms: 120,
            http_status: Some(200),
            error: None,
        },
        DomainEvaluationResult {
            domain: "target.com".to_string(),
            mode: BypassMode::CombinedTtlDecoy,
            success: true,
            latency_ms: 140,
            http_status: Some(200),
            error: None,
        },
    ];

    let optimal = DomainBypassEvaluator::select_optimal_mode(&results);
    assert_eq!(optimal, Some(BypassMode::FakeSniDecoy));
}

#[test]
fn test_domain_bypass_evaluator_no_success() {
    let results = vec![DomainEvaluationResult {
        domain: "blocked.com".to_string(),
        mode: BypassMode::Direct,
        success: false,
        latency_ms: 3000,
        http_status: None,
        error: Some("Blocked".to_string()),
    }];

    let optimal = DomainBypassEvaluator::select_optimal_mode(&results);
    assert_eq!(optimal, None);
}
