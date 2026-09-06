use lumicore::routing::proxy_chain_router::{
    ProxyChainError, ProxyChainHop, ProxyChainHopMode, ProxyChainRouter, ProxyChainSettings,
    ProxyChainSlot, ProxyProfileRef,
};

#[test]
fn test_disabled_chain_returns_base_only() {
    let base = ProxyProfileRef::new("sub1", "fp_base", "Primary Server");
    let settings = ProxyChainSettings::default();

    let result = ProxyChainRouter::resolve_chain(&base, &settings, &[]).unwrap();
    assert_eq!(result.hops.len(), 1);
    assert_eq!(result.hops[0].fingerprint, "fp_base");
    assert!(!result.is_chained);
}

#[test]
fn test_enabled_fixed_3_hop_chain() {
    let before_p = ProxyProfileRef::new("sub1", "fp_before", "Bridge Pre-Hop");
    let base_p = ProxyProfileRef::new("sub1", "fp_base", "Core Relay");
    let after_p = ProxyProfileRef::new("sub2", "fp_after", "Egress Exit");

    let settings = ProxyChainSettings {
        enabled: true,
        before: ProxyChainHop::fixed(ProxyChainSlot::Before, before_p.clone()),
        after: ProxyChainHop::fixed(ProxyChainSlot::After, after_p.clone()),
    };

    let result = ProxyChainRouter::resolve_chain(&base_p, &settings, &[]).unwrap();
    assert_eq!(result.hops.len(), 3);
    assert_eq!(result.hops[0].fingerprint, "fp_before");
    assert_eq!(result.hops[1].fingerprint, "fp_base");
    assert_eq!(result.hops[2].fingerprint, "fp_after");
    assert!(result.is_chained);
}

#[test]
fn test_loop_detection_rejects_duplicate_hops() {
    let base_p = ProxyProfileRef::new("sub1", "fp_dup", "Dup Node");

    // Before hop identical to base hop -> loop error
    let settings = ProxyChainSettings {
        enabled: true,
        before: ProxyChainHop::fixed(ProxyChainSlot::Before, base_p.clone()),
        after: ProxyChainHop::off(ProxyChainSlot::After),
    };

    let err = ProxyChainRouter::resolve_chain(&base_p, &settings, &[]).unwrap_err();
    assert_eq!(
        err,
        ProxyChainError::LoopDetected("before".to_string(), "fp_dup".to_string())
    );
}

#[test]
fn test_automatic_hop_selection_avoids_base() {
    let base_p = ProxyProfileRef::new("sub1", "fp_base", "Base Node");
    let cand1 = ProxyProfileRef::new("sub1", "fp_base", "Base Node Copy");
    let cand2 = ProxyProfileRef::new("sub1", "fp_cand2", "Alt Node 2");

    let settings = ProxyChainSettings {
        enabled: true,
        before: ProxyChainHop::automatic(ProxyChainSlot::Before),
        after: ProxyChainHop::off(ProxyChainSlot::After),
    };

    let result = ProxyChainRouter::resolve_chain(&base_p, &settings, &[cand1, cand2]).unwrap();
    assert_eq!(result.hops.len(), 2);
    assert_eq!(result.hops[0].fingerprint, "fp_cand2");
    assert_eq!(result.hops[1].fingerprint, "fp_base");
}
