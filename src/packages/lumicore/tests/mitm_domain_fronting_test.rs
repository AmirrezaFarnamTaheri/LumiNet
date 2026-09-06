use lumicore::evasion::mitm_domain_fronting::{
    match_san_pattern, FrontingAction, FrontingTargetProfile, MitmAlpn, MitmFrontingRouter,
};

#[test]
fn test_san_pattern_matching() {
    // Exact matches
    assert!(match_san_pattern("www.google.com", "www.google.com"));
    assert!(match_san_pattern("WWW.GOOGLE.COM", "www.google.com"));

    // Wildcard matches
    assert!(match_san_pattern("r1---sn-4g5edn6s.googlevideo.com", "*.googlevideo.com"));
    assert!(match_san_pattern("scontent.cdninstagram.com", "*.cdninstagram.com"));
    assert!(match_san_pattern("api.github.com", "*.github.com"));

    // Negative matches (wildcard does not match multi-level or other domains)
    assert!(!match_san_pattern("deep.sub.api.github.com", "*.github.com"));
    assert!(!match_san_pattern("notgooglevideo.com", "*.googlevideo.com"));
    assert!(!match_san_pattern("evil.com", "*.google.com"));
}

#[test]
fn test_fronting_profiles_verification() {
    let fastly = FrontingTargetProfile::fastly_default();
    assert_eq!(fastly.fronted_sni, "github.githubassets.com");
    assert_eq!(fastly.alpn, MitmAlpn::Http2And11);

    // Peer returns certificate containing SANs
    let presented = vec![
        "other.net".to_string(),
        "reddit.com".to_string(),
    ];
    assert!(fastly.verify_peer_sans(&presented));

    let invalid_presented = vec!["attacker.org".to_string()];
    assert!(!fastly.verify_peer_sans(&invalid_presented));

    let meta = FrontingTargetProfile::meta_default();
    assert_eq!(meta.fronted_sni, "www.microsoft.com");
    let meta_presented = vec!["web.whatsapp.com".to_string()];
    assert!(meta.verify_peer_sans(&meta_presented));
}

#[test]
fn test_client_ingress_routing() {
    let router = MitmFrontingRouter::new(11666, 11777);

    // Direct domain bypass
    let action_ir = router.route_client_ingress("varzesh3.ir", false);
    assert_eq!(action_ir, FrontingAction::Direct);

    // Video domain goes to H1.1 decryption inbound
    let action_video = router.route_client_ingress("rr2---sn-oxun-xx.googlevideo.com", false);
    assert_eq!(action_video, FrontingAction::RedirectToMitm { port: 11666 });

    // Frontable web services go to H2/H1.1 decryption inbound
    let action_insta = router.route_client_ingress("www.instagram.com", false);
    assert_eq!(action_insta, FrontingAction::RedirectToMitm { port: 11777 });

    let action_reddit = router.route_client_ingress("reddit.com", false);
    assert_eq!(action_reddit, FrontingAction::RedirectToMitm { port: 11777 });

    // Unknown domain defaults to Direct
    let action_unknown = router.route_client_ingress("some-private-host.org", false);
    assert_eq!(action_unknown, FrontingAction::Direct);
}

#[test]
fn test_decrypted_egress_routing() {
    let router = MitmFrontingRouter::new(11666, 11777);

    // From H1.1 inbound: googlevideo succeeds with H1.1 ALPN
    let egress_video = router.route_decrypted_egress("manifest.googlevideo.com", 11666);
    match egress_video {
        FrontingAction::RepackFronted { fronted_sni, alpn, .. } => {
            assert_eq!(fronted_sni, "www.google.com");
            assert_eq!(alpn, MitmAlpn::Http11);
        }
        other => panic!("expected RepackFronted, got {:?}", other),
    }

    // From H1.1 inbound: non-video is strictly blocked
    let egress_blocked = router.route_decrypted_egress("www.instagram.com", 11666);
    assert_eq!(egress_blocked, FrontingAction::Block);

    // From H2/H1.1 inbound: meta domain gets www.microsoft.com fronted SNI
    let egress_meta = router.route_decrypted_egress("api.instagram.com", 11777);
    match egress_meta {
        FrontingAction::RepackFronted { fronted_sni, alpn, .. } => {
            assert_eq!(fronted_sni, "www.microsoft.com");
            assert_eq!(alpn, MitmAlpn::Http2And11);
        }
        other => panic!("expected RepackFronted, got {:?}", other),
    }

    // From H2/H1.1 inbound: fastly domain gets github.githubassets.com fronted SNI
    let egress_fastly = router.route_decrypted_egress("reddit.com", 11777);
    match egress_fastly {
        FrontingAction::RepackFronted { fronted_sni, redirect_endpoint, .. } => {
            assert_eq!(fronted_sni, "github.githubassets.com");
            assert_eq!(redirect_endpoint, Some("github.githubassets.com:443".to_string()));
        }
        other => panic!("expected RepackFronted, got {:?}", other),
    }
}
