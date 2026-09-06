use lumicore::routing::{
    compile_combined_ruleset, normalize_mihomo_domains, split_sections, unusable_behind_tunnel,
    validate_cidr,
};

#[test]
fn test_split_sections_fail_closed() {
    let raw = r#"
# Heading comment
[block]
malware.evil
phishing.bad

[proxy]
ignored.example

[direct]
internal.lan
10.0.0.0/8
"#;

    let (block, direct) = split_sections(raw);
    assert!(block.contains("malware.evil\n"));
    assert!(block.contains("phishing.bad\n"));
    assert!(!block.contains("ignored.example"));
    assert!(!direct.contains("ignored.example"));
    assert!(direct.contains("internal.lan\n"));
    assert!(direct.contains("10.0.0.0/8\n"));
}

#[test]
fn test_normalize_mihomo_domains() {
    let input = r#"
+.example.com
+.sub.domain.org
plain.domain.net
# comment line
+.another.ir
"#;

    let normalized = normalize_mihomo_domains(input);
    assert_eq!(
        normalized,
        vec![
            "example.com".to_string(),
            "sub.domain.org".to_string(),
            "plain.domain.net".to_string(),
            "another.ir".to_string(),
        ]
    );
}

#[test]
fn test_validate_cidr() {
    assert!(validate_cidr("192.168.1.0/24"));
    assert!(validate_cidr("10.0.0.0/8"));
    assert!(validate_cidr("2001:db8::/32"));
    assert!(validate_cidr("0.0.0.0/0"));

    assert!(!validate_cidr("192.168.1.0/33"));
    assert!(!validate_cidr("2001:db8::/129"));
    assert!(!validate_cidr("999.999.999.999/24"));
    assert!(!validate_cidr("invalid-cidr"));
    assert!(!validate_cidr("10.0.0.1"));
}

#[test]
fn test_compile_combined_ruleset() {
    let user_config = "[block]\nads.tracker\n[direct]\ncorp.internal\n";
    let bundled_domains = "+.bank.ir\n+.gov.ir\n";
    let bundled_ips = "5.200.0.0/16\n2.144.0.0/14";

    let compiled = compile_combined_ruleset(Some(user_config), bundled_domains, bundled_ips);
    assert!(compiled.contains("[block]\nads.tracker"));
    assert!(compiled.contains("[direct]"));
    assert!(compiled.contains("bank.ir"));
    assert!(compiled.contains("gov.ir"));
    assert!(compiled.contains("5.200.0.0/16"));
    assert!(compiled.contains("corp.internal"));
}

#[test]
fn test_unusable_behind_tunnel() {
    assert!(unusable_behind_tunnel("Vless", false).is_none());
    assert!(unusable_behind_tunnel("Trojan", false).is_none());
    assert!(unusable_behind_tunnel("Shadowsocks", false).is_none());

    assert!(unusable_behind_tunnel("Hysteria2", false).is_some());
    assert!(unusable_behind_tunnel("TUIC", false).is_some());

    // When carries_quic is true, all are supported
    assert!(unusable_behind_tunnel("Hysteria2", true).is_none());
}
