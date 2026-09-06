use lumicore::proxy::subscription_transform::{
    cap_nodes, parse_proxy_line, rule_10_set_address, rule_11_strip_insecure,
    rule_12_apply_443_masking, rule_13_apply_8080_masking, rule_1_security_allowed,
    rule_2_transport_allowed, rule_3_has_host, rule_4_port_allowed, rule_5_normalise_to_443,
    rule_6_normalise_to_8080, rule_7_drop_plaintext_port_with_tls,
    rule_8_drop_tls_port_without_tls, rule_9_mirror, transform_nodes, SubscriptionNode,
    ADDRESS_FOR_PORT_443, ADDRESS_FOR_PORT_8080, CS_443, FM_443, FM_8080, FP_443,
};

#[test]
fn test_parse_and_serialize_vless_and_trojan() {
    let raw = "vless://user-uuid-1234@edge.cf.example.com:2053?security=tls&type=ws&host=origin.example.com&path=%2Fws-in#Primary%20Edge";
    let node = parse_proxy_line(raw).expect("must parse vless");
    assert_eq!(node.scheme, "vless");
    assert_eq!(node.uid, "user-uuid-1234");
    assert_eq!(node.address, "edge.cf.example.com");
    assert_eq!(node.port, "2053");
    assert_eq!(node.get("security"), "tls");
    assert_eq!(node.get("type"), "ws");
    assert_eq!(node.get("host"), "origin.example.com");
    assert_eq!(node.get("path"), "/ws-in");
    assert_eq!(node.tag, "Primary Edge");

    let link = node.to_link();
    assert!(link.starts_with("vless://user-uuid-1234@edge.cf.example.com:2053"));
    assert!(link.contains("security=tls"));
    assert!(link.contains("type=ws"));
    assert!(link.contains("host=origin.example.com"));
    assert!(link.contains("#Primary%20Edge"));

    // Trojan parsing
    let trojan_raw = "trojan://secret-pw@origin.example.com:443?type=grpc&serviceName=my-service&host=origin.example.com#TrojanNode";
    let trojan_node = parse_proxy_line(trojan_raw).expect("must parse trojan");
    assert_eq!(trojan_node.scheme, "trojan");
    assert_eq!(trojan_node.uid, "secret-pw");
    assert_eq!(trojan_node.get("serviceName"), "my-service");
}

#[test]
fn test_rules_1_to_8_filtering_and_port_normalization() {
    let mut node = SubscriptionNode::new("vless", "uuid-1", "example.com", "2053");
    node.set("security", "tls");
    node.set("type", "ws");
    node.set("host", "example.com");

    // Rule 1: security
    assert!(rule_1_security_allowed(&node));
    node.set("security", "reality");
    assert!(!rule_1_security_allowed(&node));
    node.set("security", "tls");

    // Rule 2: transport
    assert!(rule_2_transport_allowed(&node));
    node.set("type", "kcp");
    assert!(!rule_2_transport_allowed(&node));
    node.set("type", "ws");

    // Rule 3: host
    assert!(rule_3_has_host(&node));
    node.set("host", "   ");
    assert!(!rule_3_has_host(&node));
    node.set("host", "example.com");

    // Rule 4, 5, 6: ports
    assert!(rule_4_port_allowed(&node));
    rule_5_normalise_to_443(&mut node);
    assert_eq!(node.port, "443");

    let mut http_node = SubscriptionNode::new("vless", "uuid-2", "example.com", "8880");
    rule_6_normalise_to_8080(&mut http_node);
    assert_eq!(http_node.port, "8080");

    // Rule 7 & 8: security/port invariants
    http_node.set("security", "tls");
    assert!(!rule_7_drop_plaintext_port_with_tls(&http_node));
    http_node.set("security", "none");
    assert!(rule_7_drop_plaintext_port_with_tls(&http_node));

    let mut bad_tls_node = SubscriptionNode::new("vless", "uuid-3", "example.com", "443");
    bad_tls_node.set("security", "none");
    assert!(!rule_8_drop_tls_port_without_tls(&bad_tls_node));
    bad_tls_node.set("security", "tls");
    assert!(rule_8_drop_tls_port_without_tls(&bad_tls_node));
}

#[test]
fn test_rule_9_opposite_transport_mirroring() {
    let mut orig_443 = SubscriptionNode::new("vless", "uuid-1", "origin.example.com", "443");
    orig_443.set("security", "tls");
    orig_443.set("type", "ws");
    orig_443.set("host", "origin.example.com");
    orig_443.set("sni", "custom.origin.com");

    let mirror_8080 = rule_9_mirror(&orig_443);
    assert!(mirror_8080.is_mirror);
    assert_eq!(mirror_8080.port, "8080");
    assert_eq!(mirror_8080.security(), "none");
    assert_eq!(mirror_8080.get("sni"), ""); // SNI dropped on plaintext port

    // Reverse mirror: 8080 -> 443
    let mut orig_8080 = SubscriptionNode::new("vless", "uuid-2", "origin.example.com", "8080");
    orig_8080.set("security", "none");
    orig_8080.set("type", "ws");
    orig_8080.set("host", "origin.example.com");

    let mirror_443 = rule_9_mirror(&orig_8080);
    assert!(mirror_443.is_mirror);
    assert_eq!(mirror_443.port, "443");
    assert_eq!(mirror_443.security(), "tls");
    assert_eq!(mirror_443.get("sni"), "origin.example.com"); // SNI initialized to host
}

#[test]
fn test_rule_10_to_13_masking_and_sanitization() {
    let mut node_443 = SubscriptionNode::new("vless", "uuid-1", "1.2.3.4", "443");
    node_443.set("security", "tls");
    node_443.set("type", "ws");
    node_443.set("host", "origin.com");
    node_443.set("allowinsecure", "1");
    node_443.set("ech", "force");

    rule_10_set_address(&mut node_443);
    assert_eq!(node_443.address, ADDRESS_FOR_PORT_443);

    rule_11_strip_insecure(&mut node_443);
    assert!(!node_443.has("allowinsecure"));
    assert!(!node_443.has("ech"));

    rule_12_apply_443_masking(&mut node_443);
    assert_eq!(node_443.get("fp"), FP_443);
    assert_eq!(node_443.get("fm"), FM_443);
    assert_eq!(node_443.get("cs"), CS_443);
    assert_eq!(node_443.get("sni"), "origin.com");

    let mut node_8080 = SubscriptionNode::new("vless", "uuid-2", "1.2.3.4", "8080");
    node_8080.set("security", "none");
    node_8080.set("type", "ws");
    node_8080.set("host", "origin.com");
    node_8080.set("alpn", "h2");
    node_8080.set("fp", "chrome");

    rule_10_set_address(&mut node_8080);
    assert_eq!(node_8080.address, ADDRESS_FOR_PORT_8080);

    rule_13_apply_8080_masking(&mut node_8080);
    assert_eq!(node_8080.get("fm"), FM_8080);
    assert_eq!(node_8080.get("alpn"), "");
    assert_eq!(node_8080.get("fp"), "");
}

#[test]
fn test_deduplication_and_deterministic_tag() {
    let mut n1 = SubscriptionNode::new("vless", "user-uuid", "cf.edge.com", "443");
    n1.set("security", "tls");
    n1.set("type", "ws");
    n1.set("host", "cdn.example.com");
    n1.tag = "First Comment".to_string();

    let mut n2 = SubscriptionNode::new("vless", "user-uuid", "cf.edge.com", "443");
    n2.set("type", "ws");
    n2.set("security", "tls"); // inverted insertion order
    n2.set("host", "cdn.example.com");
    n2.tag = "Second Different Comment".to_string();

    // Despite tag and param insertion differences, identity matches
    assert_eq!(n1.identity(), n2.identity());

    let (transformed, stats) = transform_nodes(vec![n1, n2], false, true, true);
    // n1 and n2 collapse to 1 node, which generates 1 mirror => total 2 nodes (443 and 8080)
    assert_eq!(transformed.len(), 2);
    assert_eq!(stats.dropped_duplicates, 1);
    assert_eq!(stats.final_443, 1);
    assert_eq!(stats.final_8080, 1);

    // Verify tag contains comment, port, and hash
    let tag = &transformed[0].tag;
    assert!(tag.contains("443") || tag.contains("8080"));
    assert!(tag.contains("First Comment"));
}

#[test]
fn test_cap_nodes_balanced_round_robin() {
    let mut pool = Vec::new();
    for i in 0..10 {
        let mut orig = SubscriptionNode::new("vless", &format!("id-{}", i), "1.1.1.1", if i % 2 == 0 { "443" } else { "8080" });
        orig.is_mirror = false;
        pool.push(orig);
    }
    for i in 0..10 {
        let mut mirr = SubscriptionNode::new("vless", &format!("m-{}", i), "1.1.1.1", if i % 2 == 0 { "8080" } else { "443" });
        mirr.is_mirror = true;
        pool.push(mirr);
    }

    assert_eq!(pool.len(), 20);

    // Cap to 6: should take all 6 from originals, alternating 443 and 8080
    let capped_6 = cap_nodes(pool.clone(), 6);
    assert_eq!(capped_6.len(), 6);
    assert!(capped_6.iter().all(|n| !n.is_mirror));
    let count_443 = capped_6.iter().filter(|n| n.port == "443").count();
    let count_8080 = capped_6.iter().filter(|n| n.port == "8080").count();
    assert_eq!(count_443, 3);
    assert_eq!(count_8080, 3);

    // Cap to 14: should take all 10 originals, then 4 mirrors
    let capped_14 = cap_nodes(pool, 14);
    assert_eq!(capped_14.len(), 14);
    let orig_count = capped_14.iter().filter(|n| !n.is_mirror).count();
    let mirr_count = capped_14.iter().filter(|n| n.is_mirror).count();
    assert_eq!(orig_count, 10);
    assert_eq!(mirr_count, 4);
}
