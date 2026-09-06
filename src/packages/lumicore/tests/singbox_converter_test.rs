use lumicore::proxy::singbox_converter::{
    build_singbox_full_config, build_singbox_outbound, parse_proxy_url, SingboxConfigOptions,
};

#[test]
fn test_parse_vmess() {
    let raw_json = r#"{"v":"2","ps":"VmessNode","add":"vmess.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"ws","type":"none","host":"vmess.example.com","path":"/ws","tls":"tls","sni":"vmess.example.com"}"#;
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw_json);
    let url = format!("vmess://{}", b64);

    let node = parse_proxy_url(&url).expect("Failed to parse VMess");
    assert_eq!(node.protocol_type, "vmess");
    assert_eq!(node.tag, "VmessNode");
    assert_eq!(node.server, "vmess.example.com");
    assert_eq!(node.port, 443);
    assert_eq!(node.uuid, "b831381d-6324-4d53-ad4f-8cda48b30811");
    assert_eq!(node.transport_type, "ws");
    assert_eq!(node.transport_path, "/ws");
    assert!(node.tls_enabled);

    let ob = build_singbox_outbound(&node);
    assert_eq!(ob["type"], "vmess");
    assert_eq!(ob["transport"]["type"], "ws");
    assert_eq!(ob["transport"]["path"], "/ws");
    assert_eq!(ob["tls"]["enabled"], true);
}

#[test]
fn test_parse_vless_reality() {
    let url = "vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@198.51.100.25:443?security=reality&pbk=o9R7P9kP53v6U8fE0a1b2c3d4e5f6g7h8i9j0k1l2m3&sid=12345678&sni=gateway.apple.com&fp=chrome&type=tcp#VlessReality";
    let node = parse_proxy_url(url).expect("Failed to parse VLESS");

    assert_eq!(node.protocol_type, "vless");
    assert_eq!(node.tag, "VlessReality");
    assert_eq!(node.server, "198.51.100.25");
    assert_eq!(node.port, 443);
    assert!(node.tls_reality_enabled);
    assert_eq!(node.tls_reality_public_key, "o9R7P9kP53v6U8fE0a1b2c3d4e5f6g7h8i9j0k1l2m3");
    assert_eq!(node.tls_reality_short_id, "12345678");
    assert_eq!(node.tls_utls_fingerprint, "chrome");

    let ob = build_singbox_outbound(&node);
    assert_eq!(ob["type"], "vless");
    assert_eq!(ob["tls"]["reality"]["enabled"], true);
    assert_eq!(ob["tls"]["reality"]["short_id"], "12345678");
    assert_eq!(ob["tls"]["utls"]["fingerprint"], "chrome");
}

#[test]
fn test_parse_trojan() {
    let url = "trojan://supersecretpass@trojan.example.com:443?sni=trojan.example.com&type=ws&path=%2Ftrojanws#TrojanNode";
    let node = parse_proxy_url(url).expect("Failed to parse Trojan");

    assert_eq!(node.protocol_type, "trojan");
    assert_eq!(node.tag, "TrojanNode");
    assert_eq!(node.password, "supersecretpass");
    assert_eq!(node.transport_type, "ws");
    assert_eq!(node.transport_path, "/trojanws");

    let ob = build_singbox_outbound(&node);
    assert_eq!(ob["type"], "trojan");
    assert_eq!(ob["password"], "supersecretpass");
}

#[test]
fn test_parse_shadowsocks() {
    let url = "ss://YWVzLTEyOC1nY206c2VjcmV0cGFzcw==@192.0.2.10:8388#ShadowsocksNode";
    let node = parse_proxy_url(url).expect("Failed to parse SS");

    assert_eq!(node.protocol_type, "shadowsocks");
    assert_eq!(node.tag, "ShadowsocksNode");
    assert_eq!(node.server, "192.0.2.10");
    assert_eq!(node.port, 8388);
    assert_eq!(node.method, "aes-128-gcm");
    assert_eq!(node.password, "secretpass");

    let ob = build_singbox_outbound(&node);
    assert_eq!(ob["type"], "shadowsocks");
    assert_eq!(ob["method"], "aes-128-gcm");
}

#[test]
fn test_parse_hysteria2_and_tuic() {
    let hy2_url = "hy2://mypassword@hy2.node.com:8443?sni=hy2.node.com&obfs=salamander_secret&up_mbps=50&down_mbps=200#Hy2Node";
    let hy2 = parse_proxy_url(hy2_url).expect("Failed to parse Hy2");
    assert_eq!(hy2.protocol_type, "hysteria2");
    assert_eq!(hy2.obfs_password, "salamander_secret");
    assert_eq!(hy2.up_mbps, 50);

    let tuic_url = "tuic://myuuid:mypass@tuic.node.com:443?congestion_control=bbr&sni=tuic.node.com#TuicNode";
    let tuic = parse_proxy_url(tuic_url).expect("Failed to parse TUIC");
    assert_eq!(tuic.protocol_type, "tuic");
    assert_eq!(tuic.uuid, "myuuid");
    assert_eq!(tuic.password, "mypass");
    assert_eq!(tuic.congestion_control, "bbr");
}

#[test]
fn test_build_singbox_full_config() {
    let vless_url = "vless://uuid1@node1.org:443?security=reality&pbk=key1&sid=sid1#Node1";
    let trojan_url = "trojan://pass2@node2.org:443?sni=node2.org#Node2";

    let n1 = parse_proxy_url(vless_url).unwrap();
    let n2 = parse_proxy_url(trojan_url).unwrap();

    let opts = SingboxConfigOptions {
        listen: "127.0.0.1".to_string(),
        mixed_port: 2080,
        tun_enabled: true,
        tun_mtu: 9000,
        auto_urltest: true,
        test_url: "https://www.gstatic.com/generate_204".to_string(),
        experimental_clash_api: true,
        clash_api_port: 9090,
    };

    let full_config = build_singbox_full_config(&[n1, n2], &opts);

    // Verify Inbounds
    let inbounds = full_config["inbounds"].as_array().expect("inbounds array");
    assert_eq!(inbounds.len(), 2); // tun and mixed
    assert_eq!(inbounds[0]["type"], "tun");
    assert_eq!(inbounds[0]["mtu"], 9000);
    assert_eq!(inbounds[1]["type"], "mixed");
    assert_eq!(inbounds[1]["listen_port"], 2080);

    // Verify Outbounds: selector ("select"), urltest ("auto"), Node1, Node2, direct, block, dns-out
    let outbounds = full_config["outbounds"].as_array().expect("outbounds array");
    assert_eq!(outbounds[0]["tag"], "select");
    assert_eq!(outbounds[1]["tag"], "auto");
    assert_eq!(outbounds[2]["tag"], "Node1");
    assert_eq!(outbounds[3]["tag"], "Node2");

    // Verify Route rules
    let rules = full_config["route"]["rules"].as_array().expect("route rules");
    assert!(rules.len() >= 3);
    assert_eq!(rules[0]["ip_is_private"], true);
    assert_eq!(rules[0]["outbound"], "direct");
}
