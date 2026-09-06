use lumicore::routing::core_context_builder::{
    ChainedOutboundHop, CoreContextBuilder, DomainStrategy,
};
use serde_json::json;

#[test]
fn test_domain_strategy_as_str() {
    assert_eq!(DomainStrategy::AsIs.as_str(), "AsIs");
    assert_eq!(DomainStrategy::IPIfNonMatch.as_str(), "IPIfNonMatch");
    assert_eq!(DomainStrategy::IPOnDemand.as_str(), "IPOnDemand");
}

#[test]
fn test_build_proxy_chain_outbounds() {
    let hops = vec![
        ChainedOutboundHop {
            tag: "hop1".to_string(),
            protocol: "vmess".to_string(),
            address: "1.2.3.4".to_string(),
            port: 443,
            settings: None,
            stream_settings: None,
        },
        ChainedOutboundHop {
            tag: "hop2".to_string(),
            protocol: "shadowsocks".to_string(),
            address: "5.6.7.8".to_string(),
            port: 8388,
            settings: None,
            stream_settings: None,
        },
        ChainedOutboundHop {
            tag: "exit".to_string(),
            protocol: "vless".to_string(),
            address: "9.10.11.12".to_string(),
            port: 443,
            settings: None,
            stream_settings: None,
        },
    ];

    let outbounds = CoreContextBuilder::build_proxy_chain_outbounds(&hops);
    assert_eq!(outbounds.len(), 3);

    // Hop 1 should dial through hop 2
    assert_eq!(
        outbounds[0]["streamSettings"]["sockopt"]["dialerProxy"],
        "hop2"
    );

    // Hop 2 should dial through exit
    assert_eq!(
        outbounds[1]["streamSettings"]["sockopt"]["dialerProxy"],
        "exit"
    );

    // Exit hop should not dial through anything
    assert!(outbounds[2].get("streamSettings").is_none());
}

#[test]
fn test_build_split_dns_config() {
    let direct_domains = vec!["geosite:cn".to_string(), "geosite:ir".to_string()];
    let dns_cfg = CoreContextBuilder::build_split_dns_config(
        &direct_domains,
        "223.5.5.5",
        "https://1.1.1.1/dns-query",
    );

    let servers = dns_cfg["servers"].as_array().expect("servers array");
    assert_eq!(servers.len(), 3);
    assert_eq!(servers[0]["address"], "https://1.1.1.1/dns-query");
    assert_eq!(servers[1]["address"], "223.5.5.5");
    assert_eq!(servers[2], "223.5.5.5");
}

#[test]
fn test_strip_config_for_speedtest() {
    let full_config = json!({
        "inbounds": [
            { "tag": "mixed-in", "port": 2080, "protocol": "mixed" },
            { "tag": "tun-in", "protocol": "tun" }
        ],
        "outbounds": [
            { "tag": "proxy_node_1", "protocol": "vless" },
            { "tag": "proxy_node_2", "protocol": "vmess" },
            { "tag": "direct", "protocol": "freedom" },
            { "tag": "block", "protocol": "blackhole" }
        ],
        "observatory": { "probeURL": "http://cp.cloudflare.com/generate_204" },
        "stats": {}
    });

    let speed_cfg =
        CoreContextBuilder::strip_config_for_speedtest(&full_config, "proxy_node_1", 10999);

    // Verify observatory and stats are stripped
    assert!(speed_cfg.get("observatory").is_none());
    assert!(speed_cfg.get("stats").is_none());

    // Inbounds should be exactly one socks listener on 10999
    let inbounds = speed_cfg["inbounds"].as_array().expect("inbounds");
    assert_eq!(inbounds.len(), 1);
    assert_eq!(inbounds[0]["port"], 10999);
    assert_eq!(inbounds[0]["protocol"], "socks");

    // Outbounds should contain only proxy_node_1 and direct
    let outbounds = speed_cfg["outbounds"].as_array().expect("outbounds");
    assert_eq!(outbounds.len(), 2);
    assert_eq!(outbounds[0]["tag"], "proxy_node_1");
    assert_eq!(outbounds[1]["tag"], "direct");
}
