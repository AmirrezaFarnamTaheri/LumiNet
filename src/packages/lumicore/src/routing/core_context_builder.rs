//! Core Configuration Context Builder and Multi-Hop Chaining Engine.
//!
//! Provides runtime configuration compilation for proxy cores (Xray, sing-box, etc.):
//! 1. Multi-hop proxy chaining with reverse detour linking.
//! 2. Split DNS rule compilation (direct domestic DNS vs remote secure DoH/DoT).
//! 3. Domain resolution strategy mapping (AsIs, IPIfNonMatch, IPOnDemand).
//! 4. Lightweight latency test configuration generation for zero-overhead background probing.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Domain resolution strategy for proxy routing cores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainStrategy {
    AsIs,
    IPIfNonMatch,
    IPOnDemand,
}

impl DomainStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AsIs => "AsIs",
            Self::IPIfNonMatch => "IPIfNonMatch",
            Self::IPOnDemand => "IPOnDemand",
        }
    }
}

/// Target action for routing rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingTargetAction {
    Proxy,
    Direct,
    Block,
    Tag(String),
}

impl RoutingTargetAction {
    pub fn tag_name(&self) -> &str {
        match self {
            Self::Proxy => "proxy",
            Self::Direct => "direct",
            Self::Block => "block",
            Self::Tag(t) => t.as_str(),
        }
    }
}

/// Domain routing rule definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRoutingRule {
    pub domains: Vec<String>,
    pub target: RoutingTargetAction,
}

/// Node hop descriptor for proxy chain construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainedOutboundHop {
    pub tag: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub settings: Option<Value>,
    pub stream_settings: Option<Value>,
}

/// Core configuration context synthesizer.
pub struct CoreContextBuilder;

impl CoreContextBuilder {
    /// Compiles a multi-hop proxy chain into an array of linked outbound specifications.
    ///
    /// In a chain [HopA, HopB, HopC], HopA dials through HopB, and HopB dials through HopC.
    /// In Xray/V2Ray terminology, `proxySettings.tag` points to the next outward hop.
    pub fn build_proxy_chain_outbounds(hops: &[ChainedOutboundHop]) -> Vec<Value> {
        if hops.is_empty() {
            return Vec::new();
        }

        let mut outbounds = Vec::with_capacity(hops.len());

        for (idx, hop) in hops.iter().enumerate() {
            let mut outbound_json = json!({
                "tag": hop.tag,
                "protocol": hop.protocol,
                "settings": hop.settings.clone().unwrap_or_else(|| json!({
                    "vnext": [{
                        "address": hop.address,
                        "port": hop.port,
                    }]
                })),
            });

            if let Some(stream) = &hop.stream_settings {
                outbound_json["streamSettings"] = stream.clone();
            }

            // If this is not the final exit hop, point proxySettings to the next hop
            if idx + 1 < hops.len() {
                let next_tag = &hops[idx + 1].tag;
                let mut stream = outbound_json["streamSettings"].clone();
                if stream.is_null() {
                    stream = json!({});
                }
                stream["sockopt"] = json!({
                    "dialerProxy": next_tag
                });
                outbound_json["streamSettings"] = stream;
            }

            outbounds.push(outbound_json);
        }

        outbounds
    }

    /// Compiles split DNS routing rules mapping domestic domains to local DNS and
    /// overseas/proxy domains to encrypted remote DoH/DoT endpoints.
    pub fn build_split_dns_config(
        direct_domains: &[String],
        direct_dns_addr: &str,
        remote_dns_addr: &str,
    ) -> Value {
        let mut servers = vec![
            json!({
                "address": remote_dns_addr,
                "domains": ["geosite:geolocation-!cn", "geosite:google", "geosite:netflix"],
            }),
        ];

        if !direct_domains.is_empty() {
            servers.push(json!({
                "address": direct_dns_addr,
                "domains": direct_domains,
                "expectIPs": ["geoip:cn", "geoip:ir", "geoip:private"],
            }));
        }

        // Catch-all fallback server
        servers.push(json!(direct_dns_addr));

        json!({
            "servers": servers,
            "queryStrategy": "UseIP"
        })
    }

    /// Condenses a full production configuration into a minimal lightweight config
    /// specifically tailored for latency and speed probing.
    ///
    /// Strips TUN virtual interfaces, observatory, complex geosite/geoip rules,
    /// and stats collectors to achieve instant sub-millisecond core initialization.
    pub fn strip_config_for_speedtest(
        full_config: &Value,
        target_outbound_tag: &str,
        probe_listen_port: u16,
    ) -> Value {
        // Retain only the target outbound and direct fallback
        let mut selected_outbounds = Vec::new();
        if let Some(outbounds) = full_config.get("outbounds").and_then(|o| o.as_array()) {
            for ob in outbounds {
                let tag = ob.get("tag").and_then(|t| t.as_str()).unwrap_or("");
                if tag == target_outbound_tag || tag == "direct" {
                    selected_outbounds.push(ob.clone());
                }
            }
        }

        // If target outbound not found, fallback to first available outbound
        if selected_outbounds.is_empty() {
            if let Some(outbounds) = full_config.get("outbounds").and_then(|o| o.as_array()) {
                if let Some(first) = outbounds.first() {
                    selected_outbounds.push(first.clone());
                }
            }
        }

        // Minimal loopback SOCKS inbound
        let test_inbound = json!({
            "tag": "speedtest_inbound",
            "listen": "127.0.0.1",
            "port": probe_listen_port,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": false
            }
        });

        json!({
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [test_inbound],
            "outbounds": selected_outbounds,
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": ["speedtest_inbound"],
                        "outboundTag": target_outbound_tag
                    }
                ]
            }
        })
    }
}
