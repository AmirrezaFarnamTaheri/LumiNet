//! # Subscription Node Transformation & Normalization Engine
//!
//! Implements deterministic multi-protocol subscription filtering, Cloudflare
//! fronted exit redirection, certificate sanitization, anti-DPI fragmentation
//! injection, opposite-transport mirroring, and balanced port capping.

use base64::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Target exit IP addresses for fronted egress.
pub const ADDRESS_FOR_PORT_443: &str = "188.114.97.6";
pub const ADDRESS_FOR_PORT_8080: &str = "188.114.97.6";

/// Port buckets for Cloudflare edge routing.
pub const PORTS_MAPPED_TO_443: &[&str] = &["443", "2053", "2083", "2087", "2096", "8443"];
pub const PORTS_MAPPED_TO_8080: &[&str] = &["80", "8080", "8880", "2052", "2082", "2086", "2095"];

/// Accepted protocol parameters.
pub const ALLOWED_SECURITY: &[&str] = &["", "tls", "none"];
pub const ALLOWED_TRANSPORTS: &[&str] = &["ws", "xhttp", "websocket", "httpupgrade", "grpc"];

/// Client-side fingerprint and fragmentation profiles.
pub const FP_443: &str = "unsafe";
pub const FM_443: &str = r#"{"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["5", "94", "1"], "delays": ["0"], "maxSplit": "0"}}, {"type": "fragment", "settings": {"packets": "1-1", "lengths": ["109", "1"], "delays": ["1"], "maxSplit": "355"}}]}"#;
pub const CS_443: &str = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
pub const FM_8080: &str = r#"{"tcp": [{"type": "fragment", "settings": {"packets": "1-1", "lengths": ["1"], "delays": ["4"], "maxSplit": "355"}}]}"#;

/// Query parameters that disable certificate validation or force ECH lookup.
pub const INSECURE_KEYS: &[&str] = &["allowinsecure", "allow_insecure", "insecure"];
pub const ECH_KEYS: &[&str] = &["ech"];
pub const TLS_ONLY_KEYS: &[&str] = &["sni", "alpn", "fp", "cs"];

/// Stable parameter emit order for byte-identical subscription diffs.
pub const PARAM_ORDER: &[&str] = &[
    "encryption",
    "security",
    "type",
    "host",
    "path",
    "serviceName",
    "mode",
    "sni",
    "alpn",
    "fp",
    "cs",
    "fm",
    "flow",
    "headerType",
    "packetEncoding",
];

/// Represents a parsed proxy node independent of its wire dialect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionNode {
    pub scheme: String,
    pub uid: String,
    pub address: String,
    pub port: String,
    pub params: HashMap<String, String>,
    pub tag: String,
    pub extra: HashMap<String, String>,
    pub source: String,
    pub latency_ms: Option<u64>,
    pub is_mirror: bool,
}

impl SubscriptionNode {
    pub fn new(scheme: &str, uid: &str, address: &str, port: &str) -> Self {
        Self {
            scheme: scheme.to_string(),
            uid: uid.to_string(),
            address: address.to_string(),
            port: port.to_string(),
            params: HashMap::new(),
            tag: String::new(),
            extra: HashMap::new(),
            source: String::new(),
            latency_ms: None,
            is_mirror: false,
        }
    }

    fn find_key(&self, key: &str) -> Option<String> {
        let lowered = key.to_ascii_lowercase();
        for existing in self.params.keys() {
            if existing.to_ascii_lowercase() == lowered {
                return Some(existing.clone());
            }
        }
        None
    }

    pub fn get(&self, key: &str) -> &str {
        if let Some(actual) = self.find_key(key) {
            if let Some(v) = self.params.get(&actual) {
                return v.as_str();
            }
        }
        ""
    }

    pub fn set(&mut self, key: &str, value: &str) {
        if let Some(actual) = self.find_key(key) {
            self.params.insert(actual, value.to_string());
        } else {
            self.params.insert(key.to_string(), value.to_string());
        }
    }

    pub fn pop(&mut self, key: &str) -> Option<String> {
        if let Some(actual) = self.find_key(key) {
            self.params.remove(&actual)
        } else {
            None
        }
    }

    pub fn has(&self, key: &str) -> bool {
        self.find_key(key).is_some()
    }

    pub fn transport(&self) -> String {
        self.get("type").to_ascii_lowercase()
    }

    pub fn security(&self) -> String {
        self.get("security").to_ascii_lowercase()
    }

    pub fn host(&self) -> &str {
        self.get("host")
    }

    /// Functional identity tuple for deduplication, ignoring display tag and comments.
    pub fn identity(&self) -> (String, String, String, String, Vec<(String, String)>) {
        let mut sorted_params: Vec<(String, String)> = self
            .params
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect();
        sorted_params.sort();

        (
            self.scheme.to_ascii_lowercase(),
            self.uid.clone(),
            self.address.clone(),
            self.port.clone(),
            sorted_params,
        )
    }

    /// Serializes the node into a canonical share link URI.
    pub fn to_link(&self) -> String {
        if self.scheme == "vmess" {
            return self.to_vmess_link();
        }

        let mut ordered = Vec::new();
        let rank_map: HashMap<&str, usize> = PARAM_ORDER
            .iter()
            .enumerate()
            .map(|(i, &k)| (k, i))
            .collect();

        for (k, v) in &self.params {
            if !v.is_empty() {
                let rank = rank_map.get(k.to_ascii_lowercase().as_str()).copied().unwrap_or(usize::MAX);
                ordered.push((rank, k.clone(), v.clone()));
            }
        }
        ordered.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        let query_parts: Vec<String> = ordered
            .into_iter()
            .map(|(_, k, v)| {
                format!(
                    "{}={}",
                    urlencoding::encode(&k),
                    urlencoding::encode(&v)
                )
            })
            .collect();

        let host_formatted = if self.address.contains(':') && !self.address.starts_with('[') {
            format!("[{}]", self.address)
        } else {
            self.address.clone()
        };

        let mut link = format!(
            "{}://{}@{}:{}",
            self.scheme,
            urlencoding::encode(&self.uid),
            host_formatted,
            self.port
        );

        if !query_parts.is_empty() {
            link.push('?');
            link.push_str(&query_parts.join("&"));
        }

        if !self.tag.is_empty() {
            link.push('#');
            link.push_str(&urlencoding::encode(&self.tag));
        }

        link
    }

    fn to_vmess_link(&self) -> String {
        let mut map = serde_json::Map::new();
        map.insert("v".into(), serde_json::Value::String(self.extra.get("v").cloned().unwrap_or_else(|| "2".into())));
        map.insert("ps".into(), serde_json::Value::String(self.tag.clone()));
        map.insert("add".into(), serde_json::Value::String(self.address.clone()));
        map.insert("port".into(), serde_json::Value::String(self.port.clone()));
        map.insert("id".into(), serde_json::Value::String(self.uid.clone()));
        map.insert("aid".into(), serde_json::Value::String(self.extra.get("aid").cloned().unwrap_or_else(|| "0".into())));
        map.insert("scy".into(), serde_json::Value::String(self.extra.get("scy").cloned().unwrap_or_else(|| "auto".into())));
        map.insert("net".into(), serde_json::Value::String(self.get("type").to_string()));
        map.insert("type".into(), serde_json::Value::String(self.get("headerType").to_string()));
        map.insert("host".into(), serde_json::Value::String(self.get("host").to_string()));
        map.insert("path".into(), serde_json::Value::String(self.get("path").to_string()));
        map.insert("tls".into(), serde_json::Value::String(self.get("security").to_string()));
        map.insert("sni".into(), serde_json::Value::String(self.get("sni").to_string()));
        map.insert("alpn".into(), serde_json::Value::String(self.get("alpn").to_string()));
        map.insert("fp".into(), serde_json::Value::String(self.get("fp").to_string()));

        let json_bytes = serde_json::to_vec(&map).unwrap_or_default();
        format!("vmess://{}", BASE64_STANDARD.encode(json_bytes))
    }
}

/// Parses a single URI share link into a `SubscriptionNode`.
pub fn parse_proxy_line(raw: &str) -> Option<SubscriptionNode> {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('#') || !line.contains("://") {
        return None;
    }

    let (scheme, rest) = line.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();

    if scheme == "vmess" {
        return parse_vmess(rest, line);
    }

    if scheme == "vless" || scheme == "trojan" {
        return parse_url_style(&scheme, rest, line);
    }

    None
}

fn parse_url_style(scheme: &str, rest: &str, original_line: &str) -> Option<SubscriptionNode> {
    let (rest_no_frag, tag) = match rest.split_once('#') {
        Some((r, t)) => (r, urlencoding::decode(t).unwrap_or_default().to_string()),
        None => (rest, String::new()),
    };

    let (user_host, query) = match rest_no_frag.split_once('?') {
        Some((uh, q)) => (uh, q),
        None => (rest_no_frag, ""),
    };

    let (userinfo, hostport) = match user_host.rsplit_once('@') {
        Some((u, hp)) => (urlencoding::decode(u).unwrap_or_default().to_string(), hp),
        None => (String::new(), user_host),
    };

    let (address, port) = split_host_port(hostport);
    if address.is_empty() {
        return None;
    }

    let mut params = HashMap::new();
    for chunk in query.split('&') {
        if chunk.is_empty() {
            continue;
        }
        if let Some((k, v)) = chunk.split_once('=') {
            let key = urlencoding::decode(k).unwrap_or_default().to_string();
            let val = urlencoding::decode(v).unwrap_or_default().to_string();
            if !key.is_empty() {
                params.insert(key, val);
            }
        }
    }

    Some(SubscriptionNode {
        scheme: scheme.to_string(),
        uid: userinfo,
        address,
        port,
        params,
        tag,
        extra: HashMap::new(),
        source: original_line.to_string(),
        latency_ms: None,
        is_mirror: false,
    })
}

fn parse_vmess(payload: &str, original_line: &str) -> Option<SubscriptionNode> {
    let (encoded_json, _) = payload.split_once('#').unwrap_or((payload, ""));
    let raw_bytes = BASE64_STANDARD
        .decode(encoded_json.trim())
        .or_else(|_| BASE64_URL_SAFE_NO_PAD.decode(encoded_json.trim()))
        .or_else(|_| BASE64_URL_SAFE.decode(encoded_json.trim()))
        .ok()?;

    let json_val: serde_json::Value = serde_json::from_slice(&raw_bytes).ok()?;
    let obj = json_val.as_object()?;

    let mut params = HashMap::new();
    if let Some(net) = obj.get("net").and_then(|v| v.as_str()) {
        params.insert("type".into(), net.to_string());
    }
    if let Some(tls) = obj.get("tls").and_then(|v| v.as_str()) {
        params.insert("security".into(), tls.to_string());
    }
    if let Some(host) = obj.get("host").and_then(|v| v.as_str()) {
        params.insert("host".into(), host.to_string());
    }
    if let Some(path) = obj.get("path").and_then(|v| v.as_str()) {
        params.insert("path".into(), path.to_string());
    }
    if let Some(sni) = obj.get("sni").and_then(|v| v.as_str()) {
        params.insert("sni".into(), sni.to_string());
    }
    if let Some(alpn) = obj.get("alpn").and_then(|v| v.as_str()) {
        params.insert("alpn".into(), alpn.to_string());
    }
    if let Some(fp) = obj.get("fp").and_then(|v| v.as_str()) {
        params.insert("fp".into(), fp.to_string());
    }
    if let Some(ht) = obj.get("type").and_then(|v| v.as_str()) {
        params.insert("headerType".into(), ht.to_string());
    }

    let mut extra = HashMap::new();
    if let Some(v) = obj.get("v") {
        extra.insert("v".into(), v.to_string().trim_matches('"').into());
    }
    if let Some(aid) = obj.get("aid") {
        extra.insert("aid".into(), aid.to_string().trim_matches('"').into());
    }
    if let Some(scy) = obj.get("scy").and_then(|v| v.as_str()) {
        extra.insert("scy".into(), scy.to_string());
    }

    let uid = obj.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let address = obj.get("add").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let port = obj.get("port").map(|v| v.to_string().trim_matches('"').to_string()).unwrap_or_default();
    let tag = obj.get("ps").and_then(|v| v.as_str()).unwrap_or("").to_string();

    Some(SubscriptionNode {
        scheme: "vmess".to_string(),
        uid,
        address,
        port,
        params,
        tag,
        extra,
        source: original_line.to_string(),
        latency_ms: None,
        is_mirror: false,
    })
}

fn split_host_port(hostport: &str) -> (String, String) {
    if hostport.starts_with('[') {
        if let Some((host, rest)) = hostport.split_once(']') {
            let port = rest.trim_start_matches(':').to_string();
            return (host[1..].to_string(), port);
        }
    }
    if let Some((h, p)) = hostport.rsplit_once(':') {
        (h.to_string(), p.to_string())
    } else {
        (hostport.to_string(), String::new())
    }
}

// --- Rules 1 through 13 Implementation ---

/// Rule 1: Keep only allowed security values (tls, none, empty). Drops reality, xtls.
pub fn rule_1_security_allowed(node: &SubscriptionNode) -> bool {
    let sec = node.security();
    ALLOWED_SECURITY.contains(&sec.as_str())
}

/// Rule 2: Keep only supported transports.
pub fn rule_2_transport_allowed(node: &SubscriptionNode) -> bool {
    let tr = node.transport();
    ALLOWED_TRANSPORTS.contains(&tr.as_str())
}

/// Rule 3: Must have a non-empty host parameter.
pub fn rule_3_has_host(node: &SubscriptionNode) -> bool {
    !node.host().trim().is_empty()
}

/// Rule 4: Port must fall into known Cloudflare HTTPS or HTTP buckets.
pub fn rule_4_port_allowed(node: &SubscriptionNode) -> bool {
    PORTS_MAPPED_TO_443.contains(&node.port.as_str())
        || PORTS_MAPPED_TO_8080.contains(&node.port.as_str())
}

/// Rule 5: Normalize HTTPS ports to 443.
pub fn rule_5_normalise_to_443(node: &mut SubscriptionNode) {
    if PORTS_MAPPED_TO_443.contains(&node.port.as_str()) {
        node.port = "443".to_string();
    }
}

/// Rule 6: Normalize HTTP ports to 8080.
pub fn rule_6_normalise_to_8080(node: &mut SubscriptionNode) {
    if PORTS_MAPPED_TO_8080.contains(&node.port.as_str()) {
        node.port = "8080".to_string();
    }
}

/// Rule 7: Reject plaintext port 8080 carrying security=tls.
pub fn rule_7_drop_plaintext_port_with_tls(node: &SubscriptionNode) -> bool {
    !(node.port == "8080" && node.security() == "tls")
}

/// Rule 8: Reject port 443 lacking security=tls.
pub fn rule_8_drop_tls_port_without_tls(node: &SubscriptionNode) -> bool {
    !(node.port == "443" && node.security() != "tls")
}

/// Rule 9: Generate opposite-transport twin mirror node.
pub fn rule_9_mirror(node: &SubscriptionNode) -> SubscriptionNode {
    let mut twin = node.clone();
    twin.is_mirror = true;

    if twin.port == "8080" {
        twin.port = "443".to_string();
        twin.set("security", "tls");
        let host = twin.host().to_string();
        twin.set("sni", &host);
    } else if twin.port == "443" {
        twin.port = "8080".to_string();
        twin.pop("sni");
        twin.set("security", "none");
    }

    twin
}

/// Rule 10: Set fronted exit addresses.
pub fn rule_10_set_address(node: &mut SubscriptionNode) {
    if node.port == "443" {
        node.address = ADDRESS_FOR_PORT_443.to_string();
    } else if node.port == "8080" {
        node.address = ADDRESS_FOR_PORT_8080.to_string();
    }
}

/// Rule 11: Strip certificate opt-outs and ECH keys.
pub fn rule_11_strip_insecure(node: &mut SubscriptionNode) {
    let keys_to_remove: Vec<String> = node
        .params
        .keys()
        .filter(|k| {
            let lk = k.to_ascii_lowercase();
            INSECURE_KEYS.contains(&lk.as_str()) || ECH_KEYS.contains(&lk.as_str())
        })
        .cloned()
        .collect();

    for k in keys_to_remove {
        node.params.remove(&k);
    }
}

/// Rule 12: Apply port 443 masking (fp=unsafe, fm, cs, sni=host).
pub fn rule_12_apply_443_masking(node: &mut SubscriptionNode) {
    if node.port != "443" {
        return;
    }
    node.set("fp", FP_443);
    node.set("fm", FM_443);
    node.set("cs", CS_443);
    let host = node.host().to_string();
    node.set("sni", &host);
}

/// Rule 13: Apply port 8080 masking (fm fragment, drop TLS-only keys).
pub fn rule_13_apply_8080_masking(node: &mut SubscriptionNode) {
    if node.port != "8080" {
        return;
    }
    node.set("fm", FM_8080);
    for key in TLS_ONLY_KEYS {
        node.pop(key);
    }
}

/// Generates a deterministic tag using source comment, port, and 6-char SHA-256 hash of node identity.
pub fn make_tag(node: &SubscriptionNode, keep_source_comment: bool) -> String {
    let id_tuple = node.identity();
    let serialized_id = format!("{:?}", id_tuple);
    let mut hasher = Sha256::new();
    hasher.update(serialized_id.as_bytes());
    let digest = hasher.finalize();
    let hash_hex = format!("{:02x}{:02x}{:02x}", digest[0], digest[1], digest[2]);

    let comment = node.tag.trim();
    if keep_source_comment && !comment.is_empty() {
        format!("{} | {} | {}", comment, node.port, hash_hex)
    } else {
        let tr = if node.transport() == "websocket" { "ws" } else { &node.transport() };
        format!("{} | {}-{} | {} | {}", node.host(), node.scheme, tr, node.port, hash_hex)
    }
}

/// Statistics collected during pipeline execution.
#[derive(Debug, Default, Clone)]
pub struct TransformStats {
    pub dropped_vmess: usize,
    pub dropped_rule_1_security: usize,
    pub dropped_rule_2_transport: usize,
    pub dropped_rule_3_no_host: usize,
    pub dropped_rule_4_port: usize,
    pub dropped_rule_7_8080_with_tls: usize,
    pub dropped_rule_8_443_without_tls: usize,
    pub kept_after_rules_1_to_8: usize,
    pub mirrors_added_rule_9: usize,
    pub dropped_duplicates: usize,
    pub final_443: usize,
    pub final_8080: usize,
    pub final_total: usize,
}

/// Transforms an upstream node collection according to the 13 canonical rules.
pub fn transform_nodes(
    nodes: Vec<SubscriptionNode>,
    include_vmess: bool,
    rename_nodes: bool,
    keep_source_comment: bool,
) -> (Vec<SubscriptionNode>, TransformStats) {
    let mut stats = TransformStats::default();
    let mut kept = Vec::new();

    for mut node in nodes {
        if !include_vmess && node.scheme == "vmess" {
            stats.dropped_vmess += 1;
            continue;
        }
        if !rule_1_security_allowed(&node) {
            stats.dropped_rule_1_security += 1;
            continue;
        }
        if !rule_2_transport_allowed(&node) {
            stats.dropped_rule_2_transport += 1;
            continue;
        }
        if !rule_3_has_host(&node) {
            stats.dropped_rule_3_no_host += 1;
            continue;
        }
        if !rule_4_port_allowed(&node) {
            stats.dropped_rule_4_port += 1;
            continue;
        }

        rule_5_normalise_to_443(&mut node);
        rule_6_normalise_to_8080(&mut node);

        if !rule_7_drop_plaintext_port_with_tls(&node) {
            stats.dropped_rule_7_8080_with_tls += 1;
            continue;
        }
        if !rule_8_drop_tls_port_without_tls(&node) {
            stats.dropped_rule_8_443_without_tls += 1;
            continue;
        }

        kept.push(node);
    }

    stats.kept_after_rules_1_to_8 = kept.len();

    // Rule 9: mirror survivors
    let mut mirrors = Vec::new();
    for node in &kept {
        mirrors.push(rule_9_mirror(node));
    }
    stats.mirrors_added_rule_9 = mirrors.len();

    let mut everything = kept;
    everything.extend(mirrors);

    for node in &mut everything {
        rule_10_set_address(node);
        rule_11_strip_insecure(node);
        rule_12_apply_443_masking(node);
        rule_13_apply_8080_masking(node);
    }

    let mut deduped = Vec::new();
    let mut seen = HashSet::new();

    for mut node in everything {
        let key = node.identity();
        if seen.contains(&key) {
            stats.dropped_duplicates += 1;
            continue;
        }
        seen.insert(key);

        if rename_nodes {
            node.tag = make_tag(&node, keep_source_comment);
        }

        if node.port == "443" {
            stats.final_443 += 1;
        } else if node.port == "8080" {
            stats.final_8080 += 1;
        }
        deduped.push(node);
    }

    stats.final_total = deduped.len();
    (deduped, stats)
}

/// Trims node pool to `limit`, prioritizing original source nodes over synthetic mirrors,
/// alternating between port 443 and 8080 to maintain balanced subscriptions.
pub fn cap_nodes(nodes: Vec<SubscriptionNode>, limit: usize) -> Vec<SubscriptionNode> {
    if nodes.len() <= limit {
        return nodes;
    }

    let (originals, mirrors): (Vec<SubscriptionNode>, Vec<SubscriptionNode>) =
        nodes.into_iter().partition(|n| !n.is_mirror);

    let mut kept = round_robin_by_port(originals, limit);
    if kept.len() < limit {
        let remainder = limit - kept.len();
        kept.extend(round_robin_by_port(mirrors, remainder));
    }

    kept
}

fn round_robin_by_port(nodes: Vec<SubscriptionNode>, limit: usize) -> Vec<SubscriptionNode> {
    let mut buckets: BTreeMap<String, Vec<SubscriptionNode>> = BTreeMap::new();
    for node in nodes {
        buckets.entry(node.port.clone()).or_default().push(node);
    }

    let keys: Vec<String> = buckets.keys().cloned().collect();
    let mut result = Vec::new();
    let mut index = 0;

    while result.len() < limit {
        let mut progressed = false;
        for key in &keys {
            if let Some(bucket) = buckets.get(key) {
                if index < bucket.len() {
                    result.push(bucket[index].clone());
                    progressed = true;
                    if result.len() == limit {
                        break;
                    }
                }
            }
        }
        if !progressed {
            break;
        }
        index += 1;
    }

    result
}
