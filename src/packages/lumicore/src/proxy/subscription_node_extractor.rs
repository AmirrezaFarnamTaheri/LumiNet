//! # Subscription Node Extractor & Decoder
//!
//! Parses Base64-encoded subscription manifests containing VMess, Shadowsocks,
//! Trojan, and VLESS endpoint URIs into normalized proxy node configurations.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyNodeType {
    VMess,
    Shadowsocks,
    Trojan,
    VLess,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ProxyNodeConfig {
    pub node_type: ProxyNodeType,
    pub address: String,
    pub port: u16,
    pub credential: String,
    pub remark: String,
}

pub struct SubscriptionNodeExtractor;

impl SubscriptionNodeExtractor {
    pub fn decode_subscription(manifest_base64: &str) -> Vec<ProxyNodeConfig> {
        let clean = manifest_base64.trim().replace('\n', "").replace('\r', "");
        let decoded_bytes = match base64_decode_lossy(&clean) {
            Some(b) => b,
            None => return Vec::new(),
        };

        let decoded_str = String::from_utf8_lossy(&decoded_bytes);
        let mut nodes = Vec::new();

        for line in decoded_str.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(node) = Self::parse_node_uri(line) {
                nodes.push(node);
            }
        }
        nodes
    }

    pub fn parse_node_uri(uri: &str) -> Option<ProxyNodeConfig> {
        if let Some(rest) = uri.strip_prefix("ss://") {
            Self::parse_ss(rest)
        } else if let Some(rest) = uri.strip_prefix("vmess://") {
            Self::parse_vmess(rest)
        } else if let Some(rest) = uri.strip_prefix("trojan://") {
            Self::parse_trojan(rest)
        } else {
            None
        }
    }

    fn parse_ss(uri: &str) -> Option<ProxyNodeConfig> {
        // ss://BASE64(method:password)@address:port#remark or ss://BASE64(method:password@address:port)#remark
        let (body, remark) = match uri.split_once('#') {
            Some((b, r)) => (b, r.to_string()),
            None => (uri, "SS-Node".to_string()),
        };

        if let Some((userinfo, hostport)) = body.split_once('@') {
            let (host, port_str) = hostport.split_once(':')?;
            let port = port_str.parse::<u16>().ok()?;
            Some(ProxyNodeConfig {
                node_type: ProxyNodeType::Shadowsocks,
                address: host.to_string(),
                port,
                credential: userinfo.to_string(),
                remark,
            })
        } else {
            // Whole body might be base64
            let decoded = base64_decode_lossy(body)?;
            let dec_str = String::from_utf8_lossy(&decoded);
            if let Some((cred, hostport)) = dec_str.split_once('@') {
                let (host, port_str) = hostport.split_once(':')?;
                let port = port_str.parse::<u16>().ok()?;
                Some(ProxyNodeConfig {
                    node_type: ProxyNodeType::Shadowsocks,
                    address: host.to_string(),
                    port,
                    credential: cred.to_string(),
                    remark,
                })
            } else {
                None
            }
        }
    }

    fn parse_vmess(b64_json: &str) -> Option<ProxyNodeConfig> {
        let decoded = base64_decode_lossy(b64_json)?;
        let json_str = String::from_utf8_lossy(&decoded);

        // Simple JSON extractor for "add", "port", "id", "ps"
        let address = extract_json_field(&json_str, "add")?;
        let port_str = extract_json_field(&json_str, "port")?;
        let port = port_str.parse::<u16>().ok()?;
        let id = extract_json_field(&json_str, "id").unwrap_or_default();
        let remark = extract_json_field(&json_str, "ps").unwrap_or_else(|| "VMess-Node".to_string());

        Some(ProxyNodeConfig {
            node_type: ProxyNodeType::VMess,
            address,
            port,
            credential: id,
            remark,
        })
    }

    fn parse_trojan(uri: &str) -> Option<ProxyNodeConfig> {
        // trojan://password@address:port#remark
        let (body, remark) = match uri.split_once('#') {
            Some((b, r)) => (b, r.to_string()),
            None => (uri, "Trojan-Node".to_string()),
        };

        let (password, hostport) = body.split_once('@')?;
        let (host, port_str) = hostport.split_once(':')?;
        let port = port_str.split('?').next()?.parse::<u16>().ok()?;

        Some(ProxyNodeConfig {
            node_type: ProxyNodeType::Trojan,
            address: host.to_string(),
            port,
            credential: password.to_string(),
            remark,
        })
    }
}

fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\"", field);
    let idx = json.find(&pattern)?;
    let rest = &json[idx + pattern.len()..];
    let colon_idx = rest.find(':')?;
    let val_part = rest[colon_idx + 1..].trim();

    if val_part.starts_with('"') {
        let after_quote = &val_part[1..];
        let end_quote = after_quote.find('"')?;
        Some(after_quote[..end_quote].to_string())
    } else {
        // numeric or boolean
        let end = val_part
            .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
            .unwrap_or(val_part.len());
        Some(val_part[..end].to_string())
    }
}

fn base64_decode_lossy(input: &str) -> Option<Vec<u8>> {
    const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut clean: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    while clean.len() % 4 != 0 {
        clean.push(b'=');
    }

    let mut out = Vec::new();
    let mut i = 0;
    while i < clean.len() {
        let b0 = clean[i];
        let b1 = clean[i + 1];
        let b2 = clean[i + 2];
        let b3 = clean[i + 3];

        let v0 = B64_CHARS.iter().position(|&c| c == b0)? as u32;
        let v1 = B64_CHARS.iter().position(|&c| c == b1)? as u32;
        let v2 = if b2 == b'=' { 0 } else { B64_CHARS.iter().position(|&c| c == b2)? as u32 };
        let v3 = if b3 == b'=' { 0 } else { B64_CHARS.iter().position(|&c| c == b3)? as u32 };

        let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        out.push(((triple >> 16) & 0xff) as u8);
        if b2 != b'=' {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if b3 != b'=' {
            out.push((triple & 0xff) as u8);
        }
        i += 4;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ss_node() {
        let uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@192.168.1.1:8388#MyServer";
        let node = SubscriptionNodeExtractor::parse_node_uri(uri).unwrap();
        assert_eq!(node.node_type, ProxyNodeType::Shadowsocks);
        assert_eq!(node.address, "192.168.1.1");
        assert_eq!(node.port, 8388);
        assert_eq!(node.remark, "MyServer");
    }

    #[test]
    fn test_parse_trojan_node() {
        let uri = "trojan://secret-pwd@edge.example.com:443#Primary-Trojan";
        let node = SubscriptionNodeExtractor::parse_node_uri(uri).unwrap();
        assert_eq!(node.node_type, ProxyNodeType::Trojan);
        assert_eq!(node.address, "edge.example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.credential, "secret-pwd");
    }
}
