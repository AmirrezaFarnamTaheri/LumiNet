// Pure Rust implementation: Multiprotocol Traffic Inspector

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectedProtocol {
    Rdp,
    Ssh,
    Tls,
    Http,
    WebSocket,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectionVerdict {
    Permitted,
    Denied(&'static str),
    NeedsMoreData,
}

#[derive(Debug, Clone)]
pub struct InspectorConfig {
    pub allow_rdp: bool,
    pub allow_ssh: bool,
    pub allow_tls: bool,
    pub allow_http: bool,
    pub enforce_sni: bool,
}

impl Default for InspectorConfig {
    fn default() -> Self {
        Self {
            allow_rdp: true,
            allow_ssh: true,
            allow_tls: true,
            allow_http: true,
            enforce_sni: false,
        }
    }
}

pub struct MultiprotocolTrafficInspector {
    pub config: InspectorConfig,
    pub inspected_count: u64,
}

impl MultiprotocolTrafficInspector {
    pub fn new(config: InspectorConfig) -> Self {
        Self {
            config,
            inspected_count: 0,
        }
    }

    pub fn inspect_stream(
        &mut self,
        data: &[u8],
    ) -> (DetectedProtocol, InspectionVerdict, Option<String>) {
        self.inspected_count += 1;

        if data.is_empty() {
            return (DetectedProtocol::Unknown, InspectionVerdict::NeedsMoreData, None);
        }

        // 1. Check SSH: starts with "SSH-2.0-" or "SSH-1.99-"
        if data.starts_with(b"SSH-") {
            if let Ok(banner_str) = std::str::from_utf8(data) {
                let banner = banner_str.lines().next().unwrap_or("").to_string();
                let verdict = if self.config.allow_ssh {
                    InspectionVerdict::Permitted
                } else {
                    InspectionVerdict::Denied("SSH traffic prohibited by policy")
                };
                return (DetectedProtocol::Ssh, verdict, Some(banner));
            }
        }

        // 2. Check TLS: ContentType Handshake (0x16), Version (0x03, 0x01..0x03)
        if data.len() >= 5 && data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x04 {
            let sni = parse_tls_sni(data);
            if self.config.enforce_sni && sni.is_none() {
                return (
                    DetectedProtocol::Tls,
                    InspectionVerdict::Denied("Missing required TLS SNI extension"),
                    None,
                );
            }

            let verdict = if self.config.allow_tls {
                InspectionVerdict::Permitted
            } else {
                InspectionVerdict::Denied("TLS traffic prohibited by policy")
            };
            return (DetectedProtocol::Tls, verdict, sni);
        }

        // 3. Check RDP (TPKT header: 0x03, 0x00, length u16)
        if data.len() >= 4 && data[0] == 0x03 && data[1] == 0x00 {
            let tpkt_len = u16::from_be_bytes([data[2], data[3]]) as usize;
            if tpkt_len >= 4 {
                let verdict = if self.config.allow_rdp {
                    InspectionVerdict::Permitted
                } else {
                    InspectionVerdict::Denied("RDP traffic prohibited by policy")
                };
                return (
                    DetectedProtocol::Rdp,
                    verdict,
                    Some(format!("TPKT-length-{}", tpkt_len)),
                );
            }
        }

        // 4. Check HTTP / WebSocket
        if data.starts_with(b"GET ")
            || data.starts_with(b"POST ")
            || data.starts_with(b"CONNECT ")
            || data.starts_with(b"HEAD ")
            || data.starts_with(b"OPTIONS ")
        {
            if let Ok(txt) = std::str::from_utf8(data) {
                let is_ws = txt.to_ascii_lowercase().contains("upgrade: websocket");
                let proto = if is_ws {
                    DetectedProtocol::WebSocket
                } else {
                    DetectedProtocol::Http
                };

                let verdict = if self.config.allow_http {
                    InspectionVerdict::Permitted
                } else {
                    InspectionVerdict::Denied("HTTP traffic prohibited by policy")
                };

                let path = txt
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .map(|s| s.to_string());

                return (proto, verdict, path);
            }
        }

        if data.len() < 8 {
            (DetectedProtocol::Unknown, InspectionVerdict::NeedsMoreData, None)
        } else {
            (
                DetectedProtocol::Unknown,
                InspectionVerdict::Denied("Unrecognized protocol format"),
                None,
            )
        }
    }
}

fn parse_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 43 {
        return None;
    }
    // Handshake type == 0x01 (Client Hello)
    if data[5] != 0x01 {
        return None;
    }

    let mut cursor = 43; // skip record header (5) + type(1) + len(3) + ver(2) + random(32)
    if cursor >= data.len() {
        return None;
    }

    // Session ID
    let session_id_len = data[cursor] as usize;
    cursor += 1 + session_id_len;
    if cursor + 2 > data.len() {
        return None;
    }

    // Cipher Suites
    let cipher_suites_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
    cursor += 2 + cipher_suites_len;
    if cursor + 1 > data.len() {
        return None;
    }

    // Compression Methods
    let comp_len = data[cursor] as usize;
    cursor += 1 + comp_len;
    if cursor + 2 > data.len() {
        return None;
    }

    // Extensions length
    let ext_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
    cursor += 2;
    let ext_end = (cursor + ext_len).min(data.len());

    while cursor + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
        let ext_data_len = u16::from_be_bytes([data[cursor + 2], data[cursor + 3]]) as usize;
        cursor += 4;

        if ext_type == 0x0000 {
            // Server Name Indication
            if cursor + 5 <= ext_end {
                let name_type = data[cursor + 2];
                let name_len = u16::from_be_bytes([data[cursor + 3], data[cursor + 4]]) as usize;
                if name_type == 0 && cursor + 5 + name_len <= ext_end {
                    let name_bytes = &data[cursor + 5..cursor + 5 + name_len];
                    return std::str::from_utf8(name_bytes).ok().map(|s| s.to_string());
                }
            }
        }
        cursor += ext_data_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_ssh_and_rdp() {
        let mut inspector = MultiprotocolTrafficInspector::new(InspectorConfig::default());

        let ssh_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n";
        let (proto, verdict, meta) = inspector.inspect_stream(ssh_banner);
        assert_eq!(proto, DetectedProtocol::Ssh);
        assert_eq!(verdict, InspectionVerdict::Permitted);
        assert_eq!(meta, Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1".to_string()));

        let rdp_tpkt = [0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00];
        let (proto, verdict, meta) = inspector.inspect_stream(&rdp_tpkt);
        assert_eq!(proto, DetectedProtocol::Rdp);
        assert_eq!(verdict, InspectionVerdict::Permitted);
        assert_eq!(meta, Some("TPKT-length-19".to_string()));
    }

    #[test]
    fn test_inspect_http_and_policy_denial() {
        let mut config = InspectorConfig::default();
        config.allow_http = false;
        let mut inspector = MultiprotocolTrafficInspector::new(config);

        let http_req = b"GET /api/v1/health HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (proto, verdict, _) = inspector.inspect_stream(http_req);
        assert_eq!(proto, DetectedProtocol::Http);
        assert_eq!(verdict, InspectionVerdict::Denied("HTTP traffic prohibited by policy"));
    }
}
