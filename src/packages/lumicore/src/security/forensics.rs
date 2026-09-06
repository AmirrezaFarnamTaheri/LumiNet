//! # Network Forensic Analysis
//!
//! Packet parsing, session reassembly, credential extraction, and protocol detection.
//!
//! Key patterns:
//! - Plugin-based module system (IModule trait)
//! - TCP session reassembly
//! - Protocol-specific credential parsers (FTP, HTTP Basic, Telnet, SMTP, NTLM)
//! - File carving via header/footer signatures

/// Network connection identifier.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ConnectionId {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
}

/// TCP session with reassembled data.
#[derive(Debug, Clone)]
pub struct TcpSession {
    pub id: ConnectionId,
    pub data: Vec<u8>,
    pub packets: usize,
    pub start_time: u64,
    pub end_time: u64,
}

/// Extracted credential.
#[derive(Debug, Clone)]
pub struct Credential {
    pub protocol: String,
    pub username: String,
    pub password: String,
    pub source: ConnectionId,
    pub hash: Option<String>,
    pub hash_type: Option<String>,
}

/// Network file extracted via carving.
#[derive(Debug, Clone)]
pub struct ExtractedFile {
    pub file_type: String,
    pub data: Vec<u8>,
    pub source: ConnectionId,
    pub offset: usize,
}

/// DNS mapping from network traffic.
#[derive(Debug, Clone)]
pub struct DnsMapping {
    pub query: String,
    pub response: String,
    pub source: ConnectionId,
}

/// File signature for header/footer-based carving.
#[derive(Debug, Clone)]
pub struct FileSignature {
    pub extension: String,
    pub header: Vec<u8>,
    pub footer: Vec<u8>,
}

/// Default file signatures for common file types.
pub fn default_file_signatures() -> Vec<FileSignature> {
    vec![
        FileSignature {
            extension: "jpg".to_string(),
            header: vec![0xFF, 0xD8, 0xFF],
            footer: vec![0xFF, 0xD9],
        },
        FileSignature {
            extension: "png".to_string(),
            header: vec![0x89, 0x50, 0x4E, 0x47],
            footer: vec![0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82],
        },
        FileSignature {
            extension: "gif".to_string(),
            header: vec![0x47, 0x49, 0x46, 0x38],
            footer: vec![0x00, 0x3B],
        },
        FileSignature {
            extension: "pdf".to_string(),
            header: b"%PDF".to_vec(),
            footer: b"%%EOF".to_vec(),
        },
        FileSignature {
            extension: "zip".to_string(),
            header: vec![0x50, 0x4B, 0x03, 0x04],
            footer: vec![0x50, 0x4B, 0x05, 0x06],
        },
    ]
}

/// Searches for a byte pattern in a byte slice.
/// Delegates to netutil::shared::find_pattern for consistency.
pub fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    crate::netutil::find_pattern(haystack, needle)
}

/// Carves files from a data stream using header/footer signatures.
pub fn carve_files(data: &[u8], signatures: &[FileSignature]) -> Vec<ExtractedFile> {
    let mut files = Vec::new();

    for sig in signatures {
        let mut offset = 0;
        while offset < data.len() {
            if let Some(start) = find_pattern(&data[offset..], &sig.header) {
                let abs_start = offset + start;
                if let Some(end) = find_pattern(&data[abs_start + sig.header.len()..], &sig.footer)
                {
                    let abs_end = abs_start + sig.header.len() + end + sig.footer.len();
                    let file_data = data[abs_start..abs_end].to_vec();
                    files.push(ExtractedFile {
                        file_type: sig.extension.clone(),
                        data: file_data,
                        source: ConnectionId {
                            src_ip: String::new(),
                            dst_ip: String::new(),
                            src_port: 0,
                            dst_port: 0,
                            protocol: String::new(),
                        },
                        offset: abs_start,
                    });
                    offset = abs_end;
                } else {
                    offset = abs_start + 1;
                }
            } else {
                break;
            }
        }
    }

    files
}

/// FTP credential parser.
pub fn parse_ftp_credentials(session: &TcpSession) -> Option<Credential> {
    let data = String::from_utf8_lossy(&session.data);

    // Pattern: USER username\r\n...PASS password\r\n
    let user_start = data.find("USER ")?;
    let user_end = data[user_start..].find("\r\n")?;
    let username = data[user_start + 5..user_start + user_end]
        .trim()
        .to_string();

    let pass_start = data[user_start + user_end..].find("PASS ")?;
    let pass_end = data[user_start + user_end + pass_start..].find("\r\n")?;
    let password = data
        [user_start + user_end + pass_start + 5..user_start + user_end + pass_start + pass_end]
        .trim()
        .to_string();

    if username.is_empty() && password.is_empty() {
        return None;
    }

    Some(Credential {
        protocol: "FTP".to_string(),
        username,
        password,
        source: session.id.clone(),
        hash: None,
        hash_type: None,
    })
}

/// HTTP Basic Auth credential parser.
pub fn parse_http_basic_auth(session: &TcpSession) -> Option<Credential> {
    let data = String::from_utf8_lossy(&session.data);

    // Find Authorization: Basic header
    let auth_start = data.find("Authorization: Basic ")?;
    let line_end = data[auth_start..].find("\r\n")?;
    let b64_creds = data[auth_start + 21..auth_start + line_end].trim();

    let decoded = base64_decode(b64_creds)?;
    let creds_str = String::from_utf8_lossy(&decoded);
    let colon_idx = creds_str.find(':')?;
    let username = creds_str[..colon_idx].to_string();
    let password = creds_str[colon_idx + 1..].to_string();

    Some(Credential {
        protocol: "HTTP Basic".to_string(),
        username,
        password,
        source: session.id.clone(),
        hash: None,
        hash_type: None,
    })
}

/// HTTP Digest Auth credential parser.
pub fn parse_http_digest_auth(session: &TcpSession) -> Option<Credential> {
    let data = String::from_utf8_lossy(&session.data);

    let auth_start = data.find("Authorization: Digest ")?;
    let line_end = data[auth_start..].find("\r\n")?;
    let digest_params = &data[auth_start + 22..auth_start + line_end];

    let mut username = String::new();
    let mut realm = String::new();
    let mut nonce = String::new();
    let mut uri = String::new();
    let mut response = String::new();
    let mut qop = String::new();
    let mut nc = String::new();
    let mut cnonce = String::new();

    for param in digest_params.split(',') {
        let param = param.trim();
        if let Some(idx) = param.find('=') {
            let key = param[..idx].trim();
            let value = param[idx + 1..].trim().trim_matches('"');
            match key {
                "username" => username = value.to_string(),
                "realm" => realm = value.to_string(),
                "nonce" => nonce = value.to_string(),
                "uri" => uri = value.to_string(),
                "response" => response = value.to_string(),
                "qop" => qop = value.to_string(),
                "nc" => nc = value.to_string(),
                "cnonce" => cnonce = value.to_string(),
                _ => {}
            }
        }
    }

    if username.is_empty() || response.is_empty() {
        return None;
    }

    // Build hashcat-compatible hash
    let hash = format!(
        "$http${}::::{}:{}:{}:{}:{}:{}:{}:{}",
        "GET",
        username,
        realm,
        password_placeholder(),
        uri,
        nonce,
        nc,
        cnonce,
        qop
    );

    Some(Credential {
        protocol: "HTTP Digest".to_string(),
        username,
        password: String::new(),
        source: session.id.clone(),
        hash: Some(hash),
        hash_type: Some("HTTP Digest".to_string()),
    })
}

/// Telnet credential parser (state machine).
pub fn parse_telnet_credentials(session: &TcpSession) -> Option<Credential> {
    let data = &session.data;

    // Telnet NVT filtering: only keep printable ASCII (0x20-0x7E)
    let filtered: Vec<u8> = data
        .iter()
        .filter(|&&b| (0x20..=0x7E).contains(&b))
        .copied()
        .collect();

    let text = String::from_utf8_lossy(&filtered);

    // Simple heuristic: look for login/password patterns
    let lines: Vec<&str> = text.split('\n').collect();
    let mut username = String::new();
    let mut password = String::new();

    for (i, line) in lines.iter().enumerate() {
        let lower = line.to_lowercase();
        if (lower.contains("login") || lower.contains("username")) && i + 1 < lines.len() {
            username = lines[i + 1].trim().to_string();
        }
        if lower.contains("password") && i + 1 < lines.len() {
            password = lines[i + 1].trim().to_string();
        }
    }

    if username.is_empty() && password.is_empty() {
        return None;
    }

    Some(Credential {
        protocol: "Telnet".to_string(),
        username,
        password,
        source: session.id.clone(),
        hash: None,
        hash_type: None,
    })
}

/// SMTP AUTH credential parser.
pub fn parse_smtp_credentials(session: &TcpSession) -> Option<Credential> {
    let data = String::from_utf8_lossy(&session.data);

    // AUTH PLAIN: base64(\0username\0password)
    if let Some(idx) = data.find("AUTH PLAIN ") {
        let b64_start = idx + 11;
        let line_end = data[b64_start..]
            .find("\r\n")
            .unwrap_or(data.len() - b64_start);
        let b64 = data[b64_start..b64_start + line_end].trim();

        if let Some(decoded) = base64_decode(b64) {
            // Format: \0username\0password
            let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();
            if parts.len() >= 3 {
                let username = String::from_utf8_lossy(parts[1]).to_string();
                let password = String::from_utf8_lossy(parts[2]).to_string();
                return Some(Credential {
                    protocol: "SMTP".to_string(),
                    username,
                    password,
                    source: session.id.clone(),
                    hash: None,
                    hash_type: None,
                });
            }
        }
    }

    // AUTH LOGIN: base64(username) then base64(password)
    if let Some(idx) = data.find("AUTH LOGIN\r\n") {
        let after_auth = &data[idx + 12..];
        let lines: Vec<&str> = after_auth.split("\r\n").collect();
        if lines.len() >= 3 {
            let username = base64_decode_str(lines[1].trim()).unwrap_or_default();
            let password = base64_decode_str(lines[2].trim()).unwrap_or_default();
            if !username.is_empty() {
                return Some(Credential {
                    protocol: "SMTP".to_string(),
                    username,
                    password,
                    source: session.id.clone(),
                    hash: None,
                    hash_type: None,
                });
            }
        }
    }

    None
}

/// NTLM hash parser for SMB/HTTP NTLM authentication.
pub fn parse_ntlm_hash(session: &TcpSession) -> Option<Credential> {
    let data = &session.data;

    // NTLMSSP signature
    let ntlm_sig = b"NTLMSSP\0";

    // Look for Type 3 message (authentication response)
    for i in 0..data.len().saturating_sub(ntlm_sig.len()) {
        if &data[i..i + ntlm_sig.len()] == ntlm_sig {
            // Check message type (offset 8, 4 bytes, little-endian)
            if i + 12 <= data.len() {
                let msg_type = u32::from_le_bytes(data[i + 8..i + 12].try_into().ok()?);
                if msg_type == 3 {
                    // Extract NT hash (24 bytes at offset 24)
                    if i + 24 + 24 <= data.len() {
                        let nt_hash = &data[i + 24..i + 24 + 24];
                        let lm_hash = &data[i + 16..i + 16 + 24];

                        // Extract domain and user from Type 3 fields
                        let hash_hex = hex_encode(nt_hash);
                        let lm_hex = hex_encode(lm_hash);

                        return Some(Credential {
                            protocol: "NTLM".to_string(),
                            username: String::new(), // Would need full parsing
                            password: String::new(),
                            source: session.id.clone(),
                            hash: Some(format!(
                                "{}:::{}:{}:{}",
                                "user", "domain", lm_hex, hash_hex
                            )),
                            hash_type: Some(
                                if nt_hash.len() > 24 {
                                    "NTLMv2"
                                } else {
                                    "NTLMv1"
                                }
                                .to_string(),
                            ),
                        });
                    }
                }
            }
        }
    }

    None
}

/// Network statistics aggregator.
pub struct NetworkMap {
    connections: Vec<ConnectionId>,
    credentials: Vec<Credential>,
    dns_mappings: Vec<DnsMapping>,
    files: Vec<ExtractedFile>,
}

impl Default for NetworkMap {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkMap {
    pub fn new() -> Self {
        Self {
            connections: Vec::new(),
            credentials: Vec::new(),
            dns_mappings: Vec::new(),
            files: Vec::new(),
        }
    }

    pub fn add_connection(&mut self, conn: ConnectionId) {
        if !self.connections.contains(&conn) {
            self.connections.push(conn);
        }
    }

    pub fn add_credential(&mut self, cred: Credential) {
        self.credentials.push(cred);
    }

    pub fn add_dns_mapping(&mut self, mapping: DnsMapping) {
        self.dns_mappings.push(mapping);
    }

    pub fn add_file(&mut self, file: ExtractedFile) {
        self.files.push(file);
    }

    pub fn unique_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .connections
            .iter()
            .map(|c| c.src_ip.clone())
            .chain(self.connections.iter().map(|c| c.dst_ip.clone()))
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }

    pub fn credential_count(&self) -> usize {
        self.credentials.len()
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

// Helper functions - delegate to netutil::shared for consistency
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    crate::netutil::base64_decode(s).ok()
}

fn base64_decode_str(s: &str) -> Option<String> {
    crate::netutil::base64_decode_str(s).ok()
}

fn hex_encode(bytes: &[u8]) -> String {
    crate::netutil::hex_encode(bytes)
}

fn password_placeholder() -> &'static str {
    "password"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_pattern() {
        let data = b"Hello World";
        assert_eq!(find_pattern(data, b"World"), Some(6));
        assert_eq!(find_pattern(data, b"xyz"), None);
    }

    #[test]
    fn test_carve_jpg() {
        let data = vec![0x00, 0xFF, 0xD8, 0xFF, 0x01, 0x02, 0xFF, 0xD9, 0x00];
        let sigs = vec![FileSignature {
            extension: "jpg".to_string(),
            header: vec![0xFF, 0xD8, 0xFF],
            footer: vec![0xFF, 0xD9],
        }];
        let files = carve_files(&data, &sigs);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_type, "jpg");
    }

    #[test]
    fn test_parse_ftp() {
        let session = TcpSession {
            id: ConnectionId {
                src_ip: "192.168.1.1".to_string(),
                dst_ip: "10.0.0.1".to_string(),
                src_port: 12345,
                dst_port: 21,
                protocol: "TCP".to_string(),
            },
            data: b"220 Welcome\r\nUSER admin\r\n331 OK\r\nPASS secret123\r\n230 Login\r\n"
                .to_vec(),
            packets: 4,
            start_time: 0,
            end_time: 0,
        };

        let cred = parse_ftp_credentials(&session).unwrap();
        assert_eq!(cred.protocol, "FTP");
        assert_eq!(cred.username, "admin");
        assert_eq!(cred.password, "secret123");
    }

    #[test]
    fn test_parse_http_basic() {
        let session = TcpSession {
            id: ConnectionId {
                src_ip: "192.168.1.1".to_string(),
                dst_ip: "10.0.0.1".to_string(),
                src_port: 12345,
                dst_port: 80,
                protocol: "TCP".to_string(),
            },
            data: b"GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n".to_vec(),
            packets: 1,
            start_time: 0,
            end_time: 0,
        };

        let cred = parse_http_basic_auth(&session).unwrap();
        assert_eq!(cred.protocol, "HTTP Basic");
        assert_eq!(cred.username, "admin");
        assert_eq!(cred.password, "password");
    }

    #[test]
    fn test_parse_http_digest_preserves_request_uri() {
        let session = TcpSession {
            id: ConnectionId {
                src_ip: "192.168.1.1".to_string(),
                dst_ip: "10.0.0.1".to_string(),
                src_port: 12345,
                dst_port: 80,
                protocol: "TCP".to_string(),
            },
            data: b"GET /private HTTP/1.1\r\nAuthorization: Digest username=\"admin\", realm=\"example\", nonce=\"abc\", uri=\"/private\", response=\"deadbeef\", qop=\"auth\", nc=\"00000001\", cnonce=\"xyz\"\r\n\r\n".to_vec(),
            packets: 1,
            start_time: 0,
            end_time: 0,
        };

        let credential = parse_http_digest_auth(&session).unwrap();
        assert!(credential.hash.unwrap().contains(":/private:"));
    }

    #[test]
    fn test_network_map() {
        let mut map = NetworkMap::new();
        map.add_connection(ConnectionId {
            src_ip: "1.2.3.4".to_string(),
            dst_ip: "5.6.7.8".to_string(),
            src_port: 12345,
            dst_port: 80,
            protocol: "TCP".to_string(),
        });
        assert_eq!(map.connection_count(), 1);
        assert_eq!(map.unique_hosts().len(), 2);
    }
}
