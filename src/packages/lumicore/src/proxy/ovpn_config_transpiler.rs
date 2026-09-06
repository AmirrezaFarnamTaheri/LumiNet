//! # OpenVPN Config Transpiler
//!
//! Parses and transpiles OpenVPN (.ovpn) configuration profiles, inline PEM certificates,
//! cipher configurations, and transport directives into LumiNet unified node profiles.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TranspiledOvpnProfile {
    pub remote_host: String,
    pub remote_port: u16,
    pub proto: String,
    pub cipher: String,
    pub auth_user_pass: bool,
    pub ca_cert: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub tls_auth_key: Option<String>,
}

pub struct OvpnConfigTranspiler;

impl OvpnConfigTranspiler {
    pub fn parse(raw_ovpn_content: &str) -> Result<TranspiledOvpnProfile, String> {
        let mut remote_host = String::new();
        let mut remote_port: u16 = 1194;
        let mut proto = "udp".to_string();
        let mut cipher = "AES-256-GCM".to_string();
        let mut auth_user_pass = false;

        let mut in_ca = false;
        let mut in_cert = false;
        let mut in_key = false;
        let mut in_tls_auth = false;

        let mut ca_buf = String::new();
        let mut cert_buf = String::new();
        let mut key_buf = String::new();
        let mut tls_auth_buf = String::new();

        for line in raw_ovpn_content.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("<ca>") {
                in_ca = true;
                continue;
            } else if trimmed.starts_with("</ca>") {
                in_ca = false;
                continue;
            }

            if trimmed.starts_with("<cert>") {
                in_cert = true;
                continue;
            } else if trimmed.starts_with("</cert>") {
                in_cert = false;
                continue;
            }

            if trimmed.starts_with("<key>") {
                in_key = true;
                continue;
            } else if trimmed.starts_with("</key>") {
                in_key = false;
                continue;
            }

            if trimmed.starts_with("<tls-auth>") {
                in_tls_auth = true;
                continue;
            } else if trimmed.starts_with("</tls-auth>") {
                in_tls_auth = false;
                continue;
            }

            if in_ca {
                ca_buf.push_str(line);
                ca_buf.push('\n');
                continue;
            }
            if in_cert {
                cert_buf.push_str(line);
                cert_buf.push('\n');
                continue;
            }
            if in_key {
                key_buf.push_str(line);
                key_buf.push('\n');
                continue;
            }
            if in_tls_auth {
                tls_auth_buf.push_str(line);
                tls_auth_buf.push('\n');
                continue;
            }

            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            match parts[0] {
                "remote" if parts.len() >= 2 => {
                    remote_host = parts[1].to_string();
                    if parts.len() >= 3 {
                        remote_port = parts[2].parse::<u16>().unwrap_or(1194);
                    }
                    if parts.len() >= 4 {
                        proto = parts[3].to_lowercase();
                    }
                }
                "proto" if parts.len() >= 2 => {
                    proto = parts[1].to_lowercase();
                }
                "cipher" if parts.len() >= 2 => {
                    cipher = parts[1].to_string();
                }
                "auth-user-pass" => {
                    auth_user_pass = true;
                }
                _ => {}
            }
        }

        if remote_host.is_empty() {
            return Err("Missing 'remote' host in OpenVPN config".to_string());
        }

        Ok(TranspiledOvpnProfile {
            remote_host,
            remote_port,
            proto,
            cipher,
            auth_user_pass,
            ca_cert: if ca_buf.is_empty() { None } else { Some(ca_buf.trim().to_string()) },
            client_cert: if cert_buf.is_empty() { None } else { Some(cert_buf.trim().to_string()) },
            client_key: if key_buf.is_empty() { None } else { Some(key_buf.trim().to_string()) },
            tls_auth_key: if tls_auth_buf.is_empty() { None } else { Some(tls_auth_buf.trim().to_string()) },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ovpn_config_transpiler() {
        let ovpn = r#"
client
dev tun
proto tcp
remote vpn.example.com 443
cipher AES-128-GCM
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
MIIB...CA...
-----END CERTIFICATE-----
</ca>
<key>
-----BEGIN PRIVATE KEY-----
MIIE...KEY...
-----END PRIVATE KEY-----
</key>
"#;

        let profile = OvpnConfigTranspiler::parse(ovpn).unwrap();
        assert_eq!(profile.remote_host, "vpn.example.com");
        assert_eq!(profile.remote_port, 443);
        assert_eq!(profile.proto, "tcp");
        assert_eq!(profile.cipher, "AES-128-GCM");
        assert!(profile.auth_user_pass);
        assert!(profile.ca_cert.unwrap().contains("BEGIN CERTIFICATE"));
        assert!(profile.client_key.unwrap().contains("BEGIN PRIVATE KEY"));
    }
}
