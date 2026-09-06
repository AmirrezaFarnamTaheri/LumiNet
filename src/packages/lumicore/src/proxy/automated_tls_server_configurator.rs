//! Automated TLS Proxy Server Configurator
//!
//! Generates production-grade server configuration blocks with TLS certificate bindings,
//! fallback reverse proxy targets, and multi-user authentication hashes.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TlsCertificateBinding {
    pub cert_path: String,
    pub key_path: String,
    pub alpn_protocols: Vec<String>,
    pub sni_domain: String,
}

#[derive(Debug, Clone)]
pub struct ServerProvisionConfig {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_fallback_addr: String,
    pub remote_fallback_port: u16,
    pub passwords: Vec<String>,
    pub tls: TlsCertificateBinding,
    pub enable_tcp_fastopen: bool,
}

pub struct AutomatedTlsServerConfigurator {
    servers: HashMap<String, ServerProvisionConfig>,
}

impl AutomatedTlsServerConfigurator {
    pub fn new() -> Self {
        Self {
            servers: HashMap::new(),
        }
    }

    pub fn register_server(&mut self, server_id: impl Into<String>, config: ServerProvisionConfig) {
        self.servers.insert(server_id.into(), config);
    }

    pub fn get_server(&self, server_id: &str) -> Option<&ServerProvisionConfig> {
        self.servers.get(server_id)
    }

    pub fn generate_json_config(&self, server_id: &str) -> Result<String, &'static str> {
        let cfg = self.servers.get(server_id).ok_or("Server not found")?;

        let passwords_json: Vec<String> = cfg.passwords.iter().map(|p| format!("\"{}\"", p)).collect();
        let alpn_json: Vec<String> = cfg.tls.alpn_protocols.iter().map(|a| format!("\"{}\"", a)).collect();

        let json = format!(
            r#"{{
  "run_type": "server",
  "local_addr": "{}",
  "local_port": {},
  "remote_addr": "{}",
  "remote_port": {},
  "password": [{}],
  "ssl": {{
    "cert": "{}",
    "key": "{}",
    "sni": "{}",
    "alpn": [{}]
  }},
  "tcp": {{
    "fast_open": {}
  }}
}}"#,
            cfg.local_addr,
            cfg.local_port,
            cfg.remote_fallback_addr,
            cfg.remote_fallback_port,
            passwords_json.join(", "),
            cfg.tls.cert_path,
            cfg.tls.key_path,
            cfg.tls.sni_domain,
            alpn_json.join(", "),
            cfg.enable_tcp_fastopen
        );

        Ok(json)
    }

    pub fn total_servers(&self) -> usize {
        self.servers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_automated_tls_config_generation() {
        let mut configurator = AutomatedTlsServerConfigurator::new();
        let tls = TlsCertificateBinding {
            cert_path: "/etc/ssl/cert.pem".to_string(),
            key_path: "/etc/ssl/key.pem".to_string(),
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            sni_domain: "cdn.example.org".to_string(),
        };

        let cfg = ServerProvisionConfig {
            local_addr: "0.0.0.0".to_string(),
            local_port: 443,
            remote_fallback_addr: "127.0.0.1".to_string(),
            remote_fallback_port: 80,
            passwords: vec!["user_secret_token_1".to_string()],
            tls,
            enable_tcp_fastopen: true,
        };

        configurator.register_server("node-tokyo", cfg);
        let json = configurator.generate_json_config("node-tokyo").unwrap();

        assert!(json.contains("\"run_type\": \"server\""));
        assert!(json.contains("\"local_port\": 443"));
        assert!(json.contains("\"cdn.example.org\""));
        assert!(json.contains("\"user_secret_token_1\""));
    }
}
