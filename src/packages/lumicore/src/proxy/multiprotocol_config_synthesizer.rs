#[derive(Debug, Clone, PartialEq)]
pub enum TransportProtocol {
    TcpReality,
    WebsocketTls,
    GrpcTls,
}

#[derive(Debug, Clone)]
pub struct ServerConfigPreset {
    pub listen_port: u16,
    pub server_uuid: String,
    pub sni_dest: String,
    pub transport: TransportProtocol,
}

#[derive(Debug, Default)]
pub struct MultiprotocolConfigSynthesizer;

impl MultiprotocolConfigSynthesizer {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_singbox_inbound_json(&self, preset: &ServerConfigPreset) -> String {
        let proto_str = match preset.transport {
            TransportProtocol::TcpReality => "vless-reality",
            TransportProtocol::WebsocketTls => "vless-ws",
            TransportProtocol::GrpcTls => "vless-grpc",
        };

        format!(
            r#"{{"type":"vless","tag":"in-{}","listen_port":{},"users":[{{"uuid":"{}"}}],"tls":{{"enabled":true,"server_name":"{}"}}}}"#,
            proto_str, preset.listen_port, preset.server_uuid, preset.sni_dest
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiprotocol_config_generation() {
        let syn = MultiprotocolConfigSynthesizer::new();
        let preset = ServerConfigPreset {
            listen_port: 8443,
            server_uuid: "11111111-2222-3333-4444-555555555555".to_string(),
            sni_dest: "cdn.cloudflare.com".to_string(),
            transport: TransportProtocol::TcpReality,
        };

        let json = syn.generate_singbox_inbound_json(&preset);
        assert!(json.contains("8443"));
        assert!(json.contains("cdn.cloudflare.com"));
        assert!(json.contains("vless-reality"));
    }
}
