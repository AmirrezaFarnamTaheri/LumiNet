//! Multi-Format Core Configuration Compiler
//!
//! Transforms unified outbound proxy definitions into target-specific JSON configs
//! for SingBox, Xray, and Clash.

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct UnifiedOutboundDefinition {
    pub tag: String,
    pub protocol: String,
    pub server: String,
    pub server_port: u16,
    pub uuid: String,
    pub tls_sni: String,
    pub transport_type: String,
    pub ws_path: String,
}

pub struct MultiFormatCompiler;

impl MultiFormatCompiler {
    /// Compiles definition into SingBox JSON outbound format
    pub fn compile_singbox(def: &UnifiedOutboundDefinition) -> String {
        format!(
            "{{\"type\":\"{}\",\"tag\":\"{}\",\"server\":\"{}\",\"server_port\":{},\"uuid\":\"{}\",\"tls\":{{\"enabled\":true,\"server_name\":\"{}\"}},\"transport\":{{\"type\":\"{}\",\"path\":\"{}\"}}}}",
            def.protocol, def.tag, def.server, def.server_port, def.uuid, def.tls_sni, def.transport_type, def.ws_path
        )
    }

    /// Compiles definition into Xray JSON outbound format
    pub fn compile_xray(def: &UnifiedOutboundDefinition) -> String {
        format!(
            "{{\"protocol\":\"{}\",\"tag\":\"{}\",\"settings\":{{\"vnext\":[{{\"address\":\"{}\",\"port\":{},\"users\":[{{\"id\":\"{}\"}}]}}]}},\"streamSettings\":{{\"network\":\"{}\",\"security\":\"tls\",\"tlsSettings\":{{\"serverName\":\"{}\"}},\"wsSettings\":{{\"path\":\"{}\"}}}}}}",
            def.protocol, def.tag, def.server, def.server_port, def.uuid, def.transport_type, def.tls_sni, def.ws_path
        )
    }

    /// Compiles definition into Clash proxy YAML format
    pub fn compile_clash(def: &UnifiedOutboundDefinition) -> String {
        format!(
            "- name: \"{}\"\n  type: {}\n  server: {}\n  port: {}\n  uuid: {}\n  tls: true\n  servername: {}\n  network: {}\n  ws-opts:\n    path: {}",
            def.tag, def.protocol, def.server, def.server_port, def.uuid, def.tls_sni, def.transport_type, def.ws_path
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_compilation() {
        let def = UnifiedOutboundDefinition {
            tag: "proxy-node".to_string(),
            protocol: "vless".to_string(),
            server: "edge.luminet.net".to_string(),
            server_port: 443,
            uuid: "11111111-2222-3333-4444-555555555555".to_string(),
            tls_sni: "edge.luminet.net".to_string(),
            transport_type: "ws".to_string(),
            ws_path: "/tunnel".to_string(),
        };

        let sb = MultiFormatCompiler::compile_singbox(&def);
        assert!(sb.contains("\"type\":\"vless\""));
        assert!(sb.contains("443"));

        let xr = MultiFormatCompiler::compile_xray(&def);
        assert!(xr.contains("\"protocol\":\"vless\""));
        assert!(xr.contains("streamSettings"));

        let cl = MultiFormatCompiler::compile_clash(&def);
        assert!(cl.contains("name: \"proxy-node\""));
        assert!(cl.contains("ws-opts:"));
    }
}
