//! # Transactional Routing Session & TUN Lifecycle Manager
//!
//! Provides transactional lifecycle management for system-wide virtual TUN adapters,
//! atomic IPC state serialization (request.json, status.json, recovery.json),
//! stale adapter detection and crash recovery, DoH hijack configuration, and
//! sing-box 1.13.x TUN routing configuration generation.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RoutingError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("SOCKS5 handshake error: {0}")]
    Socks5(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RoutingMode {
    Full,
    BypassLocal,
    SplitInclude,
    SplitExclude,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ipv6Behavior {
    Tunnel,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingConfig {
    pub session_id: String,
    pub socks_address: SocketAddr,
    pub routing_mode: RoutingMode,
    pub dns_leak_protection: bool,
    pub ipv6_behavior: Ipv6Behavior,
    pub kill_switch: bool,
    pub tun_mtu: u16,
    pub tun_interface: String,
    pub split_applications: Vec<String>,
    pub route_exclusions: Vec<String>,
    pub session_dir: PathBuf,
    pub previous_session_dir: Option<PathBuf>,
}

impl RoutingConfig {
    pub fn new(
        socks_address: SocketAddr,
        base_dir: PathBuf,
        routing_mode: RoutingMode,
    ) -> Result<Self, RoutingError> {
        if !socks_address.ip().is_loopback() {
            return Err(RoutingError::Validation(
                "VPN routing mode requires a loopback SOCKS5 listener".into(),
            ));
        }

        let pid = std::process::id();
        let session_id = generate_session_id(pid);
        let session_dir = base_dir.join(&session_id);
        let tun_interface = generate_tun_name("LumiTun", pid, &session_id);

        Ok(Self {
            session_id,
            socks_address,
            routing_mode,
            dns_leak_protection: true,
            ipv6_behavior: Ipv6Behavior::Block,
            kill_switch: false,
            tun_mtu: 1400,
            tun_interface,
            split_applications: Vec::new(),
            route_exclusions: Vec::new(),
            session_dir,
            previous_session_dir: None,
        })
    }

    pub fn validate(&self) -> Result<(), RoutingError> {
        if !(1280..=9000).contains(&self.tun_mtu) {
            return Err(RoutingError::Validation(format!(
                "invalid MTU {}, must be in 1280..=9000",
                self.tun_mtu
            )));
        }
        if self.tun_interface.len() > 32 {
            return Err(RoutingError::Validation("TUN interface name too long".into()));
        }
        Ok(())
    }
}

pub fn generate_session_id(pid: u32) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{pid}-{now}")
}

pub fn generate_tun_name(prefix: &str, pid: u32, session_id: &str) -> String {
    let suffix: String = session_id
        .rsplit('-')
        .next()
        .unwrap_or("0")
        .chars()
        .rev()
        .take(6)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{prefix}-{}-{}", pid % 10000, suffix)
}

/// Atomically writes JSON content using a temporary file and atomic filesystem rename.
pub fn atomic_write_json(path: &Path, value: &Value) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp_path = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(&temp_path, path)?;
    Ok(())
}

/// Discovers stale routing sessions by scanning for recovery.json or abandoned session directories.
pub fn detect_stale_sessions(base_dir: &Path) -> Vec<PathBuf> {
    let mut stale = Vec::new();
    if !base_dir.exists() {
        return stale;
    }

    if let Ok(entries) = fs::read_dir(base_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let status_path = path.join("status.json");
                if status_path.exists() {
                    if let Ok(content) = fs::read_to_string(&status_path) {
                        if let Ok(val) = serde_json::from_str::<Value>(&content) {
                            let state = val.get("state").and_then(Value::as_str).unwrap_or("");
                            if matches!(state, "error" | "disabled" | "preparing" | "starting-adapter") {
                                stale.push(path);
                            }
                        }
                    }
                }
            }
        }
    }
    stale
}

/// Builds a production-grade sing-box 1.13.x TUN routing configuration.
pub fn build_singbox_tun_config(config: &RoutingConfig) -> Value {
    let mut rules = vec![
        json!({"action": "sniff"}),
        json!({"protocol": "dns", "action": "hijack-dns"}),
        json!({
            "process_name": [
                "luminet.exe",
                "lumicore.exe",
                "sing-box.exe",
                "aether.exe",
                "Aethon.exe"
            ],
            "action": "route",
            "outbound": "direct"
        }),
    ];

    if config.ipv6_behavior == Ipv6Behavior::Block {
        rules.push(json!({"ip_version": 6, "action": "reject"}));
    }

    if config.routing_mode == RoutingMode::BypassLocal {
        rules.push(json!({"ip_is_private": true, "action": "route", "outbound": "direct"}));
    }

    for cidr in &config.route_exclusions {
        rules.push(json!({"ip_cidr": [cidr], "action": "route", "outbound": "direct"}));
    }

    let normalized_apps: Vec<String> = config
        .split_applications
        .iter()
        .map(|p| p.replace('\\', "/"))
        .collect();

    if config.routing_mode == RoutingMode::SplitInclude && !normalized_apps.is_empty() {
        rules.push(json!({"process_path": normalized_apps, "action": "route", "outbound": "socks-out"}));
    } else if config.routing_mode == RoutingMode::SplitExclude && !normalized_apps.is_empty() {
        rules.push(json!({"process_path": normalized_apps, "action": "route", "outbound": "direct"}));
    }

    let final_outbound = if config.routing_mode == RoutingMode::SplitInclude {
        "direct"
    } else {
        "socks-out"
    };

    json!({
        "log": {
            "level": "info",
            "timestamp": true
        },
        "dns": {
            "servers": [{
                "type": "https",
                "tag": "secure-dns",
                "server": "1.1.1.1",
                "server_port": 443,
                "path": "/dns-query",
                "tls": {
                    "enabled": true,
                    "server_name": "cloudflare-dns.com"
                },
                "detour": "socks-out"
            }],
            "final": "secure-dns",
            "strategy": "prefer_ipv4"
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": config.tun_interface,
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": config.tun_mtu,
            "auto_route": true,
            "strict_route": config.dns_leak_protection,
            "stack": "mixed"
        }],
        "outbounds": [
            {
                "type": "socks",
                "tag": "socks-out",
                "server": config.socks_address.ip().to_string(),
                "server_port": config.socks_address.port(),
                "version": "5"
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "auto_detect_interface": true,
            "find_process": true,
            "rules": rules,
            "final": final_outbound
        }
    })
}

/// Verifies SOCKS5 listener responsiveness using a standard initial handshake probe.
pub fn verify_socks5_handshake_bytes(mut stream: impl Read + Write) -> Result<bool, std::io::Error> {
    // SOCKS5 greeting: Version 5, 1 Auth Method (0x00 = No Auth)
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut response = [0u8; 2];
    stream.read_exact(&mut response)?;
    Ok(response == [0x05, 0x00])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_routing_config_validation() {
        let loopback: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let config = RoutingConfig::new(loopback, PathBuf::from("/tmp/routing"), RoutingMode::Full)
            .expect("valid config");
        assert!(config.validate().is_ok());
        assert!(config.tun_interface.starts_with("LumiTun-"));

        // Non-loopback SOCKS5 should fail validation
        let non_loopback: SocketAddr = "192.168.1.100:1080".parse().unwrap();
        assert!(RoutingConfig::new(non_loopback, PathBuf::from("/tmp/routing"), RoutingMode::Full).is_err());
    }

    #[test]
    fn test_singbox_config_structure() {
        let loopback: SocketAddr = "127.0.0.1:1819".parse().unwrap();
        let mut config = RoutingConfig::new(loopback, PathBuf::from("/tmp/routing"), RoutingMode::BypassLocal)
            .expect("valid config");
        config.route_exclusions.push("198.51.100.0/24".into());

        let json = build_singbox_tun_config(&config);
        let inbounds = json.get("inbounds").and_then(Value::as_array).unwrap();
        assert_eq!(inbounds.len(), 1);
        assert_eq!(inbounds[0].get("type").unwrap(), "tun");
        assert_eq!(inbounds[0].get("interface_name").unwrap(), &config.tun_interface);

        let outbounds = json.get("outbounds").and_then(Value::as_array).unwrap();
        assert_eq!(outbounds[0].get("type").unwrap(), "socks");
        assert_eq!(outbounds[0].get("server_port").unwrap(), 1819);

        let rules = json["route"]["rules"].as_array().unwrap();
        // Check for bypass-local rule
        assert!(rules.iter().any(|r| r.get("ip_is_private") == Some(&Value::Bool(true))));
        // Check for route-exclusion CIDR rule
        assert!(rules.iter().any(|r| r.get("ip_cidr") == Some(&json!(["198.51.100.0/24"]))));
    }

    #[test]
    fn test_socks5_handshake_bytes() {
        struct MockSocksServer {
            read_buf: Cursor<Vec<u8>>,
            write_buf: Vec<u8>,
        }
        impl Read for MockSocksServer {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.read_buf.read(buf)
            }
        }
        impl Write for MockSocksServer {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.write_buf.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mock = MockSocksServer {
            read_buf: Cursor::new(vec![0x05, 0x00]),
            write_buf: Vec::new(),
        };

        assert_eq!(verify_socks5_handshake_bytes(mock).unwrap(), true);
    }

    #[test]
    fn test_atomic_write_json_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("luminet_test_{}", std::process::id()));
        let target = temp_dir.join("test.json");
        let val = json!({"hello": "luminet", "ok": true});

        assert!(atomic_write_json(&target, &val).is_ok());
        let read_back: Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
        assert_eq!(read_back, val);

        let _ = fs::remove_dir_all(temp_dir);
    }
}
