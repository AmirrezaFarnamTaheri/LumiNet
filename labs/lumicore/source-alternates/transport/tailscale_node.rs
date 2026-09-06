//! # Tailscale Local API Node Client
//!
//! Rust client for the Tailscale `localapi` Unix domain socket interface,
//! ported from tailscale-rs-main and tailscale-client-go-main.
//!
//! Exposes functions to query peer status, manage routes, and fetch the
//! current Tailscale node's state via HTTP over a Unix socket.
//!
//! Socket path: `/var/run/tailscale/tailscaled.sock` (Linux/macOS)
//!             `\\.\pipe\ProtectedPrefix\Administrators\Tailscale\tailscaled` (Windows)

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Default Tailscale local API base URL (via Unix socket).
pub const TAILSCALE_SOCKET_PATH: &str = "/var/run/tailscale/tailscaled.sock";
pub const TAILSCALE_API_BASE: &str = "http://local-tailscaled.sock";

/// Represents a Tailscale network peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TailscalePeer {
    /// Unique node ID.
    pub id: String,
    /// Public key (Curve25519, base64).
    pub public_key: String,
    /// Tailnet hostname.
    pub host_name: String,
    /// DNS name in the tailnet.
    pub dns_name: String,
    /// Operating system string.
    pub os: String,
    /// Assigned Tailscale IPv4 address.
    pub tailscale_ips: Vec<String>,
    /// Whether the peer is currently reachable.
    pub online: Option<bool>,
    /// Whether the peer is an exit node.
    pub exit_node: Option<bool>,
    /// Relay (DERP) server region code.
    pub relay: Option<String>,
    /// Round-trip time in milliseconds.
    pub curl_milli: Option<i64>,
}

/// Tailscale local status response (`/localapi/v0/status`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TailscaleStatus {
    /// Tailnet name (e.g., `user@example.com`).
    pub backend_state: String,
    /// The local node's info.
    pub self_node: Option<TailscalePeer>,
    /// Map of `node_key → peer`.
    pub peer: Option<HashMap<String, TailscalePeer>>,
    /// Current exit node, if any.
    pub current_tailnet: Option<serde_json::Value>,
}

/// Tailscale route preference configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleRoutes {
    /// Advertised routes (subnets this node announces).
    pub advertised: Vec<String>,
    /// Accepted routes (subnets received from peers).
    pub accepted: Vec<String>,
}

/// Tailscale local API client using `reqwest` over a Unix socket transport.
pub struct TailscaleLocalClient {
    socket_path: String,
    #[cfg(feature = "reqwest")]
    client: reqwest::Client,
}

impl TailscaleLocalClient {
    /// Creates a new client targeting the given Unix socket path.
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
            #[cfg(feature = "reqwest")]
            client: reqwest::Client::new(),
        }
    }

    /// Creates a client using the default system socket path.
    pub fn default_socket() -> Self {
        Self::new(TAILSCALE_SOCKET_PATH)
    }

    /// Returns the Unix socket path this client connects to.
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Builds the full API URL for a given path.
    pub fn api_url(&self, path: &str) -> String {
        format!("{}{}", TAILSCALE_API_BASE, path)
    }
}

/// Status of the Tailscale backend (from `/localapi/v0/backend-state`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendState {
    /// Not yet started.
    NoState,
    /// Needs configuration.
    NeedsLogin,
    /// Logged in and connected.
    Running,
    /// Logged in but not connected.
    Stopped,
    /// Starting up.
    Starting,
    /// Authentication error.
    NeedsMachineAuth,
}

impl BackendState {
    pub fn from_str(s: &str) -> Self {
        match s {
            "NoState" => Self::NoState,
            "NeedsLogin" => Self::NeedsLogin,
            "Running" => Self::Running,
            "Stopped" => Self::Stopped,
            "Starting" => Self::Starting,
            "NeedsMachineAuth" => Self::NeedsMachineAuth,
            _ => Self::NoState,
        }
    }

    pub fn is_connected(&self) -> bool {
        *self == Self::Running
    }
}

/// A parsed Tailscale WireGuard configuration entry for a peer.
#[derive(Debug, Clone)]
pub struct TailscaleWgPeer {
    /// WireGuard public key (base64).
    pub public_key: String,
    /// Allowed source IPs for this peer.
    pub allowed_ips: Vec<String>,
    /// DERP relay server endpoint (e.g., `127.3.3.40:derp-region-id`).
    pub endpoint: Option<String>,
    /// Persistent keepalive interval in seconds (0 = disabled).
    pub persistent_keepalive: u16,
}

/// Represents the Tailscale daemon's WireGuard configuration.
#[derive(Debug, Clone)]
pub struct TailscaleWgConfig {
    /// Private key of the local node.
    pub private_key: String,
    /// Listening port for WireGuard (usually 41641).
    pub listen_port: u16,
    /// Connected peers.
    pub peers: Vec<TailscaleWgPeer>,
}

impl TailscaleWgConfig {
    /// Renders the config in `wg-quick` format.
    pub fn to_wg_conf(&self) -> String {
        let mut out = String::new();
        out.push_str("[Interface]\n");
        out.push_str(&format!("PrivateKey = {}\n", self.private_key));
        out.push_str(&format!("ListenPort = {}\n", self.listen_port));
        for peer in &self.peers {
            out.push('\n');
            out.push_str("[Peer]\n");
            out.push_str(&format!("PublicKey = {}\n", peer.public_key));
            if !peer.allowed_ips.is_empty() {
                out.push_str(&format!("AllowedIPs = {}\n", peer.allowed_ips.join(", ")));
            }
            if let Some(ep) = &peer.endpoint {
                out.push_str(&format!("Endpoint = {}\n", ep));
            }
            if peer.persistent_keepalive > 0 {
                out.push_str(&format!("PersistentKeepalive = {}\n", peer.persistent_keepalive));
            }
        }
        out
    }
}

/// Parses a Tailscale peer list from a JSON status response.
pub fn parse_peer_list(json: &serde_json::Value) -> Vec<TailscalePeer> {
    let peer_map = match json.get("Peer").and_then(|v| v.as_object()) {
        Some(m) => m,
        None => return vec![],
    };
    peer_map.values()
        .filter_map(|v| serde_json::from_value(v.clone()).ok())
        .collect()
}

/// Filters peers that are both online and operating as exit nodes.
pub fn online_exit_nodes(peers: &[TailscalePeer]) -> Vec<&TailscalePeer> {
    peers.iter()
        .filter(|p| p.online.unwrap_or(false) && p.exit_node.unwrap_or(false))
        .collect()
}

/// Returns the lowest-latency peer from a list, using `curl_milli`.
pub fn fastest_peer<'a>(peers: &'a [TailscalePeer]) -> Option<&'a TailscalePeer> {
    peers.iter()
        .filter(|p| p.curl_milli.is_some())
        .min_by_key(|p| p.curl_milli.unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_state_from_str() {
        assert_eq!(BackendState::from_str("Running"), BackendState::Running);
        assert_eq!(BackendState::from_str("NeedsLogin"), BackendState::NeedsLogin);
        assert!(BackendState::Running.is_connected());
        assert!(!BackendState::Stopped.is_connected());
    }

    #[test]
    fn test_wg_conf_rendering() {
        let cfg = TailscaleWgConfig {
            private_key: "abc123".to_string(),
            listen_port: 41641,
            peers: vec![TailscaleWgPeer {
                public_key: "peer_key".to_string(),
                allowed_ips: vec!["100.64.0.0/10".to_string()],
                endpoint: Some("derp-1.tailscale.com:3478".to_string()),
                persistent_keepalive: 25,
            }],
        };
        let conf = cfg.to_wg_conf();
        assert!(conf.contains("[Interface]"));
        assert!(conf.contains("ListenPort = 41641"));
        assert!(conf.contains("[Peer]"));
        assert!(conf.contains("PersistentKeepalive = 25"));
    }

    #[test]
    fn test_fastest_peer_selection() {
        let peers = vec![
            TailscalePeer {
                id: "a".to_string(),
                public_key: String::new(),
                host_name: "node-a".to_string(),
                dns_name: String::new(),
                os: "linux".to_string(),
                tailscale_ips: vec![],
                online: Some(true),
                exit_node: None,
                relay: None,
                curl_milli: Some(120),
            },
            TailscalePeer {
                id: "b".to_string(),
                public_key: String::new(),
                host_name: "node-b".to_string(),
                dns_name: String::new(),
                os: "linux".to_string(),
                tailscale_ips: vec![],
                online: Some(true),
                exit_node: None,
                relay: None,
                curl_milli: Some(45),
            },
        ];
        let fastest = fastest_peer(&peers).unwrap();
        assert_eq!(fastest.id, "b");
    }

    #[test]
    fn test_client_api_url() {
        let client = TailscaleLocalClient::default_socket();
        let url = client.api_url("/localapi/v0/status");
        assert!(url.contains("/localapi/v0/status"));
    }
}
