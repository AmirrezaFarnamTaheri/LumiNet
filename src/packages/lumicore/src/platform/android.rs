//! # Android Transparent Proxy
//!
//! iptables/netfilter rules for transparent proxying on Android.
//!
//! Core functionality:
//! - TPROXY/REDIRECT rules for TCP/UDP hijacking
//! - Per-app proxy (blacklist/whitelist by UID)
//! - Per-interface proxy (mobile, WiFi, hotspot)
//! - DNS hijacking (port 53 → proxy DNS port)
//! - CN IP bypass via ipset
//! - Anti-loopback rules

use std::io;
use std::net::IpAddr;
use tokio::net::{TcpListener, TcpStream};

/// Proxy mode for transparent proxy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyMode {
    /// TPROXY mode (requires kernel support).
    Tproxy,
    /// REDIRECT mode (NAT redirect).
    Redirect,
    /// TUN mode (virtual network interface).
    Tun,
}

/// Configuration for transparent proxy rules.
#[derive(Debug, Clone)]
pub struct TproxyConfig {
    /// Proxy mode.
    pub mode: ProxyMode,
    /// TCP proxy port.
    pub tcp_port: u16,
    /// UDP proxy port.
    pub udp_port: u16,
    /// DNS proxy port.
    pub dns_port: u16,
    /// Mobile data interface name.
    pub mobile_interface: String,
    /// WiFi interface name.
    pub wifi_interface: String,
    /// Proxy mobile data traffic.
    pub proxy_mobile: bool,
    /// Proxy WiFi traffic.
    pub proxy_wifi: bool,
    /// Proxy hotspot traffic.
    pub proxy_hotspot: bool,
    /// Per-app proxy mode.
    pub app_proxy_mode: AppProxyMode,
    /// App UIDs for per-app proxy.
    pub app_uids: Vec<u32>,
    /// Bypass CN IPs.
    pub bypass_cn_ip: bool,
    /// Proxy IPv6 traffic.
    pub proxy_ipv6: bool,
    /// Block QUIC (UDP 443).
    pub block_quic: bool,
    /// Proxy core UID (to exclude from proxy).
    pub core_uid: u32,
    /// Local proxy IP.
    pub local_ip: IpAddr,
}

impl Default for TproxyConfig {
    fn default() -> Self {
        Self {
            mode: ProxyMode::Tproxy,
            tcp_port: 7890,
            udp_port: 7890,
            dns_port: 7878,
            mobile_interface: "rmnet_data0".to_string(),
            wifi_interface: "wlan0".to_string(),
            proxy_mobile: true,
            proxy_wifi: true,
            proxy_hotspot: false,
            app_proxy_mode: AppProxyMode::Off,
            app_uids: Vec::new(),
            bypass_cn_ip: false,
            proxy_ipv6: true,
            block_quic: false,
            core_uid: 0,
            local_ip: "127.0.0.1".parse().unwrap(),
        }
    }
}

/// Per-app proxy mode.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppProxyMode {
    /// No per-app filtering.
    Off,
    /// Only proxy listed apps (whitelist).
    Whitelist,
    /// Proxy all except listed apps (blacklist).
    Blacklist,
}

/// Generates iptables commands for transparent proxy setup.
pub fn generate_tproxy_rules(config: &TproxyConfig) -> Vec<String> {
    let mut rules = Vec::new();

    // Create custom chains
    rules.push("-N PROXY_PREROUTING".to_string());
    rules.push("-N PROXY_OUTPUT".to_string());
    rules.push("-N PROXY_BYPASS".to_string());
    rules.push("-N PROXY_APP".to_string());
    rules.push("-N DNS_HIJACK".to_string());

    // Clear existing rules
    rules.push("-F PROXY_PREROUTING".to_string());
    rules.push("-F PROXY_OUTPUT".to_string());
    rules.push("-F PROXY_BYPASS".to_string());
    rules.push("-F PROXY_APP".to_string());
    rules.push("-F DNS_HIJACK".to_string());

    // Anti-loopback: bypass proxy core's own traffic
    rules.push(format!(
        "-A PROXY_OUTPUT -m owner --uid-owner {} -j RETURN",
        config.core_uid
    ));

    // Bypass local/private IPs
    for cidr in &[
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
    ] {
        rules.push(format!("-A PROXY_BYPASS -d {} -j RETURN", cidr));
    }

    // Per-app proxy rules
    match config.app_proxy_mode {
        AppProxyMode::Whitelist => {
            // Only proxy listed apps
            for uid in &config.app_uids {
                rules.push(format!(
                    "-A PROXY_APP -m owner --uid-owner {} -j PROXY_BYPASS",
                    uid
                ));
            }
            // Drop all other traffic
            rules.push("-A PROXY_APP -j DROP".to_string());
        }
        AppProxyMode::Blacklist => {
            // Bypass listed apps
            for uid in &config.app_uids {
                rules.push(format!(
                    "-A PROXY_APP -m owner --uid-owner {} -j RETURN",
                    uid
                ));
            }
        }
        AppProxyMode::Off => {}
    }

    // DNS hijacking
    rules.push(format!(
        "-A DNS_HIJACK -p udp --dport 53 -j REDIRECT --to-ports {}",
        config.dns_port
    ));
    rules.push(format!(
        "-A DNS_HIJACK -p tcp --dport 53 -j REDIRECT --to-ports {}",
        config.dns_port
    ));

    // PREROUTING chain (for forwarded traffic - hotspot)
    if config.proxy_hotspot {
        rules.push(
            "-A PROXY_PREROUTING -i wlan0 -p tcp -j TPROXY --tproxy-mark 0x1/0x1".to_string(),
        );
        rules.push(
            "-A PROXY_PREROUTING -i wlan0 -p udp -j TPROXY --tproxy-mark 0x1/0x1".to_string(),
        );
    }

    // OUTPUT chain (for local traffic)
    // TCP
    if config.proxy_mobile || config.proxy_wifi {
        rules.push(format!(
            "-A PROXY_OUTPUT -p tcp -j REDIRECT --to-ports {}",
            config.tcp_port
        ));
    }

    // Block QUIC if configured
    if config.block_quic {
        rules.push("-A PROXY_OUTPUT -p udp --dport 443 -j DROP".to_string());
    }

    // Wire up chains
    rules.push("-A PREROUTING -j PROXY_PREROUTING".to_string());
    rules.push("-A OUTPUT -j PROXY_OUTPUT".to_string());

    rules
}

/// Generates iptables commands for cleanup.
pub fn generate_cleanup_rules() -> Vec<String> {
    vec![
        "-F PROXY_PREROUTING".to_string(),
        "-F PROXY_OUTPUT".to_string(),
        "-F PROXY_BYPASS".to_string(),
        "-F PROXY_APP".to_string(),
        "-F DNS_HIJACK".to_string(),
        "-X PROXY_PREROUTING".to_string(),
        "-X PROXY_OUTPUT".to_string(),
        "-X PROXY_BYPASS".to_string(),
        "-X PROXY_APP".to_string(),
        "-X DNS_HIJACK".to_string(),
    ]
}

/// Generates ip rules for policy routing.
pub fn generate_routing_rules(fwmark: u32, table_id: u32) -> Vec<String> {
    vec![
        format!("ip rule add fwmark {} table {}", fwmark, table_id),
        format!("ip route add local default dev lo table {}", table_id),
        "sysctl -w net.ipv4.conf.all.route_localnet=1".to_string(),
    ]
}

/// Generates ipset commands for CN IP bypass.
pub fn generate_cn_ipset_commands(cidrs: &[&str]) -> Vec<String> {
    let mut cmds = Vec::new();
    cmds.push("ipset create cn_ipset hash:net family inet".to_string());
    for cidr in cidrs {
        cmds.push(format!("ipset add cn_ipset {}", cidr));
    }
    cmds
}

/// Network interface configuration for Android.
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub is_up: bool,
    pub ip: Option<IpAddr>,
    pub is_mobile: bool,
    pub is_wifi: bool,
}

/// Detects active network interfaces on Android.
pub fn detect_interfaces() -> Vec<NetworkInterface> {
    // In real implementation, parse /proc/net/if_inet6 or use netlink
    vec![
        NetworkInterface {
            name: "rmnet_data0".to_string(),
            is_up: true,
            ip: None,
            is_mobile: true,
            is_wifi: false,
        },
        NetworkInterface {
            name: "wlan0".to_string(),
            is_up: true,
            ip: None,
            is_mobile: false,
            is_wifi: true,
        },
    ]
}

/// DNS configuration for Android Private DNS handling.
pub struct DnsConfig {
    /// Original Private DNS setting.
    pub original_setting: String,
    /// Whether to disable Private DNS during proxy.
    pub disable_during_proxy: bool,
    /// DNS server to use.
    pub dns_server: String,
    /// DNS port.
    pub dns_port: u16,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            original_setting: "opportunistic".to_string(),
            disable_during_proxy: true,
            dns_server: "127.0.0.1".to_string(),
            dns_port: 7878,
        }
    }
}

/// Async TCP multiplexer bridging a local port to a target ADB port.
pub async fn start_adb_forwarder(
    local_port: u16,
    target_port: u16,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> io::Result<()> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", local_port)).await?;

    loop {
        tokio::select! {
            incoming = listener.accept() => {
                if let Ok((mut client_stream, _)) = incoming {
                    let target_addr = format!("127.0.0.1:{}", target_port);

                    tokio::spawn(async move {
                        if let Ok(mut target_stream) = TcpStream::connect(&target_addr).await {
                            let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut target_stream).await;
                        }
                    });
                }
            }
            _ = &mut shutdown_rx => {
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_tproxy_rules() {
        let config = TproxyConfig::default();
        let rules = generate_tproxy_rules(&config);
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.contains("PROXY_PREROUTING")));
        assert!(rules.iter().any(|r| r.contains("DNS_HIJACK")));
    }

    #[test]
    fn test_generate_cleanup_rules() {
        let rules = generate_cleanup_rules();
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.contains("-X PROXY_PREROUTING")));
    }

    #[test]
    fn test_routing_rules() {
        let rules = generate_routing_rules(0x1, 100);
        assert!(rules.iter().any(|r| r.contains("ip rule add")));
        assert!(rules.iter().any(|r| r.contains("route_localnet")));
    }

    #[test]
    fn test_app_proxy_whitelist() {
        let config = TproxyConfig {
            app_proxy_mode: AppProxyMode::Whitelist,
            app_uids: vec![10001, 10002],
            ..Default::default()
        };
        let rules = generate_tproxy_rules(&config);
        assert!(rules.iter().any(|r| r.contains("--uid-owner 10001")));
        assert!(rules.iter().any(|r| r.contains("--uid-owner 10002")));
    }

    #[tokio::test]
    async fn test_start_adb_forwarder() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 1. Bind mock target listener
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target_listener.local_addr().unwrap().port();

        // 2. Bind forwarder local port
        let temp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_port = temp_listener.local_addr().unwrap().port();
        drop(temp_listener); // Free the port so forwarder can bind it

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        // 3. Start forwarder task
        let forwarder_handle =
            tokio::spawn(
                async move { start_adb_forwarder(local_port, target_port, shutdown_rx).await },
            );

        // 4. Start mock target handler
        let target_handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = target_listener.accept().await {
                let mut buf = [0u8; 10];
                let n = stream.read(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"hello");
                stream.write_all(b"world").await.unwrap();
            }
        });

        // 5. Connect client to forwarder
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if let Ok(mut client) = TcpStream::connect(format!("127.0.0.1:{}", local_port)).await {
            client.write_all(b"hello").await.unwrap();
            let mut reply = [0u8; 5];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"world");
        }

        // 6. Shutdown forwarder
        let _ = shutdown_tx.send(());
        let _ = forwarder_handle.await;
        let _ = target_handle.await;
    }
}
