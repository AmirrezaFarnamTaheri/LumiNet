//! Autonomous hardware and network advisor for DNS tunnel tuning.
//!
//! Provides deterministic configuration recommendations for both client and server nodes
//! based on hardware capacity (CPU cores, RAM), network physical transport (Mobile, WiFi, DSL, Fiber),
//! link quality/loss profile, upstream resolver topologies, and workload characteristics.

use serde::{Deserialize, Serialize};

/// Network connection medium of the client endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkConnection {
    Mobile4g5g,
    Wifi,
    Dsl,
    Fiber,
}

impl Default for NetworkConnection {
    fn default() -> Self {
        Self::Mobile4g5g
    }
}

/// Link stability and quality level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkQuality {
    Excellent,
    Good,
    Medium,
    Poor,
}

impl Default for NetworkQuality {
    fn default() -> Self {
        Self::Good
    }
}

impl NetworkQuality {
    /// Numerical factor between 0.3 and 1.0 representing link reliability.
    pub fn reliability_factor(&self) -> f32 {
        match self {
            Self::Excellent => 1.0,
            Self::Good => 0.8,
            Self::Medium => 0.5,
            Self::Poor => 0.3,
        }
    }

    /// Whether the network suffers from high packet drop / lossiness.
    pub fn is_lossy(&self) -> bool {
        self.reliability_factor() <= 0.5
    }
}

/// Number of active DNS resolvers configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverCensus {
    Few,    // < 10 resolvers
    Medium, // 10 - 50 resolvers
    Many,   // > 50 resolvers
}

impl Default for ResolverCensus {
    fn default() -> Self {
        Self::Few
    }
}

/// MTU priority optimization strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MtuPreference {
    Stable,   // Lower MTU, resilient across restrictive resolvers
    Balanced, // Moderate MTU
    Speed,    // High MTU, maximizing payload density
}

impl Default for MtuPreference {
    fn default() -> Self {
        Self::Balanced
    }
}

/// Primary workload type for tunnel traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UseCase {
    Browse,
    Chat,
    Stream,
    Download,
    Mixed,
}

impl Default for UseCase {
    fn default() -> Self {
        Self::Browse
    }
}

/// Cryptographic cipher preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionPreference {
    Light,    // XOR (ID 1)
    Balanced, // ChaCha20-Poly1305 (ID 2)
    Strong,   // AES-256-GCM (ID 5)
}

impl Default for EncryptionPreference {
    fn default() -> Self {
        Self::Light
    }
}

/// Hardware specification and network conditions of the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHardwareProfile {
    pub connection: NetworkConnection,
    pub quality: NetworkQuality,
    pub cpu_cores: usize,
    pub ram_mb: usize,
    pub resolver_census: ResolverCensus,
    pub mtu_preference: MtuPreference,
    pub use_case: UseCase,
    pub encryption_preference: EncryptionPreference,
}

impl Default for ClientHardwareProfile {
    fn default() -> Self {
        Self {
            connection: NetworkConnection::Mobile4g5g,
            quality: NetworkQuality::Excellent,
            cpu_cores: 2,
            ram_mb: 2048,
            resolver_census: ResolverCensus::Few,
            mtu_preference: MtuPreference::Balanced,
            use_case: UseCase::Browse,
            encryption_preference: EncryptionPreference::Light,
        }
    }
}

/// Recommended client configuration parameters computed by the advisor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientRecommendation {
    pub data_encryption_method: u8,
    pub packet_duplication_count: u8,
    pub setup_packet_duplication_count: u8,
    pub resolver_balancing_strategy: u8, // 0: RoundRobin, 1: Random, 3: LowestLoss, 4: LowestLatency
    pub stream_resolver_failover_resend_threshold: u32,
    pub stream_resolver_failover_cooldown_sec: u32,
    pub min_upload_mtu: u16,
    pub min_download_mtu: u16,
    pub max_upload_mtu: u16,
    pub max_download_mtu: u16,
    pub mtu_test_parallelism: usize,
    pub mtu_test_retries: u32,
    pub mtu_test_timeout_sec: u32,
    pub tunnel_reader_workers: usize,
    pub tunnel_writer_workers: usize,
    pub tunnel_process_workers: usize,
    pub tx_channel_size: usize,
    pub rx_channel_size: usize,
    pub resolver_udp_connection_pool_size: usize,
    pub upload_compression_type: u8,   // 0: None, 1: ZSTD, 2: LZ4
    pub download_compression_type: u8, // 0: None, 1: ZSTD, 2: LZ4
    pub arq_window_size: usize,
    pub arq_data_nack_max_gap: usize,
    pub arq_max_data_retries: usize,
    pub arq_max_rto_sec: f32,
    pub ping_aggressive_interval_sec: f32,
    pub ping_lazy_interval_sec: f32,
    pub ping_cooldown_interval_sec: f32,
    pub dispatcher_idle_poll_interval_sec: f32,
}

/// Workload density for server node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerTraffic {
    Light,
    Moderate,
    Heavy,
}

impl Default for ServerTraffic {
    fn default() -> Self {
        Self::Light
    }
}

/// Upstream DNS recursive resolver provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerDnsUpstream {
    Cloudflare,
    Google,
    Combined,
}

impl Default for ServerDnsUpstream {
    fn default() -> Self {
        Self::Cloudflare
    }
}

/// Hardware specification and operational requirements of the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHardwareProfile {
    pub cpu_cores: usize,
    pub ram_mb: usize,
    pub network_mbps: usize,
    pub concurrent_users: usize,
    pub traffic: ServerTraffic,
    pub encryption_preference: EncryptionPreference,
    pub upstream_dns: ServerDnsUpstream,
    pub clients_lossy: bool,
}

impl Default for ServerHardwareProfile {
    fn default() -> Self {
        Self {
            cpu_cores: 2,
            ram_mb: 2048,
            network_mbps: 100,
            concurrent_users: 1,
            traffic: ServerTraffic::Light,
            encryption_preference: EncryptionPreference::Light,
            upstream_dns: ServerDnsUpstream::Cloudflare,
            clients_lossy: false,
        }
    }
}

/// Recommended server configuration parameters computed by the advisor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerRecommendation {
    pub data_encryption_method: u8,
    pub dns_upstream_servers: Vec<String>,
    pub udp_readers: usize,
    pub dns_request_workers: usize,
    pub deferred_session_workers: usize,
    pub max_concurrent_requests: usize,
    pub deferred_session_queue_limit: usize,
    pub socket_buffer_size_bytes: usize,
    pub session_timeout_seconds: u32,
    pub dns_cache_max_records: usize,
    pub packet_block_control_duplication: u8,
    pub max_packets_per_batch: usize,
    pub arq_window_size: usize,
    pub arq_data_nack_max_gap: usize,
    pub arq_max_data_retries: usize,
    pub socks_connect_timeout_seconds: u32,
    pub socks5_fragment_store_capacity: usize,
    pub dns_fragment_store_capacity: usize,
    pub session_cleanup_interval_seconds: u32,
    pub closed_session_retention_seconds: u32,
}

/// Hardware Advisor implementation engine.
pub struct HardwareAdvisor;

impl HardwareAdvisor {
    /// Computes deterministic client recommendations based on the provided hardware & network profile.
    pub fn advise_client(profile: &ClientHardwareProfile) -> ClientRecommendation {
        let q = profile.quality.reliability_factor();
        let is_lossy = profile.quality.is_lossy();
        let is_mobile = profile.connection == NetworkConnection::Mobile4g5g;
        let is_stream = profile.use_case == UseCase::Stream;
        let is_download = profile.use_case == UseCase::Download;
        let is_mixed = profile.use_case == UseCase::Mixed;
        let is_chat = profile.use_case == UseCase::Chat;

        // 1. Encryption
        let enc_method = match profile.encryption_preference {
            EncryptionPreference::Light => 1,
            EncryptionPreference::Balanced => 2,
            EncryptionPreference::Strong => 5,
        };

        // 2. Packet duplication
        let mut dup = 1u8;
        if is_lossy {
            dup = 4;
        } else if q <= 0.8 {
            dup = 2;
        }
        if is_mobile {
            dup = dup.max(3);
        }
        let setup_dup = (dup + 1).min(8);

        // 3. Resolver strategy
        let strat = if is_lossy {
            3 // Lowest loss
        } else {
            match profile.resolver_census {
                ResolverCensus::Many => 4,   // Lowest latency
                ResolverCensus::Medium => 3, // Lowest loss
                ResolverCensus::Few => 0,    // Round Robin
            }
        };

        // 4. Failover thresholds
        let (failover_threshold, failover_cooldown) = if is_lossy {
            (2, 4)
        } else {
            (3, 8)
        };

        // 5. MTU profile
        let (min_up, min_dn, max_up, max_dn) = match profile.mtu_preference {
            MtuPreference::Stable => (25, 50, 60, 200),
            MtuPreference::Balanced => (40, 100, 150, 500),
            MtuPreference::Speed => (60, 120, 220, 700),
        };

        // 6. MTU test parallelism
        let mut para = match profile.resolver_census {
            ResolverCensus::Many => 64,
            ResolverCensus::Medium => 32,
            ResolverCensus::Few => 16,
        };
        if profile.cpu_cores <= 2 {
            para = para.min(16);
        }
        if profile.cpu_cores <= 1 {
            para = para.min(8);
        }
        let (mtu_retries, mtu_timeout) = if is_lossy { (3, 3) } else { (2, 2) };

        // 7. Workers
        let max_workers = profile.cpu_cores.saturating_sub(1).max(1);
        let mut rw = match profile.resolver_census {
            ResolverCensus::Many => max_workers.min(4),
            ResolverCensus::Medium => max_workers.min(3),
            ResolverCensus::Few => max_workers.min(2),
        };
        rw = rw.max(2);
        if is_stream || is_download {
            rw = rw.max(3).min(max_workers + 1);
        }
        let proc_workers = (rw.saturating_sub(1)).max(2);

        // 8. Buffers and Channels
        let (mut tx_sz, mut rx_sz) = if profile.ram_mb <= 512 {
            (4096, 4096)
        } else if profile.ram_mb <= 2048 {
            (8192, 8192)
        } else {
            (8192, 12288)
        };
        if (is_stream || is_download || is_mixed) && profile.ram_mb >= 2048 {
            tx_sz = 16384;
            rx_sz = 16384;
        }
        if is_chat && profile.ram_mb <= 2048 {
            tx_sz = 4096;
            rx_sz = 4096;
        }

        // 9. UDP Connection Pool Size
        let mut pool_sz = match profile.resolver_census {
            ResolverCensus::Many => 64,
            ResolverCensus::Medium => 128,
            ResolverCensus::Few => 256,
        };
        if profile.ram_mb <= 512 {
            pool_sz = pool_sz.min(32);
        } else if profile.ram_mb <= 2048 {
            pool_sz = pool_sz.min(64);
        }

        // 10. Compression (0: none, 1: ZSTD, 2: LZ4)
        let (up_comp, dn_comp) = if is_stream || is_download || is_mixed {
            (2, 2) // LZ4
        } else if is_lossy || is_mobile {
            (1, 1) // ZSTD
        } else {
            (0, 0) // None
        };

        // 11. ARQ parameters
        let (arq_win, arq_gap, arq_retries, arq_rto) = if is_lossy {
            (1000, 64, 1500, 6.0)
        } else if is_stream || is_download {
            (800, 48, 1200, 4.0)
        } else {
            (600, 32, 1000, 3.0)
        };

        // 12. Ping intervals
        let (ping_aggr, ping_lazy, ping_cool) = if is_stream {
            (0.15, 0.5, 1.5)
        } else if is_chat {
            (0.30, 1.0, 3.0)
        } else if is_lossy {
            (0.20, 0.75, 2.0)
        } else {
            (0.25, 0.80, 2.0)
        };

        // 13. Dispatcher idle poll interval
        let disp_interval = if profile.cpu_cores <= 1 {
            0.050
        } else if profile.cpu_cores <= 2 {
            0.030
        } else if is_stream || is_download {
            0.010
        } else {
            0.020
        };

        ClientRecommendation {
            data_encryption_method: enc_method,
            packet_duplication_count: dup,
            setup_packet_duplication_count: setup_dup,
            resolver_balancing_strategy: strat,
            stream_resolver_failover_resend_threshold: failover_threshold,
            stream_resolver_failover_cooldown_sec: failover_cooldown,
            min_upload_mtu: min_up,
            min_download_mtu: min_dn,
            max_upload_mtu: max_up,
            max_download_mtu: max_dn,
            mtu_test_parallelism: para,
            mtu_test_retries: mtu_retries,
            mtu_test_timeout_sec: mtu_timeout,
            tunnel_reader_workers: rw,
            tunnel_writer_workers: rw,
            tunnel_process_workers: proc_workers,
            tx_channel_size: tx_sz,
            rx_channel_size: rx_sz,
            resolver_udp_connection_pool_size: pool_sz,
            upload_compression_type: up_comp,
            download_compression_type: dn_comp,
            arq_window_size: arq_win,
            arq_data_nack_max_gap: arq_gap,
            arq_max_data_retries: arq_retries,
            arq_max_rto_sec: arq_rto,
            ping_aggressive_interval_sec: ping_aggr,
            ping_lazy_interval_sec: ping_lazy,
            ping_cooldown_interval_sec: ping_cool,
            dispatcher_idle_poll_interval_sec: disp_interval,
        }
    }

    /// Computes deterministic server recommendations based on hardware & expected workload profile.
    pub fn advise_server(profile: &ServerHardwareProfile) -> ServerRecommendation {
        let cpu_factor = if profile.cpu_cores >= 8 {
            4
        } else if profile.cpu_cores >= 4 {
            2
        } else {
            1
        };

        let ram_factor = if profile.ram_mb >= 4096 {
            4
        } else if profile.ram_mb >= 2048 {
            2
        } else {
            1
        };

        let is_heavy = profile.traffic == ServerTraffic::Heavy;
        let is_multi_user = profile.concurrent_users >= 5;
        let is_lossy = profile.clients_lossy;

        // 1. Encryption
        let enc_method = match profile.encryption_preference {
            EncryptionPreference::Light => 1,
            EncryptionPreference::Balanced => 2,
            EncryptionPreference::Strong => 5,
        };

        // 2. Upstream DNS servers
        let upstreams = match profile.upstream_dns {
            ServerDnsUpstream::Cloudflare => vec!["1.1.1.1:53".to_string(), "1.0.0.1:53".to_string()],
            ServerDnsUpstream::Google => vec!["8.8.8.8:53".to_string(), "8.8.4.4:53".to_string()],
            ServerDnsUpstream::Combined => vec![
                "1.1.1.1:53".to_string(),
                "1.0.0.1:53".to_string(),
                "8.8.8.8:53".to_string(),
                "8.8.4.4:53".to_string(),
            ],
        };

        // 3. Readers and workers
        let mut udp_readers = 2.max(cpu_factor);
        let mut dns_workers = 4.max(cpu_factor * 2);
        if is_multi_user {
            udp_readers = udp_readers.max(3);
            dns_workers = dns_workers.max(6);
        }
        if is_heavy {
            udp_readers = udp_readers.max(4);
            dns_workers = dns_workers.max(8);
        }

        // 4. Deferred workers
        let mut def_workers = 2.max(cpu_factor);
        if is_multi_user {
            def_workers = def_workers.max(3);
        }

        // 5. Max concurrent requests
        let mut max_req = 4096;
        if ram_factor >= 2 {
            max_req = 8192;
        }
        if ram_factor >= 4 {
            max_req = 16384;
        }
        if is_multi_user && is_heavy {
            max_req = (max_req * 2).min(32768);
        }

        // 6. Deferred queue limit
        let mut def_queue = 2048;
        if ram_factor >= 2 {
            def_queue = 4096;
        }
        if is_multi_user {
            def_queue = (def_queue * 2).min(14336);
        }

        // 7. Socket buffer size
        let mut sock_buf = 4 * 1024 * 1024; // 4 MB
        if profile.ram_mb >= 2048 {
            sock_buf = 8 * 1024 * 1024; // 8 MB
        }
        if profile.ram_mb >= 4096 && is_heavy {
            sock_buf = 16 * 1024 * 1024; // 16 MB
        }

        // 8. Session timeout
        let ses_timeout = if profile.concurrent_users >= 15 {
            180
        } else {
            300
        };

        // 9. DNS cache size
        let dns_cache = if ram_factor >= 4 {
            100_000
        } else if ram_factor >= 2 {
            50_000
        } else {
            10_000
        };

        // 10. Lossy control duplication
        let (ctrl_dup, batch_packets) = if is_lossy {
            (3, 12)
        } else {
            (1, 10)
        };

        // 11. ARQ parameters
        let (arq_win, arq_gap, arq_retries) = if is_lossy || is_heavy {
            (1000, 64, 1500)
        } else {
            (600, 32, 1000)
        };

        // 12. SOCKS connect timeout
        let connect_timeout = if profile.concurrent_users >= 15 {
            60
        } else {
            120
        };

        // 13. Fragment store capacities
        let (socks5_frag, dns_frag) = if is_multi_user {
            (2048, 1024)
        } else {
            (1024, 512)
        };

        // 14. Session cleanup and retention
        let (cleanup_interval, retention) = if profile.concurrent_users >= 15 {
            (15, 300)
        } else {
            (30, 600)
        };

        ServerRecommendation {
            data_encryption_method: enc_method,
            dns_upstream_servers: upstreams,
            udp_readers,
            dns_request_workers: dns_workers,
            deferred_session_workers: def_workers,
            max_concurrent_requests: max_req,
            deferred_session_queue_limit: def_queue,
            socket_buffer_size_bytes: sock_buf,
            session_timeout_seconds: ses_timeout,
            dns_cache_max_records: dns_cache,
            packet_block_control_duplication: ctrl_dup,
            max_packets_per_batch: batch_packets,
            arq_window_size: arq_win,
            arq_data_nack_max_gap: arq_gap,
            arq_max_data_retries: arq_retries,
            socks_connect_timeout_seconds: connect_timeout,
            socks5_fragment_store_capacity: socks5_frag,
            dns_fragment_store_capacity: dns_frag,
            session_cleanup_interval_seconds: cleanup_interval,
            closed_session_retention_seconds: retention,
        }
    }
}
