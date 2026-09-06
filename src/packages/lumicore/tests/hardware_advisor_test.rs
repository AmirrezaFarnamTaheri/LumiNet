use lumicore::dns::hardware_advisor::*;

#[test]
fn test_client_advice_mobile_poor_lossy() {
    let profile = ClientHardwareProfile {
        connection: NetworkConnection::Mobile4g5g,
        quality: NetworkQuality::Poor,
        cpu_cores: 2,
        ram_mb: 2048,
        resolver_census: ResolverCensus::Few,
        mtu_preference: MtuPreference::Stable,
        use_case: UseCase::Chat,
        encryption_preference: EncryptionPreference::Light,
    };

    let rec = HardwareAdvisor::advise_client(&profile);

    // Light encryption -> XOR (1)
    assert_eq!(rec.data_encryption_method, 1);
    // Poor quality -> lossy -> duplication = 4
    assert_eq!(rec.packet_duplication_count, 4);
    assert_eq!(rec.setup_packet_duplication_count, 5);
    // Lossy -> strategy 3 (Lowest loss)
    assert_eq!(rec.resolver_balancing_strategy, 3);
    // Lossy failover
    assert_eq!(rec.stream_resolver_failover_resend_threshold, 2);
    assert_eq!(rec.stream_resolver_failover_cooldown_sec, 4);
    // Stable MTU
    assert_eq!(rec.min_upload_mtu, 25);
    assert_eq!(rec.max_upload_mtu, 60);
    // Mobile/lossy chat compression -> ZSTD (1)
    assert_eq!(rec.upload_compression_type, 1);
    // Lossy ARQ
    assert_eq!(rec.arq_window_size, 1000);
    assert_eq!(rec.arq_data_nack_max_gap, 64);
    assert_eq!(rec.arq_max_data_retries, 1500);
    // 2 CPU cores poll interval -> 30ms
    assert!((rec.dispatcher_idle_poll_interval_sec - 0.030).abs() < f32::EPSILON);
}

#[test]
fn test_client_advice_fiber_stream_strong() {
    let profile = ClientHardwareProfile {
        connection: NetworkConnection::Fiber,
        quality: NetworkQuality::Excellent,
        cpu_cores: 8,
        ram_mb: 8192,
        resolver_census: ResolverCensus::Many,
        mtu_preference: MtuPreference::Speed,
        use_case: UseCase::Stream,
        encryption_preference: EncryptionPreference::Strong,
    };

    let rec = HardwareAdvisor::advise_client(&profile);

    // Strong encryption -> AES-256-GCM (5)
    assert_eq!(rec.data_encryption_method, 5);
    // Fiber excellent -> duplication = 1
    assert_eq!(rec.packet_duplication_count, 1);
    assert_eq!(rec.setup_packet_duplication_count, 2);
    // Many resolvers non-lossy -> strategy 4 (Lowest latency)
    assert_eq!(rec.resolver_balancing_strategy, 4);
    // Speed MTU
    assert_eq!(rec.min_upload_mtu, 60);
    assert_eq!(rec.max_download_mtu, 700);
    // Parallelism with 8 cores and Many resolvers -> 64
    assert_eq!(rec.mtu_test_parallelism, 64);
    // Stream + High RAM -> LZ4 compression (2), 16384 buffers
    assert_eq!(rec.upload_compression_type, 2);
    assert_eq!(rec.tx_channel_size, 16384);
    assert_eq!(rec.rx_channel_size, 16384);
    // Stream poll interval -> 10ms
    assert!((rec.dispatcher_idle_poll_interval_sec - 0.010).abs() < f32::EPSILON);
    // Aggressive ping for stream
    assert!((rec.ping_aggressive_interval_sec - 0.15).abs() < f32::EPSILON);
}

#[test]
fn test_server_advice_minimal_vs_enterprise() {
    // Minimal single user server
    let min_prof = ServerHardwareProfile {
        cpu_cores: 1,
        ram_mb: 512,
        network_mbps: 100,
        concurrent_users: 1,
        traffic: ServerTraffic::Light,
        encryption_preference: EncryptionPreference::Light,
        upstream_dns: ServerDnsUpstream::Cloudflare,
        clients_lossy: false,
    };
    let min_rec = HardwareAdvisor::advise_server(&min_prof);
    assert_eq!(min_rec.data_encryption_method, 1);
    assert_eq!(min_rec.udp_readers, 2);
    assert_eq!(min_rec.dns_request_workers, 4);
    assert_eq!(min_rec.max_concurrent_requests, 4096);
    assert_eq!(min_rec.socket_buffer_size_bytes, 4 * 1024 * 1024);
    assert_eq!(min_rec.dns_cache_max_records, 10_000);
    assert_eq!(min_rec.packet_block_control_duplication, 1);
    assert_eq!(min_rec.session_timeout_seconds, 300);

    // Enterprise 30+ users heavy server with lossy clients
    let ent_prof = ServerHardwareProfile {
        cpu_cores: 8,
        ram_mb: 4096,
        network_mbps: 1000,
        concurrent_users: 30,
        traffic: ServerTraffic::Heavy,
        encryption_preference: EncryptionPreference::Balanced,
        upstream_dns: ServerDnsUpstream::Combined,
        clients_lossy: true,
    };
    let ent_rec = HardwareAdvisor::advise_server(&ent_prof);
    assert_eq!(ent_rec.data_encryption_method, 2);
    assert_eq!(ent_rec.dns_upstream_servers.len(), 4);
    assert_eq!(ent_rec.udp_readers, 4);
    assert_eq!(ent_rec.dns_request_workers, 8);
    assert_eq!(ent_rec.max_concurrent_requests, 32768);
    assert_eq!(ent_rec.socket_buffer_size_bytes, 16 * 1024 * 1024);
    assert_eq!(ent_rec.dns_cache_max_records, 100_000);
    assert_eq!(ent_rec.packet_block_control_duplication, 3);
    assert_eq!(ent_rec.max_packets_per_batch, 12);
    assert_eq!(ent_rec.session_timeout_seconds, 180);
    assert_eq!(ent_rec.socks_connect_timeout_seconds, 60);
    assert_eq!(ent_rec.session_cleanup_interval_seconds, 15);
    assert_eq!(ent_rec.socks5_fragment_store_capacity, 2048);
}
