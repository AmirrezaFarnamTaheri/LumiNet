pub mod packet_crafting;
pub use packet_crafting::PacketCrafting;

pub mod dns_scanner;
pub use dns_scanner::{DnsScanConfig, DnsScanner};

pub mod network_shuffle_scanner;
pub use network_shuffle_scanner::BlackrockScanner;

pub mod edge_prober;
pub use edge_prober::EdgeProber;

// JA3/JA4 TLS fingerprinting
pub mod ja;
pub use ja::{
    compute_ja3, compute_ja4, compute_ja3_hash, compute_ja4_fingerprint,
    parse_client_hello, JA3Result, JA4Result, ParsedClientHello,
};

// OONI measurexlite observation primitives
pub mod observation;
pub use observation::{
    Observation, ObservationType, ObservationSet,
    TcpObservation, TlsObservation, DnsObservation, HttpObservation,
    TcpObservationBuilder,
};

// REALITY target scanning
pub mod reality_targets;
pub use reality_targets::{
    RealityTarget, RealityTargetSet,
    ScoreRealityTarget, ApplyScores, RecommendedTargets,
    FingerprintRegistry, FingerprintInfo,
};

// Subnet host walker & target normalizer
pub mod host_walker;
pub use host_walker::{HostWalker, PrefixEntry, TargetNormalizer};

// 6-stage DNS capability prober and transparent proxy detector
pub mod dns_prober;
pub use dns_prober::{
    format_tunnel_realism_qname, is_transparent_proxy_detected, verify_nxdomain_ratio,
    TunnelTestResult, DEFAULT_TUNNEL_SCORE_THRESHOLD, TRANSPARENT_PROXY_TEST_IPS,
};

// Flow latency RTT tracker
pub mod flow_latency;
pub use flow_latency::{compute_flow_hash, FlowLatencyStats, FlowLatencyTracker, TcpProbePacket};


// Cloudflare WARP prober & endpoint scanner
pub mod warp_handshake;
pub use warp_handshake::{
    build_initiation_packet, build_probe_packet, generate_noise_bursts, probe_warp_endpoint,
    select_random_warp_port, validate_handshake_response, WarpHandshakeError, WarpPingResult,
    WarpResponseInfo, DEFAULT_WARP_PEER_PUBLIC_KEY, INITIATION_PACKET_LEN, RESPONSE_PACKET_LEN,
    WARP_IPV4_PREFIXES, WARP_IPV6_PREFIXES, WARP_PORTS, WG_MSG_INITIATION, WG_MSG_RESPONSE,
};

// Cancellable MASQUE gateway prober & RTT ranker
pub mod gateway_scanner;
pub use gateway_scanner::{
    generate_candidates, scan_gateways_with_canceller, GatewayProbeResult, IpScanFilter, ScanMode,
    ScanStrategy, ScannerError, MASQUE_CDN_CIDRS_V4, MASQUE_CIDRS_V4, MASQUE_CIDRS_V6,
    MASQUE_PORTS, MASQUE_SEEDS,
};

// High-throughput UDP resolver scanner and response validator
pub mod udp_resolver_scanner;
pub use udp_resolver_scanner::{
    build_dns_a_query, is_valid_dns_response, parse_resolver_entry, skip_dns_name,
};

// Backend WebSocket reachability prober and duplex traffic meter
pub mod backend_prober;
pub use backend_prober::{
    analyze_probe_response, build_websocket_handshake_request, BackendProbeConfig,
    BackendProbeResult, TrafficMeter,
};

// Multi-protocol tunnel probe scoring, middlebox spoofing detector & metrics
pub mod tunnel_probe_evaluator;
pub use tunnel_probe_evaluator::{
    AttemptMetric, DnsProbeResult, HttpProbe, HttpProbeResult, ProbeMetrics, QuicProbeResult,
    ScoreResult, TcpProbeResult, TlsProbeResult, TunnelProbeEvaluator, TunnelScanReport,
    UdpProbeResult, WsProbeResult,
};

// Iran censorship prober & multi-node edge quorum evaluator
pub mod check_host_prober;
pub use check_host_prober::{
    CensorshipVerdict, CheckHostAssessment, CheckHostProber, NodeProbeDetail, ProbeMethod,
    DEFAULT_IRAN_NODES,
};

// SOCKS active prober & connection stage ladder
pub mod socks_stage_prober;
pub use socks_stage_prober::{
    AttemptLadder, AttemptPhase, AttemptStage, CloudflareTraceResult, SocksPacketBuilder,
    SocksProbeConfig,
};


pub mod cdn_front_pool;
pub use cdn_front_pool::{CdnCandidate, CdnFrontPool, CdnFrontPoolConfig};

pub mod warp_account_client;
pub use warp_account_client::WarpAccountProfile;

pub mod latency_race_selector;
pub mod subnet_dns_scanner;

pub mod edge_worker_selector;
pub mod subnet_range_scout;
pub mod subnet_neighbor_scanner;
