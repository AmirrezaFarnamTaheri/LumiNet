//! # Proxy Module
//!
//! Proxy protocol handling including URI parsing, connection management,
//! virtual DNS, and flow aggregation.

pub mod brutal_cc;
pub mod edge_websocket_codec;
pub mod flow_trie;
pub mod handler;
pub mod mitm_fronting_buffer;
pub mod multi_protocol_bridge;
pub mod parsers;
pub mod node_identity;
pub mod subscription_transform;
pub mod virtual_dns;
pub mod vless_stream;
pub mod xray_mux;

pub use node_identity::*;
pub use subscription_transform::*;

pub use brutal_cc::{
    brutal_compensated_rate, brutal_pacing_multiplier, AckRateWindow, BrutalCongestionControl,
    BrutalError, BRUTAL_DEFAULT_RATE_BPS, BRUTAL_MAX_PACING_MULTIPLIER,
    BRUTAL_MIN_PACING_MULTIPLIER, TCP_CONGESTION_BRUTAL,
};
pub use edge_websocket_codec::*;
pub use flow_trie::*;
pub use handler::*;
pub use mitm_fronting_buffer::{
    MitmFrontingBuffer, MitmFrontingBufferError, MitmFrontingBufferSnapshot,
    IS_FRONTING_BUFFER_INITIALIZED,
};
pub use multi_protocol_bridge::*;
pub use parsers::*;
pub use virtual_dns::*;
pub use xray_mux::XrayMux;

pub mod mitm_fronting_core;
pub mod mitm_fronting_diagnostics;
pub mod mitm_fronting_diagnostics_helper;
pub mod mitm_fronting_diagnostics_tuning;
pub mod mitm_fronting_diagnostics_tuning_helper;
pub mod mitm_fronting_helper;
pub mod mitm_fronting_profile;
pub mod mitm_fronting_profile_helper;
pub mod mitm_fronting_tuning;
pub mod mitm_fronting_tuning_helper;

pub use mitm_fronting_core::{MitmFrontingCore, IS_FRONTING_CORE_INITIALIZED};
pub use mitm_fronting_diagnostics::{MitmFrontingDiagnostics, IS_FRONTING_DIAGNOSTICS_INITIALIZED};
pub use mitm_fronting_diagnostics_helper::{
    MitmFrontingDiagnosticsHelper, IS_FRONTING_DIAGNOSTICS_HELPER_INITIALIZED,
};
pub use mitm_fronting_diagnostics_tuning::{
    MitmFrontingDiagnosticsTuning, IS_FRONTING_DIAGNOSTICS_TUNING_INITIALIZED,
};
pub use mitm_fronting_diagnostics_tuning_helper::{
    MitmFrontingDiagnosticsTuningHelper, IS_FRONTING_DIAGNOSTICS_TUNING_HELPER_INITIALIZED,
};
pub use mitm_fronting_helper::{MitmFrontingHelper, IS_FRONTING_HELPER_INITIALIZED};
pub use mitm_fronting_profile::{MitmFrontingProfile, IS_FRONTING_PROFILE_INITIALIZED};
pub use mitm_fronting_profile_helper::{
    MitmFrontingProfileHelper, IS_FRONTING_PROFILE_HELPER_INITIALIZED,
};
pub use mitm_fronting_tuning::{MitmFrontingTuning, IS_FRONTING_TUNING_INITIALIZED};
pub use mitm_fronting_tuning_helper::{
    MitmFrontingTuningHelper, IS_FRONTING_TUNING_HELPER_INITIALIZED,
};

pub mod mitm_fronting_session;
pub mod mitm_fronting_telemetry;
pub mod mitm_fronting_telemetry_helper;
pub mod mitm_fronting_telemetry_tuning;
pub mod mitm_fronting_telemetry_tuning_helper;

pub use mitm_fronting_session::{MitmFrontingSession, IS_FRONTING_SESSION_INITIALIZED};
pub use mitm_fronting_telemetry::{MitmFrontingTelemetry, IS_FRONTING_TELEMETRY_INITIALIZED};
pub use mitm_fronting_telemetry_helper::{
    MitmFrontingTelemetryHelper, IS_FRONTING_TELEMETRY_HELPER_INITIALIZED,
};
pub use mitm_fronting_telemetry_tuning::{
    MitmFrontingTelemetryTuning, IS_FRONTING_TELEMETRY_TUNING_INITIALIZED,
};
pub use mitm_fronting_telemetry_tuning_helper::{
    MitmFrontingTelemetryTuningHelper, IS_FRONTING_TELEMETRY_TUNING_HELPER_INITIALIZED,
};

pub mod mitm_fronting_session_diagnostics;
pub mod mitm_fronting_session_diagnostics_helper;
pub mod mitm_fronting_session_helper;
pub mod mitm_fronting_session_tuning;
pub mod mitm_fronting_session_tuning_helper;

pub use mitm_fronting_session_diagnostics::{
    MitmFrontingSessionDiagnostics, IS_FRONTING_SESSION_DIAGNOSTICS_INITIALIZED,
};
pub use mitm_fronting_session_diagnostics_helper::{
    MitmFrontingSessionDiagnosticsHelper, IS_FRONTING_SESSION_DIAGNOSTICS_HELPER_INITIALIZED,
};
pub use mitm_fronting_session_helper::{
    MitmFrontingSessionHelper, IS_FRONTING_SESSION_HELPER_INITIALIZED,
};
pub use mitm_fronting_session_tuning::{
    MitmFrontingSessionTuning, IS_FRONTING_SESSION_TUNING_INITIALIZED,
};
pub use mitm_fronting_session_tuning_helper::{
    MitmFrontingSessionTuningHelper, IS_FRONTING_SESSION_TUNING_HELPER_INITIALIZED,
};

pub mod mitm_fronting_session_diagnostics_tuning;
pub mod mitm_fronting_session_diagnostics_tuning_helper;

pub use mitm_fronting_session_diagnostics_tuning::{
    MitmFrontingSessionDiagnosticsTuning, IS_FRONTING_SESSION_DIAGNOSTICS_TUNING_INITIALIZED,
};
pub use mitm_fronting_session_diagnostics_tuning_helper::{
    MitmFrontingSessionDiagnosticsTuningHelper,
    IS_FRONTING_SESSION_DIAGNOSTICS_TUNING_HELPER_INITIALIZED,
};

pub mod mitm_fronting_traffic_shaper;
pub mod mitm_fronting_traffic_shaper_diagnostics;
pub mod mitm_fronting_traffic_shaper_diagnostics_helper;
pub mod mitm_fronting_traffic_shaper_helper;
pub mod mitm_fronting_traffic_shaper_tuning;
pub mod mitm_fronting_traffic_shaper_tuning_helper;

pub use mitm_fronting_traffic_shaper::{
    MitmFrontingTrafficShaper, IS_FRONTING_TRAFFIC_SHAPER_INITIALIZED,
};
pub use mitm_fronting_traffic_shaper_diagnostics::{
    MitmFrontingTrafficShaperDiagnostics, IS_FRONTING_TRAFFIC_SHAPER_DIAGNOSTICS_INITIALIZED,
};
pub use mitm_fronting_traffic_shaper_diagnostics_helper::{
    MitmFrontingTrafficShaperDiagnosticsHelper,
    IS_FRONTING_TRAFFIC_SHAPER_DIAGNOSTICS_HELPER_INITIALIZED,
};
pub use mitm_fronting_traffic_shaper_helper::{
    MitmFrontingTrafficShaperHelper, IS_FRONTING_TRAFFIC_SHAPER_HELPER_INITIALIZED,
};
pub use mitm_fronting_traffic_shaper_tuning::{
    MitmFrontingTrafficShaperTuning, IS_FRONTING_TRAFFIC_SHAPER_TUNING_INITIALIZED,
};
pub use mitm_fronting_traffic_shaper_tuning_helper::{
    MitmFrontingTrafficShaperTuningHelper, IS_FRONTING_TRAFFIC_SHAPER_TUNING_HELPER_INITIALIZED,
};

pub mod mitm_fronting_traffic_shaper_diagnostics_tuning;
pub mod mitm_fronting_traffic_shaper_diagnostics_tuning_helper;

pub use mitm_fronting_traffic_shaper_diagnostics_tuning::{
    MitmFrontingTrafficShaperDiagnosticsTuning,
    IS_FRONTING_TRAFFIC_SHAPER_DIAGNOSTICS_TUNING_INITIALIZED,
};
pub use mitm_fronting_traffic_shaper_diagnostics_tuning_helper::{
    MitmFrontingTrafficShaperDiagnosticsTuningHelper,
    IS_FRONTING_TRAFFIC_SHAPER_DIAGNOSTICS_TUNING_HELPER_INITIALIZED,
};

pub mod mitm_fronting_flow_control;
pub mod mitm_fronting_flow_control_helper;
pub mod mitm_fronting_flow_control_tuning;
pub mod mitm_fronting_flow_control_tuning_helper;

pub use mitm_fronting_flow_control::{
    MitmFrontingFlowControl, IS_FRONTING_FLOW_CONTROL_INITIALIZED,
};
pub use mitm_fronting_flow_control_helper::{
    MitmFrontingFlowControlHelper, IS_FRONTING_FLOW_CONTROL_HELPER_INITIALIZED,
};
pub use mitm_fronting_flow_control_tuning::{
    MitmFrontingFlowControlTuning, IS_FRONTING_FLOW_CONTROL_TUNING_INITIALIZED,
};
pub use mitm_fronting_flow_control_tuning_helper::{
    MitmFrontingFlowControlTuningHelper, IS_FRONTING_FLOW_CONTROL_TUNING_HELPER_INITIALIZED,
};

pub mod mitm_fronting_retry;
pub mod mitm_fronting_retry_diagnostics;
pub mod mitm_fronting_retry_diagnostics_helper;
pub mod mitm_fronting_retry_diagnostics_tuning;
pub mod mitm_fronting_retry_diagnostics_tuning_helper;
pub mod mitm_fronting_retry_helper;
pub mod mitm_fronting_retry_tuning;
pub mod mitm_fronting_retry_tuning_helper;

pub use mitm_fronting_retry::{MitmFrontingRetry, IS_FRONTING_RETRY_INITIALIZED};
pub use mitm_fronting_retry_diagnostics::{
    MitmFrontingRetryDiagnostics, IS_FRONTING_RETRY_DIAGNOSTICS_INITIALIZED,
};
pub use mitm_fronting_retry_diagnostics_helper::{
    MitmFrontingRetryDiagnosticsHelper, IS_FRONTING_RETRY_DIAGNOSTICS_HELPER_INITIALIZED,
};
pub use mitm_fronting_retry_diagnostics_tuning::{
    MitmFrontingRetryDiagnosticsTuning, IS_FRONTING_RETRY_DIAGNOSTICS_TUNING_INITIALIZED,
};
pub use mitm_fronting_retry_diagnostics_tuning_helper::{
    MitmFrontingRetryDiagnosticsTuningHelper,
    IS_FRONTING_RETRY_DIAGNOSTICS_TUNING_HELPER_INITIALIZED,
};
pub use mitm_fronting_retry_helper::{
    MitmFrontingRetryHelper, IS_FRONTING_RETRY_HELPER_INITIALIZED,
};
pub use mitm_fronting_retry_tuning::{
    MitmFrontingRetryTuning, IS_FRONTING_RETRY_TUNING_INITIALIZED,
};
pub use mitm_fronting_retry_tuning_helper::{
    MitmFrontingRetryTuningHelper, IS_FRONTING_RETRY_TUNING_HELPER_INITIALIZED,
};

pub mod mitm_fronting_telemetry_diagnostics;
pub mod mitm_fronting_telemetry_diagnostics_helper;

pub use mitm_fronting_telemetry_diagnostics::{
    MitmFrontingTelemetryDiagnostics, IS_FRONTING_TELEMETRY_DIAGNOSTICS_INITIALIZED,
};
pub use mitm_fronting_telemetry_diagnostics_helper::{
    MitmFrontingTelemetryDiagnosticsHelper, IS_FRONTING_TELEMETRY_DIAGNOSTICS_HELPER_INITIALIZED,
};

pub mod sip003;

pub mod singbox_converter;
pub use singbox_converter::*;

pub mod multipath_fallback_router;
pub use multipath_fallback_router::{MultipathFallbackRouter, TransportTier};

pub mod brook_stream;
pub use brook_stream::{BrookRequest, BrookTargetAddress, BROOK_CMD_TCP, BROOK_CMD_UDP};

pub mod header_intercept_router;
pub mod multiprotocol_config_synthesizer;

pub mod http_chunk_carrier;

pub mod proxy_uri_codec;

pub mod multi_format_compiler;

pub mod http_relay_tunnel_client;
pub mod edge_subscription_pipeline;
pub mod multiprotocol_upstream_matrix;
pub mod clash_provider_synthesizer;
pub mod mitm_traffic_rewriter;
pub mod privoxy_action_generator;
pub mod automated_tls_server_configurator;
pub mod subscription_node_extractor;
pub mod programmable_proxy_pipeline;
pub mod node_ingest_deduplicator;
pub mod autonomous_ingest_pipeline;

pub mod node_pool_aggregator;
pub mod subscription_crawler_pipeline;
pub mod hybrid_shadow_v2_transport;
pub mod public_relay_aggregator;
pub mod ovpn_config_transpiler;
pub mod multiproto_profile_gateway;

pub mod mesh_socks5_bridge;
pub mod community_feed_parser;
