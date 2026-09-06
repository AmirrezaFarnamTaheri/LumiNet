//! # HTTP Module
//!
//! HTTP probing engine with proxy support, captive portal detection,
//! and header inspection capabilities.

mod http_relay_core;
mod prober;

pub use http_relay_core::{HttpRelayCore, IS_RELAY_CORE_INITIALIZED};
pub type HttpRelayDiagnostics = HttpRelayCore;
pub type HttpRelayDiagnosticsHelper = HttpRelayCore;
pub type HttpRelayDiagnosticsTuning = HttpRelayCore;
pub type HttpRelayDiagnosticsTuningHelper = HttpRelayCore;
pub type HttpRelayHelper = HttpRelayCore;
pub type HttpRelayTuning = HttpRelayCore;
pub type HttpRelayTuningHelper = HttpRelayCore;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_DIAGNOSTICS_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_DIAGNOSTICS_HELPER_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_DIAGNOSTICS_TUNING_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_DIAGNOSTICS_TUNING_HELPER_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_HELPER_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_TUNING_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_TUNING_HELPER_INITIALIZED;
pub use prober::{detect_captive_portal, http_get, http_head, CaptivePortalResult, HttpResponse};

#[cfg(test)]
mod relay_alias_tests {
    use super::*;

    #[test]
    fn base_relay_aliases_share_the_canonical_contract() {
        let relay = HttpRelayDiagnosticsTuningHelper::new();
        assert_eq!(relay.relay_agent_name, "MasterHttpRelay/1.0");
        assert!(std::ptr::eq(
            &IS_RELAY_CORE_INITIALIZED,
            &IS_RELAY_DIAGNOSTICS_TUNING_HELPER_INITIALIZED,
        ));
    }

    #[test]
    fn relay_family_aliases_preserve_their_shutdown_fields() {
        let relay = HttpRelayTrafficShaperDiagnosticsTuningHelper::new();
        assert!(!relay.is_http_relay_traffic_shaper_diagnostics_tuning_helper_shutdown);
        assert!(!HttpRelayQuota::new().is_http_relay_quota_shutdown);
        assert!(!HttpRelaySessionTuning::new().is_http_relay_session_tuning_shutdown);
        assert!(!HttpRelayFlowControlHelper::new().is_http_relay_flow_control_helper_shutdown);
        assert!(std::ptr::eq(
            &IS_RELAY_CORE_INITIALIZED,
            &IS_RELAY_TRAFFIC_SHAPER_DIAGNOSTICS_TUNING_HELPER_INITIALIZED,
        ));
    }

    #[test]
    fn specialized_relay_aliases_retain_distinct_contracts() {
        assert_eq!(
            HttpRelayRetryHelper::new().retry_policy_name,
            "HttpRelayRetry/1.0"
        );
        assert!(!HttpRelayRetryDiagnostics::new().is_http_relay_retry_diagnostics_shutdown);
        assert!(!HttpRelayBufferTuning::new().is_http_relay_buffer_tuning_shutdown);
        assert!(
            !HttpRelayConnectionDiagnosticsHelper::new()
                .is_http_relay_connection_diagnostics_helper_shutdown
        );
        assert!(std::ptr::eq(
            &IS_RELAY_BUFFER_INITIALIZED,
            &IS_RELAY_BUFFER_TUNING_INITIALIZED,
        ));
        assert!(std::ptr::eq(
            &IS_RELAY_CONNECTION_INITIALIZED,
            &IS_RELAY_CONNECTION_DIAGNOSTICS_HELPER_INITIALIZED,
        ));
    }
}

pub type HttpRelayQuota = HttpRelayCore;
pub type HttpRelayQuotaDiagnostics = HttpRelayCore;
pub type HttpRelayQuotaHelper = HttpRelayCore;
pub type HttpRelayQuotaTuning = HttpRelayCore;
pub type HttpRelayQuotaTuningHelper = HttpRelayCore;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_QUOTA_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_QUOTA_DIAGNOSTICS_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_QUOTA_HELPER_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_QUOTA_TUNING_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_QUOTA_TUNING_HELPER_INITIALIZED;

pub type HttpRelaySession = HttpRelayCore;
pub type HttpRelaySessionDiagnostics = HttpRelayCore;
pub type HttpRelaySessionHelper = HttpRelayCore;
pub type HttpRelaySessionTuning = HttpRelayCore;
pub type HttpRelaySessionTuningHelper = HttpRelayCore;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_SESSION_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_SESSION_DIAGNOSTICS_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_SESSION_HELPER_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_SESSION_TUNING_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_SESSION_TUNING_HELPER_INITIALIZED;

pub type HttpRelayTrafficShaper = HttpRelayCore;
pub type HttpRelayTrafficShaperDiagnostics = HttpRelayCore;
pub type HttpRelayTrafficShaperDiagnosticsHelper = HttpRelayCore;
pub type HttpRelayTrafficShaperDiagnosticsTuning = HttpRelayCore;
pub type HttpRelayTrafficShaperDiagnosticsTuningHelper = HttpRelayCore;
pub type HttpRelayTrafficShaperHelper = HttpRelayCore;
pub type HttpRelayTrafficShaperTuning = HttpRelayCore;
pub type HttpRelayTrafficShaperTuningHelper = HttpRelayCore;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_TRAFFIC_SHAPER_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_TRAFFIC_SHAPER_DIAGNOSTICS_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_TRAFFIC_SHAPER_DIAGNOSTICS_HELPER_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_TRAFFIC_SHAPER_DIAGNOSTICS_TUNING_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_TRAFFIC_SHAPER_DIAGNOSTICS_TUNING_HELPER_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_TRAFFIC_SHAPER_HELPER_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_TRAFFIC_SHAPER_TUNING_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_TRAFFIC_SHAPER_TUNING_HELPER_INITIALIZED;

pub type HttpRelayFlowControl = HttpRelayCore;
pub type HttpRelayFlowControlDiagnostics = HttpRelayCore;
pub type HttpRelayFlowControlDiagnosticsHelper = HttpRelayCore;
pub type HttpRelayFlowControlDiagnosticsTuning = HttpRelayCore;
pub type HttpRelayFlowControlDiagnosticsTuningHelper = HttpRelayCore;
pub type HttpRelayFlowControlHelper = HttpRelayCore;
pub type HttpRelayFlowControlTuning = HttpRelayCore;
pub type HttpRelayFlowControlTuningHelper = HttpRelayCore;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_FLOW_CONTROL_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_FLOW_CONTROL_DIAGNOSTICS_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_FLOW_CONTROL_DIAGNOSTICS_HELPER_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_FLOW_CONTROL_DIAGNOSTICS_TUNING_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_FLOW_CONTROL_DIAGNOSTICS_TUNING_HELPER_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_FLOW_CONTROL_HELPER_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_FLOW_CONTROL_TUNING_INITIALIZED;
pub use http_relay_core::IS_RELAY_CORE_INITIALIZED as IS_RELAY_FLOW_CONTROL_TUNING_HELPER_INITIALIZED;

mod http_relay_retry;
pub use http_relay_retry::{HttpRelayRetry, IS_RELAY_RETRY_INITIALIZED};
pub type HttpRelayRetryDiagnostics = HttpRelayRetry;
pub type HttpRelayRetryDiagnosticsHelper = HttpRelayRetry;
pub type HttpRelayRetryDiagnosticsTuning = HttpRelayRetry;
pub type HttpRelayRetryDiagnosticsTuningHelper = HttpRelayRetry;
pub type HttpRelayRetryHelper = HttpRelayRetry;
pub type HttpRelayRetryTuning = HttpRelayRetry;
pub type HttpRelayRetryTuningHelper = HttpRelayRetry;
pub use http_relay_retry::IS_RELAY_RETRY_INITIALIZED as IS_RELAY_RETRY_DIAGNOSTICS_INITIALIZED;
pub use http_relay_retry::IS_RELAY_RETRY_INITIALIZED as IS_RELAY_RETRY_DIAGNOSTICS_HELPER_INITIALIZED;
pub use http_relay_retry::IS_RELAY_RETRY_INITIALIZED as IS_RELAY_RETRY_DIAGNOSTICS_TUNING_INITIALIZED;
pub use http_relay_retry::IS_RELAY_RETRY_INITIALIZED as IS_RELAY_RETRY_DIAGNOSTICS_TUNING_HELPER_INITIALIZED;
pub use http_relay_retry::IS_RELAY_RETRY_INITIALIZED as IS_RELAY_RETRY_HELPER_INITIALIZED;
pub use http_relay_retry::IS_RELAY_RETRY_INITIALIZED as IS_RELAY_RETRY_TUNING_INITIALIZED;
pub use http_relay_retry::IS_RELAY_RETRY_INITIALIZED as IS_RELAY_RETRY_TUNING_HELPER_INITIALIZED;

mod http_relay_buffer;
pub use http_relay_buffer::{HttpRelayBuffer, IS_RELAY_BUFFER_INITIALIZED};
pub type HttpRelayBufferDiagnostics = HttpRelayBuffer;
pub type HttpRelayBufferDiagnosticsHelper = HttpRelayBuffer;
pub type HttpRelayBufferDiagnosticsTuning = HttpRelayBuffer;
pub type HttpRelayBufferDiagnosticsTuningHelper = HttpRelayBuffer;
pub type HttpRelayBufferHelper = HttpRelayBuffer;
pub type HttpRelayBufferTuning = HttpRelayBuffer;
pub type HttpRelayBufferTuningHelper = HttpRelayBuffer;
pub use http_relay_buffer::IS_RELAY_BUFFER_INITIALIZED as IS_RELAY_BUFFER_DIAGNOSTICS_INITIALIZED;
pub use http_relay_buffer::IS_RELAY_BUFFER_INITIALIZED as IS_RELAY_BUFFER_DIAGNOSTICS_HELPER_INITIALIZED;
pub use http_relay_buffer::IS_RELAY_BUFFER_INITIALIZED as IS_RELAY_BUFFER_DIAGNOSTICS_TUNING_INITIALIZED;
pub use http_relay_buffer::IS_RELAY_BUFFER_INITIALIZED as IS_RELAY_BUFFER_DIAGNOSTICS_TUNING_HELPER_INITIALIZED;
pub use http_relay_buffer::IS_RELAY_BUFFER_INITIALIZED as IS_RELAY_BUFFER_HELPER_INITIALIZED;
pub use http_relay_buffer::IS_RELAY_BUFFER_INITIALIZED as IS_RELAY_BUFFER_TUNING_INITIALIZED;
pub use http_relay_buffer::IS_RELAY_BUFFER_INITIALIZED as IS_RELAY_BUFFER_TUNING_HELPER_INITIALIZED;

mod http_relay_connection;
pub use http_relay_connection::{HttpRelayConnection, IS_RELAY_CONNECTION_INITIALIZED};
pub type HttpRelayConnectionDiagnostics = HttpRelayConnection;
pub type HttpRelayConnectionDiagnosticsHelper = HttpRelayConnection;
pub type HttpRelayConnectionDiagnosticsTuning = HttpRelayConnection;
pub type HttpRelayConnectionDiagnosticsTuningHelper = HttpRelayConnection;
pub type HttpRelayConnectionHelper = HttpRelayConnection;
pub type HttpRelayConnectionTuning = HttpRelayConnection;
pub type HttpRelayConnectionTuningHelper = HttpRelayConnection;
pub use http_relay_connection::IS_RELAY_CONNECTION_INITIALIZED as IS_RELAY_CONNECTION_DIAGNOSTICS_INITIALIZED;
pub use http_relay_connection::IS_RELAY_CONNECTION_INITIALIZED as IS_RELAY_CONNECTION_DIAGNOSTICS_HELPER_INITIALIZED;
pub use http_relay_connection::IS_RELAY_CONNECTION_INITIALIZED as IS_RELAY_CONNECTION_DIAGNOSTICS_TUNING_INITIALIZED;
pub use http_relay_connection::IS_RELAY_CONNECTION_INITIALIZED as IS_RELAY_CONNECTION_DIAGNOSTICS_TUNING_HELPER_INITIALIZED;
pub use http_relay_connection::IS_RELAY_CONNECTION_INITIALIZED as IS_RELAY_CONNECTION_HELPER_INITIALIZED;
pub use http_relay_connection::IS_RELAY_CONNECTION_INITIALIZED as IS_RELAY_CONNECTION_TUNING_INITIALIZED;
pub use http_relay_connection::IS_RELAY_CONNECTION_INITIALIZED as IS_RELAY_CONNECTION_TUNING_HELPER_INITIALIZED;
