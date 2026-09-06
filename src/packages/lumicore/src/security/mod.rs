//! # Security Module
//!
//! Security features including blocklists, CDN challenge solving,
//! government IP classification, and network forensics.

pub mod anomaly;
pub mod blocklist;
pub mod challenge_solver;
pub mod credentials;
pub mod forensics;
pub mod gov_blocklist;
pub mod idn_sanitizer;
pub mod leak_guard;
pub mod memory;

pub use anomaly::*;
pub use blocklist::*;
pub use challenge_solver::*;
pub use credentials::*;
pub use forensics::*;
pub use gov_blocklist::*;
pub use idn_sanitizer::*;
pub use leak_guard::*;
pub use memory::*;

pub mod encrypted_payload_envelope;
pub use encrypted_payload_envelope::*;

pub mod firewall_killswitch;
pub use firewall_killswitch::{filter_endpoints, KillswitchRules, ProviderEndpoint};

pub mod dynamic_ca_manager;
pub mod bandwidth_quota_enforcer;
pub mod identity_policy_evaluator;
pub mod gateway_health_monitor;

pub mod client_ban_supervisor;
pub mod enterprise_access_interceptor;
pub mod endpoint_credential_vault;
pub mod session_rotation_pool;
pub mod wireguard_ipam_manager;

pub mod enterprise_vpn_controller;
pub mod ipsec_ikev2_state_machine;
pub mod leak_guard_supervisor;

pub mod relay_rotation_circuit_breaker;
