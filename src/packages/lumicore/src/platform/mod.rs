//! # Platform Module
//!
//! Platform-specific code including Android transparent proxy,
//! device spoofing, and Windows syscall evasion.

pub mod android;
pub mod connection_lineage;
pub mod device_spoof;
pub mod embedded_controller;
pub mod hotkeys;
pub mod job_object_supervisor;
pub mod process_reaper;
pub mod socket_protector;
pub mod syscall_evasion;
pub mod system_proxy;
pub mod transactional_route;
pub mod plugin_bridge;
pub mod pac_engine;

pub use android::*;
pub use connection_lineage::*;
pub use device_spoof::*;
pub use embedded_controller::*;
pub use hotkeys::*;
pub use job_object_supervisor::*;
pub use process_reaper::*;
pub use socket_protector::*;
pub use syscall_evasion::*;
pub use system_proxy::*;
pub use transactional_route::*;
pub use plugin_bridge::*;
pub use pac_engine::*;

pub mod toolchain_proxy_wrapper;
pub mod mobile_tunnel_supervisor;
pub mod mobile_engine_provider;
pub mod desktop_client_manager;

pub mod protocol_profile_orchestrator;

pub mod core_engine_supervisor;
pub mod autonomous_global_proxy_supervisor;




