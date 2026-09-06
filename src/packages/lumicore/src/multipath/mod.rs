//! # Multipath Multiplexing & Bonding Engine
//!
//! Ported and unified from `XPlex-main`.
//! Provides multi-tunnel bonding, packet deduplication, reordering,
//! and latency-adaptive path classification across parallel egress proxies.

pub mod controller;
pub mod dedup;
pub mod frame;

pub use controller::{
    AdaptiveConfig, AdaptiveController, ControllerTransition, PathClassification, PathState,
    PathStats,
};
pub use dedup::{DedupBuffer, DedupError, DEFAULT_GAP_TIMEOUT};
pub use frame::{
    MpFrame, MpFrameError, MpFrameType, MP_HEADER_LEN, MP_MAX_PAYLOAD,
};

pub mod multipath_dedup_buffer;
pub mod multipath_gateway_coordinator;
