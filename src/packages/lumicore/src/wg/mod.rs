//! # WireGuard Module
//!
//! WireGuard handshake probing and diagnostic utilities.

mod prober;

pub use prober::WgProber;

pub mod wireguard_peer_allocator;
pub use wireguard_peer_allocator::WireguardCidrAllocator;

pub mod peer_acl_matrix;
pub use peer_acl_matrix::{PeerAclMatrix, PeerNodeId};

pub mod static_cidr_pool;
pub mod multihop_relay_chain;

pub mod adaptive_mtu_discovery;
