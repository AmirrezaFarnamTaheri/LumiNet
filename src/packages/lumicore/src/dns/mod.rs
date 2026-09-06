//! # DNS Module
//!
//! DNS resolution with support for multiple transports: plain UDP (port 53),
//! DNS-over-HTTPS (DoH), and DNS-over-TLS (DoT). Includes hand-crafted DNS
//! packet building and parsing for minimal dependencies and full control.

pub mod antipoison;
pub mod dns_client;
pub mod dnsproxy;
mod doh;
mod dot;
pub mod evasion_autotune_presets;
pub mod hosts_optimizer;
mod packet;
mod udp;

pub use doh::{resolve_doh, resolve_doh_json, DOH_ENDPOINTS};
pub use dot::{resolve_dot, DOT_SERVERS};
pub use evasion_autotune_presets::*;
pub use hosts_optimizer::{run_hosts_optimization, IN_MEMORY_HOSTS};
pub use packet::{
    build_query, decode_domain_name, encode_domain_name, parse_response, CLASS_IN, TYPE_A,
    TYPE_AAAA, TYPE_CNAME, TYPE_HTTPS, TYPE_MX, TYPE_NS, TYPE_PTR, TYPE_SOA, TYPE_TXT,
};
pub use udp::{resolve, resolve_batch, scan_dns_servers, DnsServerResult};
pub mod anonymized_dns;
pub mod ewma_rtt;
pub mod hardware_advisor;
pub mod serve_stale;
pub mod dns_poison_filter;
pub mod doh_client_pool;
pub use anonymized_dns::*;
pub use ewma_rtt::{EWMARtt, EWMARttRegistry};
pub use hardware_advisor::*;
pub use serve_stale::{CachedResponse, SharedStaleCache, StaleCache};
pub use dns_poison_filter::*;
pub use doh_client_pool::*;

pub mod sni_router;
pub use sni_router::SniRoutingTable;
pub mod dns_tunnel_codec;

pub mod edns_subnet_scrubber;
pub mod dns_wizard_profile_generator;
pub mod dns_arq_window_codec;
pub mod doh_fallback_hierarchy;
pub mod ebpf_dns_drop_filter;
pub mod dns_blocklist_engine;
pub mod poisoned_dns_response_filter;
