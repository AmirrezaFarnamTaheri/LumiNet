//! # SNI Module
//!
//! SNI (Server Name Indication) blocking detection. Probes whether TLS
//! connections to specific domains are being blocked, reset, or tampered
//! with at the network level based on the SNI field in the TLS ClientHello.

mod detector;
mod spoofer;
pub mod wire_sniffer;

pub use detector::{classify_sni_result, detect_sni_blocking, SniClassification, TEST_DOMAINS};
pub use spoofer::build_client_hello;
pub use wire_sniffer::{http_host, sniff_hostname, tls_sni};

pub mod domain_fronting_engine;
pub mod sni_fragmentation_injector;

