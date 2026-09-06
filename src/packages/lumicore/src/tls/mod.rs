//! # TLS Module
//!
//! TLS handshake probing, certificate inspection, and SSL inspection detection.

pub mod cert_installer;
pub mod ech_greaser;
pub mod fingerprint;
pub mod mitm;
pub mod pqc;
mod prober;

pub use mitm::MitmCertManager;
pub use prober::{
    detect_ssl_inspection, pad_client_hello, tls_handshake, tls_handshake_batch,
    SslInspectionResult,
};
