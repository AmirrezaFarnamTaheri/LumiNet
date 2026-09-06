//! # Network Utilities
//!
//! Unified IP validation, SSRF protection, header sanitization, and shared utilities.
//! Consolidates: security.rs + ip_security.rs + virtual_dns.rs + shared helpers.

pub mod adaptive_limiter;
pub mod classification;
pub mod headers;
pub mod ip_check;
pub mod shared;
pub mod ssrf;
pub mod supervision;

pub use adaptive_limiter::*;
pub use classification::*;
pub use headers::*;
pub use ip_check::*;
pub use shared::*;
pub use ssrf::*;
pub use supervision::*;
