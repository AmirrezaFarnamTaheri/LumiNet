//! # Protocol Detection
//!
//! DPI protocol signature matching for traffic classification.
//! Split into sub-modules for maintainability:
//! - `signatures.rs`: All 115 protocol signatures
//! - `detector.rs`: Detection logic
//! - `dpi_db.rs`: DPI signature database

pub mod detector;
pub mod dpi_db;
pub mod signatures;

pub use detector::{detect_protocol, ProtocolCategory, ProtocolMatch};
pub use dpi_db::DpiSignatureDb;
