//! Codec module — low-level protocol wire-format encoders/decoders.
//!
//! Includes XOR-padding schemes (VLESS XorConn) and other connection obfuscation
//! codecs that operate below the transport layer.

pub mod xor_conn;

pub use xor_conn::{XorConn, XorConnConfig, XorConnError, XorConnHeader};
