pub mod client_initial;
// Stable-toolchain fuzz-style harness (cfg(test) only).
#[cfg(test)]
mod fuzz_ish;
pub mod scan;

pub use client_initial::{
    CryptoChunk, Fingerprinter, GatheredInitial, QuicFingerprint,
    decrypt_initial_v1, extract_crypto_frames, fingerprint_num_id,
    parse_long_header, decode_varint,
};
pub use scan::{scan_initial_datagram, QuicScanObserver, ScannedQuicClient};

pub mod zero_rtt_session_cache;
