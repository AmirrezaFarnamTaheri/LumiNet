//! # LumiCore — High-Performance Network Scanning Engine
//!
//! The Rust core library for LumiNet. Provides performance-critical
//! network probe implementations compiled as a C-compatible static
//! library for Go to call via CGO.
//!
//! ## Architecture
//!
//! ```text
//! LumiCore
//! ├── engine.rs          ← Unified entry point (LumiNetEngine)
//! ├── crypto/            ← Cryptographic primitives (AES-GCM, ChaCha20, FEC, HTTP tunnel)
//! │   ├── aes_gcm.rs    ← AES-GCM stream cipher
//! │   └── tunnel.rs     ← HTTP tunnel with X25519 DH
//! ├── evasion/           ← DPI evasion engine
//! │   ├── fingerprint.rs ← Browser fingerprint mimicry (40+ variants)
//! │   ├── fragment.rs    ← TLS/SNI fragmentation
//! │   ├── desync.rs      ← TCP desync attacks
//! │   ├── http_tricks.rs ← HTTP header manipulation
//! │   ├── noise.rs       ← QUIC noise injection
//! │   ├── sni_spoof.rs   ← SNI spoofing
//! │   ├── smuggling.rs   ← HTTP request smuggling
//! │   └── detect.rs      ← Censorship detection
//! ├── netutil/           ← Network utilities
//! │   ├── ip_check.rs    ← IP validation (10+ checks)
//! │   ├── ssrf.rs        ← SSRF protection
//! │   ├── headers.rs     ← Header stripping
//! │   ├── classification.rs ← Network classification
//! │   ├── shared.rs      ← Shared utilities (hex, base64, etc.)
//! │   └── ip_security.rs ← IP reputation scoring
//! ├── security/          ← Security features
//! │   ├── blocklist.rs   ← Domain blocklist engine
//! │   ├── challenge_solver.rs ← CDN challenge bypass
//! │   ├── forensics.rs   ← Network forensics
//! │   └── gov_blocklist.rs ← Government IP classification
//! ├── proxy/             ← Proxy protocol handling
//! │   ├── parsers.rs     ← URI parsing (VLESS/VMess/SS/Trojan/Hy2/TUIC)
//! │   ├── handler.rs     ← SOCKS5/HTTP CONNECT handler
//! │   ├── virtual_dns.rs ← Fake-IP DNS
//! │   └── flow_trie.rs   ← Flow aggregation trie
//! ├── platform/          ← Platform-specific code
//! │   ├── android.rs     ← Android transparent proxy
//! │   ├── device_spoof.rs ← Device fingerprint spoofing
//! │   └── syscall_evasion.rs ← Windows syscall evasion
//! ├── obfuscation/       ← Traffic obfuscation
//! │   ├── polymorph.rs   ← Traffic shaping
//! │   ├── steganography.rs ← Steganographic encoding
//! │   └── protocol_detect/ ← DPI protocol signatures (115 protocols)
//! ├── data/              ← Data structures
//! │   └── ring_buffer.rs ← Ring buffer with eviction
//! ├── dns/               ← DNS subsystem
//! │   ├── doh.rs         ← DNS-over-HTTPS
//! │   ├── dot.rs         ← DNS-over-TLS
//! │   ├── packet.rs      ← DNS packet parsing
//! │   ├── udp.rs         ← UDP DNS
//! │   └── antipoison.rs  ← DNS anti-poisoning
//! ├── cidr/              ← CIDR expansion
//! ├── routing/           ← IP routing trie
//! ├── sni/               ← SNI detection
//! ├── socks/             ← SOCKS proxy
//! ├── speed/             ← Speed testing
//! ├── tcp/               ← TCP probing + fragmentation
//! ├── tls/               ← TLS probing + cert installation
//! │   └── cert_installer/ ← Platform cert installation (macOS/Linux/Windows/NSS)
//! ├── wg/                ← WireGuard
//! ├── http/              ← HTTP probing
//! ├── icmp/              ← ICMP probing
//! └── ffi/               ← FFI exports for Go CGO
//!     └── exports/       ← Exported functions (scan/probe/dns/tls/util)
//! ```

// ─── Core Modules ────────────────────────────────────────────────────────────
pub mod engine;
pub mod ffi;
pub mod runtime;
pub mod shm;
pub mod types;

// ─── Organized Subdirectories ────────────────────────────────────────────────
pub mod cidr;
pub mod codec;
pub mod crypto;
pub mod data;
pub mod diagnostics;
pub mod dns;
pub mod evasion;
pub mod hs;
pub mod http;
pub mod icmp;
pub mod jobs;
pub mod multipath;
pub mod netutil;
pub mod obfuscation;
pub mod platform;
pub mod proxy;
pub mod quic;
pub mod relay;
pub mod routing;
pub mod scanner;
pub mod security;
pub mod sflow;
pub mod sni;
pub mod socks;
pub mod speed;
pub mod system;
pub mod tcp;
pub mod tls;
pub mod transport;
pub mod tun_vpn;
pub mod wg;
pub mod ws_tunnel;

// ─── Public API ──────────────────────────────────────────────────────────────
pub use engine::LumiNetEngine;
pub use types::*;

#[cfg(feature = "logging")]
static LOGGING_INIT: std::sync::Once = std::sync::Once::new();

/// Called by the OS loader (or explicitly by Go) to initialise Rust globals.
/// Must be called before any other lumicore_* function.
#[no_mangle]
pub extern "C" fn lumicore_init() {
    // Best-effort preload. Runtime-dependent FFI operations surface the
    // retained initialization error through their existing error contracts.
    let _ = crate::runtime::get();
    // Initialize logging (tracing subscriber if available)
    #[cfg(feature = "logging")]
    LOGGING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .try_init();
    });
}

/// Called on process shutdown. Gives runtime a chance to flush logs.
#[no_mangle]
pub extern "C" fn lumicore_shutdown() {
    // Nothing to do currently; runtime drops when process exits
}

#[cfg(all(test, feature = "logging"))]
mod logging_tests {
    #[test]
    fn lumicore_init_is_idempotent_with_an_existing_subscriber() {
        let _ = tracing_subscriber::fmt().try_init();

        super::lumicore_init();
        super::lumicore_init();
    }
}
