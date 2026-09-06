// SPDX-License-Identifier: MIT
//
// Second-order wrapper for the clienthellod-port QUIC fingerprinter.
//
// While `client_initial::Fingerprinter` is a single-stream primitive
// (caller-managed map keyed by an arbitrary string), the LumiNet scanner
// needs a passive observer that:
//   * keeps a per-thread session map,
//   * parses the client address out of a UDP datagram and uses it as
//     the per-client key,
//   * surfaces a stable, JSON-serialisable result the existing
//     scanner/daemon handlers can consume.
//
// This module is the convergence point between the parser/fingerprinter
// primitive and the rest of the system.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::client_initial::{decrypt_initial_v1, handle_datagram, Fingerprinter, QuicFingerprint};

/// Default per-client expiry applied to a session after completion.
const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(60);

/// Result of a passive scan over one (or more) datagram(s) from a single
/// client. `Stable` mirrors the upstream NumID so callers can match
/// against the corpus ids shipped in
/// daemon/internal/analysis/scanner/testdata/quic_corpus.
#[derive(Debug, Clone)]
pub struct ScannedQuicClient {
    pub addr: SocketAddr,
    pub num_id: u64,
    pub hex_id: String,
    pub client_hello: Vec<u8>,
    pub observed_at: Instant,
}

/// Passive observer with a built-in session map. Thread-affine: keep
/// one instance per scanning thread (matches the existing scanner's
/// per-thread `Fingerprinter` pattern).
pub struct QuicScanObserver {
    inner: Fingerprinter,
    sessions: HashMap<SocketAddr, Instant>,
    server_side: bool,
}

impl Default for QuicScanObserver {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_TTL, false)
    }
}

impl QuicScanObserver {
    pub fn new(expiry: Duration, server_side: bool) -> Self {
        Self {
            inner: Fingerprinter::new(expiry),
            sessions: HashMap::new(),
            server_side,
        }
    }

    /// Feed one UDP datagram observed from `addr`. Returns a
    /// `ScannedQuicClient` only when this datagram (combined with
    /// any prior datagrams from the same client) just completed
    /// reassembly of the ClientHello.
    pub fn observe(&mut self, addr: SocketAddr, datagram: &[u8]) -> Option<ScannedQuicClient> {
        let key = addr.to_string();
        let fp = handle_datagram(&mut self.inner, &key, datagram, self.server_side);
        if fp.is_some() {
            self.sessions.insert(addr, Instant::now());
        }
        fp.map(|QuicFingerprint { num_id, hex_id, stream }| ScannedQuicClient {
            addr,
            num_id,
            hex_id,
            client_hello: stream,
            observed_at: Instant::now(),
        })
    }

    /// Number of clients currently in the session map (active or
    /// completed but not yet observed).
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

/// One-shot convenience: parse a single datagram, return a
/// `ScannedQuicClient` if it is a complete ClientHello-bearing Initial,
/// or an error string if decryption/parse failed. This is the highest-level
/// entry point and the one the scanner's `observe_quic_initial` integration
/// should call.
pub fn scan_initial_datagram(
    addr: SocketAddr,
    datagram: &[u8],
    server_side: bool,
) -> Result<Option<ScannedQuicClient>, String> {
    // Caller wants a single-fire observation: use a fresh fingerprinter
    // so two unrelated clients never share a session. The caller manages
    // a long-lived observer via [QuicScanObserver::observe] when they
    // need to handle CRYPTO frames split across multiple datagrams.
    let payload = decrypt_initial_v1(datagram, server_side)
        .map_err(|e| format!("decrypt: {e}"))?;
    let mut fp = Fingerprinter::default();
    let key = addr.to_string();
    let out = fp.handle_decrypted_initial(&key, &payload);
    Ok(out.map(|QuicFingerprint { num_id, hex_id, stream }| ScannedQuicClient {
        addr,
        num_id,
        hex_id,
        client_hello: stream,
        observed_at: Instant::now(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn scan_initial_datagram_rejects_short_buffer() {
        let addr = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443));
        let err = scan_initial_datagram(addr, &[0u8; 5], false).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn scan_initial_datagram_rejects_non_v1() {
        let addr = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443));
        let mut d = vec![0xc3, 0, 0, 0, 0x6b, 0x33, 0xcf, 0x38];
        d.extend_from_slice(&[0x00; 16]);
        let r = scan_initial_datagram(addr, &d, false);
        assert!(r.is_err());
    }

    #[test]
    fn observer_round_trip_short_session() {
        // Even with a malformed payload the observer must not panic and
        // must not leak sessions: confirm the map is empty after a
        // single failed observe.
        let mut obs = QuicScanObserver::default();
        let addr = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443));
        let _ = obs.observe(addr, &[0u8; 10]);
        assert_eq!(obs.session_count(), 0);
    }
}
