//! Out-Of-Window Fake SNI Desync Injection Engine
//!
//! Calculates out-of-window TCP sequence numbers for spoofed ClientHello injection
//! to poison middlebox DPI state while being discarded by RFC-compliant TCP receivers.

use super::tls_fragmenter::{TlsFragmentStrategy, TlsFragmenter};

/// Calculates the out-of-window sequence number so the packet precedes the receiver's window.
/// Formula: `(isn + 1 - payload_len) & 0xFFFFFFFF`
pub fn compute_out_of_window_seq(isn: u32, payload_len: usize) -> u32 {
    let sub = (payload_len as u64) & 0xFFFFFFFF;
    let res = (isn as u64 + 1).wrapping_sub(sub);
    (res & 0xFFFFFFFF) as u32
}

/// A planned injection segment to be emitted over the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesyncSegment {
    /// Calculated sequence number for the TCP header.
    pub seq_num: u32,
    /// Whether this is a decoy packet meant for DPI desynchronization.
    pub is_decoy: bool,
    /// TCP PSH flag.
    pub psh: bool,
    /// Relative delay before sending this packet (in milliseconds).
    pub delay_ms: u64,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
}

/// Planner orchestrating combined fake SNI injection and legitimate ClientHello fragmentation.
pub struct SniDesyncPlanner;

impl SniDesyncPlanner {
    /// Builds an evasion plan combining an out-of-window fake SNI packet with
    /// fragmented legitimate ClientHello writes.
    pub fn plan(
        isn: u32,
        real_client_hello: &[u8],
        fake_client_hello: &[u8],
        frag_strategy: TlsFragmentStrategy,
        fragment_delay_ms: u64,
    ) -> Vec<DesyncSegment> {
        let mut segments = Vec::new();

        // 1. Out-of-window fake SNI decoy packet
        let wrong_seq = compute_out_of_window_seq(isn, fake_client_hello.len());
        segments.push(DesyncSegment {
            seq_num: wrong_seq,
            is_decoy: true,
            psh: true,
            delay_ms: 0,
            payload: fake_client_hello.to_vec(),
        });

        // 2. Real ClientHello fragments starting at legitimate sequence (isn + 1)
        let fragments = TlsFragmenter::fragment(real_client_hello, frag_strategy);
        let mut current_seq = isn.wrapping_add(1);

        for (i, frag) in fragments.into_iter().enumerate() {
            let delay = if i == 0 { 1 } else { fragment_delay_ms };
            let frag_len = frag.len() as u32;
            segments.push(DesyncSegment {
                seq_num: current_seq,
                is_decoy: false,
                psh: true,
                delay_ms: delay,
                payload: frag,
            });
            current_seq = current_seq.wrapping_add(frag_len);
        }

        segments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_out_of_window_seq() {
        let isn = 1000;
        let payload_len = 100;
        let seq = compute_out_of_window_seq(isn, payload_len);
        assert_eq!(seq, 901); // 1000 + 1 - 100 = 901
    }

    #[test]
    fn test_compute_out_of_window_seq_wraparound() {
        let isn = 10;
        let payload_len = 50;
        let seq = compute_out_of_window_seq(isn, payload_len);
        // (11 - 50) = -39 mod 2^32 = 4294967257
        assert_eq!(seq, u32::MAX - 38);
    }

    #[test]
    fn test_desync_plan_structure() {
        let isn = 5000;
        let fake = b"FAKE_CLIENT_HELLO_BYTES";
        let real = b"REAL_TLS_CLIENT_HELLO_LONG_DATA_TO_FRAGMENT";

        let plan = SniDesyncPlanner::plan(
            isn,
            real,
            fake,
            TlsFragmentStrategy::Half,
            10,
        );

        assert_eq!(plan.len(), 3); // 1 decoy + 2 fragments
        assert!(plan[0].is_decoy);
        assert_eq!(plan[0].seq_num, compute_out_of_window_seq(isn, fake.len()));

        assert!(!plan[1].is_decoy);
        assert_eq!(plan[1].seq_num, isn + 1);

        assert!(!plan[2].is_decoy);
        assert_eq!(plan[2].seq_num, (isn + 1) + plan[1].payload.len() as u32);
    }
}
