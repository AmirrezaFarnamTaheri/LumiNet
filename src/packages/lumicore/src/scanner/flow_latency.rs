//! TCP Handshake Flow Latency & RTT Tracker
//!
//! Computes TCP SYN->SYN-ACK/ACK round-trip latency via 4-tuple flow hashing.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

/// Computes 64-bit FNV-1a hash over a byte slice.
pub fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Computes a canonical bidirectional flow hash for a 4-tuple.
pub fn compute_flow_hash(src: SocketAddr, dst: SocketAddr) -> u64 {
    let mut buf_a = Vec::with_capacity(18);
    match src.ip() {
        IpAddr::V4(ip) => buf_a.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => buf_a.extend_from_slice(&ip.octets()),
    }
    buf_a.extend_from_slice(&src.port().to_be_bytes());

    let mut buf_b = Vec::with_capacity(18);
    match dst.ip() {
        IpAddr::V4(ip) => buf_b.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => buf_b.extend_from_slice(&ip.octets()),
    }
    buf_b.extend_from_slice(&dst.port().to_be_bytes());

    let hash_a = fnv1a_hash(&buf_a);
    let hash_b = fnv1a_hash(&buf_b);

    (hash_a.wrapping_add(hash_b)).wrapping_mul(FNV_PRIME)
}

/// Statistics accumulator for observed flow latencies.
#[derive(Debug, Clone, Default)]
pub struct FlowLatencyStats {
    pub sample_count: u64,
    pub min_rtt: Option<Duration>,
    pub max_rtt: Option<Duration>,
    pub total_rtt: Duration,
}

impl FlowLatencyStats {
    pub fn record(&mut self, rtt: Duration) {
        self.sample_count += 1;
        self.total_rtt += rtt;
        self.min_rtt = Some(match self.min_rtt {
            Some(cur) => cur.min(rtt),
            None => rtt,
        });
        self.max_rtt = Some(match self.max_rtt {
            Some(cur) => cur.max(rtt),
            None => rtt,
        });
    }

    pub fn average_rtt(&self) -> Option<Duration> {
        if self.sample_count == 0 {
            None
        } else {
            Some(self.total_rtt / (self.sample_count as u32))
        }
    }
}

/// State machine tracking in-flight TCP handshakes to compute RTT.
#[derive(Debug, Clone, Default)]
pub struct FlowLatencyTracker {
    /// In-flight SYN timestamp (in nanoseconds).
    syn_table: HashMap<u64, u64>,
    /// Accumulated latency statistics.
    pub stats: FlowLatencyStats,
}

impl FlowLatencyTracker {
    pub fn new() -> Self {
        Self {
            syn_table: HashMap::new(),
            stats: FlowLatencyStats::default(),
        }
    }

    /// Records outgoing or incoming SYN packet timestamp.
    pub fn on_syn(&mut self, src: SocketAddr, dst: SocketAddr, timestamp_nanos: u64) {
        let key = compute_flow_hash(src, dst);
        self.syn_table.insert(key, timestamp_nanos);
    }

    /// Records matching SYN-ACK or ACK packet and returns computed RTT if SYN was tracked.
    pub fn on_syn_ack(&mut self, src: SocketAddr, dst: SocketAddr, timestamp_nanos: u64) -> Option<Duration> {
        let key = compute_flow_hash(src, dst);
        if let Some(syn_ts) = self.syn_table.remove(&key) {
            if timestamp_nanos >= syn_ts {
                let diff_nanos = timestamp_nanos - syn_ts;
                let rtt = Duration::from_nanos(diff_nanos);
                self.stats.record(rtt);
                return Some(rtt);
            }
        }
        None
    }

    /// Cleans up stale handshake entries older than max_age_nanos.
    pub fn prune_stale(&mut self, now_nanos: u64, max_age_nanos: u64) -> usize {
        let before = self.syn_table.len();
        self.syn_table.retain(|_, &mut ts| now_nanos.saturating_sub(ts) <= max_age_nanos);
        before - self.syn_table.len()
    }

    /// Count of currently pending handshakes.
    pub fn pending_handshakes(&self) -> usize {
        self.syn_table.len()
    }

    /// Processes an incoming raw eBPF TCP event and computes latency if matching SYN-ACK.
    pub fn process_packet(&mut self, pkt: &TcpProbePacket) -> Option<Duration> {
        if pkt.syn && !pkt.ack {
            self.on_syn(pkt.src, pkt.dst, pkt.timestamp_nanos);
            None
        } else if pkt.syn && pkt.ack {
            self.on_syn_ack(pkt.src, pkt.dst, pkt.timestamp_nanos)
        } else {
            None
        }
    }
}

/// Raw eBPF TC classifier event packet (48 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpProbePacket {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub syn: bool,
    pub ack: bool,
    pub timestamp_nanos: u64,
}

impl TcpProbePacket {
    /// Deserializes a 48-byte eBPF perf buffer into a structured TCP probe packet.
    pub fn from_raw_event(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 48 {
            return None;
        }

        let mut src_ip_bytes = [0u8; 16];
        let mut dst_ip_bytes = [0u8; 16];
        src_ip_bytes.copy_from_slice(&bytes[0..16]);
        dst_ip_bytes.copy_from_slice(&bytes[16..32]);

        let src_ip = parse_ip_mapped(&src_ip_bytes);
        let dst_ip = parse_ip_mapped(&dst_ip_bytes);

        let src_port = u16::from_be_bytes([bytes[32], bytes[33]]);
        let dst_port = u16::from_be_bytes([bytes[34], bytes[35]]);

        let syn = bytes[36] == 1;
        let ack = bytes[37] == 1;

        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&bytes[40..48]);
        let timestamp_nanos = u64::from_le_bytes(ts_bytes);

        Some(TcpProbePacket {
            src: SocketAddr::new(src_ip, src_port),
            dst: SocketAddr::new(dst_ip, dst_port),
            syn,
            ack,
            timestamp_nanos,
        })
    }
}

fn parse_ip_mapped(bytes: &[u8; 16]) -> IpAddr {
    // Check if IPv4-mapped IPv6 address (::ffff:x.x.x.x)
    if bytes[0..10] == [0; 10] && bytes[10] == 0xff && bytes[11] == 0xff {
        let mut v4_bytes = [0u8; 4];
        v4_bytes.copy_from_slice(&bytes[12..16]);
        IpAddr::V4(std::net::Ipv4Addr::from(v4_bytes))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::from(*bytes))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_flow_hash_symmetry() {
        let a: SocketAddr = "192.168.1.10:54321".parse().unwrap();
        let b: SocketAddr = "1.1.1.1:443".parse().unwrap();

        let h1 = compute_flow_hash(a, b);
        let h2 = compute_flow_hash(b, a);
        assert_eq!(h1, h2, "flow hash must be symmetric for forward and reverse packets");
    }

    #[test]
    fn test_rtt_tracking() {
        let mut tracker = FlowLatencyTracker::new();
        let client: SocketAddr = "10.0.0.2:40000".parse().unwrap();
        let server: SocketAddr = "10.0.0.1:80".parse().unwrap();

        let t_syn = 1_000_000_000; // 1.000s
        tracker.on_syn(client, server, t_syn);
        assert_eq!(tracker.pending_handshakes(), 1);

        let t_ack = 1_025_000_000; // 1.025s (25ms latency)
        let rtt = tracker.on_syn_ack(server, client, t_ack).expect("RTT should be calculated");
        assert_eq!(rtt, Duration::from_millis(25));
        assert_eq!(tracker.pending_handshakes(), 0);

        assert_eq!(tracker.stats.sample_count, 1);
        assert_eq!(tracker.stats.min_rtt, Some(Duration::from_millis(25)));
        assert_eq!(tracker.stats.max_rtt, Some(Duration::from_millis(25)));
        assert_eq!(tracker.stats.average_rtt(), Some(Duration::from_millis(25)));
    }

    #[test]
    fn test_prune_stale() {
        let mut tracker = FlowLatencyTracker::new();
        let s1: SocketAddr = "1.2.3.4:100".parse().unwrap();
        let s2: SocketAddr = "5.6.7.8:200".parse().unwrap();

        tracker.on_syn(s1, s2, 100);
        let pruned = tracker.prune_stale(1000, 500);
        assert_eq!(pruned, 1);
        assert_eq!(tracker.pending_handshakes(), 0);
    }

    #[test]
    fn test_raw_event_parsing_and_processing() {
        let mut raw_syn = [0u8; 48];
        // IPv4-mapped 1.2.3.4
        raw_syn[10] = 0xff;
        raw_syn[11] = 0xff;
        raw_syn[12] = 1;
        raw_syn[13] = 2;
        raw_syn[14] = 3;
        raw_syn[15] = 4;

        // IPv4-mapped 5.6.7.8
        raw_syn[26] = 0xff;
        raw_syn[27] = 0xff;
        raw_syn[28] = 5;
        raw_syn[29] = 6;
        raw_syn[30] = 7;
        raw_syn[31] = 8;

        // src port 12345 = 0x3039
        raw_syn[32] = 0x30;
        raw_syn[33] = 0x39;
        // dst port 80 = 0x0050
        raw_syn[34] = 0x00;
        raw_syn[35] = 0x50;

        raw_syn[36] = 1; // SYN
        raw_syn[37] = 0; // ACK

        let ts_syn: u64 = 1_000_000_000;
        raw_syn[40..48].copy_from_slice(&ts_syn.to_le_bytes());

        let pkt_syn = TcpProbePacket::from_raw_event(&raw_syn).expect("must parse raw SYN event");
        assert!(pkt_syn.syn);
        assert!(!pkt_syn.ack);
        assert_eq!(pkt_syn.src.to_string(), "1.2.3.4:12345");
        assert_eq!(pkt_syn.dst.to_string(), "5.6.7.8:80");

        let mut tracker = FlowLatencyTracker::new();
        assert!(tracker.process_packet(&pkt_syn).is_none());
        assert_eq!(tracker.pending_handshakes(), 1);

        // Synthesize reverse SYN-ACK packet
        let mut raw_synack = [0u8; 48];
        raw_synack[0..16].copy_from_slice(&raw_syn[16..32]); // reverse src/dst
        raw_synack[16..32].copy_from_slice(&raw_syn[0..16]);
        raw_synack[32..34].copy_from_slice(&raw_syn[34..36]);
        raw_synack[34..36].copy_from_slice(&raw_syn[32..34]);
        raw_synack[36] = 1; // SYN
        raw_synack[37] = 1; // ACK
        let ts_synack: u64 = 1_015_000_000; // +15ms
        raw_synack[40..48].copy_from_slice(&ts_synack.to_le_bytes());

        let pkt_synack = TcpProbePacket::from_raw_event(&raw_synack).expect("must parse SYN-ACK event");
        let rtt = tracker.process_packet(&pkt_synack).expect("must compute RTT");
        assert_eq!(rtt, Duration::from_millis(15));
        assert_eq!(tracker.pending_handshakes(), 0);
    }
}

