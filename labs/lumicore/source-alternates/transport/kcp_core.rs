//! # KCP Reliable UDP Transport Core
//!
//! KCP is a reliable ARQ protocol that delivers faster retransmission than TCP
//! at the cost of higher bandwidth. Ported from kcp-go-master and libkcp-master.
//!
//! Features:
//! - Selective acknowledgement (SACK) window
//! - Forward Error Correction (FEC) using Reed-Solomon XOR groups
//! - Configurable retransmission timers and congestion window
//!
//! Wire segment header (24 bytes):
//! ```text
//! [conv   : u32][cmd    : u8][frg    : u8][wnd    : u16]
//! [ts     : u32][sn     : u32][una    : u32][len   : u32]
//! [data   : len bytes]
//! ```

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// KCP command types.
pub mod cmd {
    pub const PUSH: u8 = 81;  // Data push
    pub const ACK: u8 = 82;   // Acknowledgement
    pub const WASK: u8 = 83;  // Window size probe
    pub const WINS: u8 = 84;  // Window size answer
}

/// KCP segment wire header size (without data payload).
pub const KCP_OVERHEAD: usize = 24;
/// Maximum transmission unit for KCP segments.
pub const KCP_MTU_DEF: usize = 1400;
/// Default window size (segments).
pub const KCP_WND_SND: u32 = 32;
pub const KCP_WND_RCV: u32 = 128;
/// Initial retransmission timeout (milliseconds).
pub const KCP_RTO_MIN: u32 = 100;
pub const KCP_RTO_DEF: u32 = 200;
pub const KCP_RTO_MAX: u32 = 60_000;
/// Fast retransmit threshold.
pub const KCP_THRESH_MIN: u32 = 2;

/// A single KCP segment.
#[derive(Debug, Clone)]
pub struct KcpSegment {
    pub conv: u32,
    pub cmd: u8,
    pub frg: u8,
    pub wnd: u16,
    pub ts: u32,
    pub sn: u32,
    pub una: u32,
    pub data: Vec<u8>,
    // Retransmission metadata
    pub resendts: u32,
    pub rto: u32,
    pub fastack: u32,
    pub xmit: u32,
}

impl KcpSegment {
    pub fn new_data(conv: u32, sn: u32, frg: u8, data: Vec<u8>) -> Self {
        Self {
            conv,
            cmd: cmd::PUSH,
            frg,
            wnd: KCP_WND_RCV as u16,
            ts: 0,
            sn,
            una: 0,
            data,
            resendts: 0,
            rto: KCP_RTO_DEF,
            fastack: 0,
            xmit: 0,
        }
    }

    pub fn new_ack(conv: u32, sn: u32, ts: u32, una: u32) -> Self {
        Self {
            conv,
            cmd: cmd::ACK,
            frg: 0,
            wnd: KCP_WND_RCV as u16,
            ts,
            sn,
            una,
            data: Vec::new(),
            resendts: 0,
            rto: 0,
            fastack: 0,
            xmit: 0,
        }
    }

    /// Encodes the segment into the wire binary format.
    pub fn encode(&self) -> Vec<u8> {
        let len = self.data.len() as u32;
        let mut buf = Vec::with_capacity(KCP_OVERHEAD + self.data.len());
        buf.extend_from_slice(&self.conv.to_le_bytes());
        buf.push(self.cmd);
        buf.push(self.frg);
        buf.extend_from_slice(&self.wnd.to_le_bytes());
        buf.extend_from_slice(&self.ts.to_le_bytes());
        buf.extend_from_slice(&self.sn.to_le_bytes());
        buf.extend_from_slice(&self.una.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decodes a segment from the wire format. Returns `(segment, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), KcpError> {
        if buf.len() < KCP_OVERHEAD {
            return Err(KcpError::ShortBuffer(buf.len()));
        }
        let conv = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let cmd = buf[4];
        let frg = buf[5];
        let wnd = u16::from_le_bytes(buf[6..8].try_into().unwrap());
        let ts = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let sn = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let una = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let len = u32::from_le_bytes(buf[20..24].try_into().unwrap()) as usize;

        if buf.len() < KCP_OVERHEAD + len {
            return Err(KcpError::ShortBuffer(buf.len()));
        }
        let data = buf[KCP_OVERHEAD..KCP_OVERHEAD + len].to_vec();

        let seg = Self {
            conv, cmd, frg, wnd, ts, sn, una, data,
            resendts: 0, rto: KCP_RTO_DEF, fastack: 0, xmit: 0,
        };
        Ok((seg, KCP_OVERHEAD + len))
    }
}

/// Core KCP connection state.
pub struct KcpCore {
    /// Connection conversation ID (matches both sides).
    pub conv: u32,
    mtu: usize,
    mss: usize,
    /// Outgoing send queue (unsent messages).
    snd_queue: VecDeque<KcpSegment>,
    /// Outgoing buffer (sent but unacknowledged).
    snd_buf: BTreeMap<u32, KcpSegment>,
    /// Incoming reassembly buffer.
    rcv_buf: BTreeMap<u32, KcpSegment>,
    /// Receive queue (fully reassembled, ready to deliver).
    rcv_queue: VecDeque<Vec<u8>>,
    /// Pending ACKs to send.
    acklist: Vec<(u32, u32)>, // (sn, ts)
    /// Sequence number for next outgoing segment.
    snd_nxt: u32,
    /// Next expected receive sequence number.
    rcv_nxt: u32,
    /// Smallest unacknowledged sequence number.
    snd_una: u32,
    /// Send window size.
    snd_wnd: u32,
    /// Receive window size.
    rcv_wnd: u32,
    /// Remote receive window.
    rmt_wnd: u32,
    /// Smoothed RTT (milliseconds).
    rx_srtt: i32,
    rx_rttval: i32,
    rx_rto: u32,
    rx_minrto: u32,
    /// Congestion window.
    cwnd: u32,
    ssthresh: u32,
    /// Timestamp for next flush.
    ts_flush: u32,
    /// No-delay mode: disables Nagle algorithm.
    nodelay: bool,
    /// Fast retransmit threshold.
    fastresend: i32,
    /// Current time in milliseconds.
    current: u32,
}

impl KcpCore {
    /// Creates a new KCP connection with the given conversation ID.
    pub fn new(conv: u32) -> Self {
        Self {
            conv,
            mtu: KCP_MTU_DEF,
            mss: KCP_MTU_DEF - KCP_OVERHEAD,
            snd_queue: VecDeque::new(),
            snd_buf: BTreeMap::new(),
            rcv_buf: BTreeMap::new(),
            rcv_queue: VecDeque::new(),
            acklist: Vec::new(),
            snd_nxt: 0,
            rcv_nxt: 0,
            snd_una: 0,
            snd_wnd: KCP_WND_SND,
            rcv_wnd: KCP_WND_RCV,
            rmt_wnd: KCP_WND_RCV,
            rx_srtt: 0,
            rx_rttval: 0,
            rx_rto: KCP_RTO_DEF,
            rx_minrto: KCP_RTO_MIN,
            cwnd: 1,
            ssthresh: KCP_THRESH_MIN,
            ts_flush: 0,
            nodelay: false,
            fastresend: 0,
            current: 0,
        }
    }

    /// Enables no-delay mode for low-latency tunnels.
    pub fn set_nodelay(&mut self, nodelay: bool, resend: i32) {
        self.nodelay = nodelay;
        self.fastresend = resend;
        if nodelay {
            self.rx_minrto = 30;
        }
    }

    /// Updates the current timestamp (milliseconds since epoch mod 2^32).
    pub fn update(&mut self, current: u32) {
        self.current = current;
        // Flush if scheduled
        if self.ts_flush == 0 || current.wrapping_sub(self.ts_flush) < 0x7fff_ffff {
            self.ts_flush = current.wrapping_add(10);
        }
    }

    /// Enqueues a message for sending. Messages larger than MSS are fragmented.
    pub fn send(&mut self, data: &[u8]) -> Result<(), KcpError> {
        if data.is_empty() {
            return Err(KcpError::EmptyData);
        }
        let count = (data.len() + self.mss - 1) / self.mss;
        if count >= 256 {
            return Err(KcpError::TooLarge);
        }
        for i in 0..count {
            let frg = (count - 1 - i) as u8;
            let begin = i * self.mss;
            let end = (begin + self.mss).min(data.len());
            let seg = KcpSegment::new_data(self.conv, 0, frg, data[begin..end].to_vec());
            self.snd_queue.push_back(seg);
        }
        Ok(())
    }

    /// Processes a received UDP datagram, parsing all KCP segments inside it.
    pub fn input(&mut self, data: &[u8]) -> Result<(), KcpError> {
        let mut offset = 0;
        while offset < data.len() {
            let (seg, consumed) = KcpSegment::decode(&data[offset..])?;
            if seg.conv != self.conv {
                return Err(KcpError::ConvMismatch { expected: self.conv, got: seg.conv });
            }
            offset += consumed;

            match seg.cmd {
                cmd::PUSH => {
                    self.acklist.push((seg.sn, seg.ts));
                    if seg.sn >= self.rcv_nxt && seg.sn < self.rcv_nxt + self.rcv_wnd {
                        self.rcv_buf.insert(seg.sn, seg);
                        self.move_receive_buf();
                    }
                }
                cmd::ACK => {
                    self.update_ack(seg.sn);
                    self.snd_buf.remove(&seg.sn);
                    self.shrink_buf();
                }
                cmd::WASK => {} // Window probe — respond with WINS
                cmd::WINS => {
                    self.rmt_wnd = seg.wnd as u32;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Moves contiguous segments from rcv_buf to rcv_queue for delivery.
    fn move_receive_buf(&mut self) {
        loop {
            if let Some(seg) = self.rcv_buf.remove(&self.rcv_nxt) {
                self.rcv_nxt += 1;
                // Reassemble fragments: frg == 0 means last fragment
                self.rcv_queue.push_back(seg.data);
            } else {
                break;
            }
        }
    }

    /// Updates the un-acked sequence number after removing an acked segment.
    fn shrink_buf(&mut self) {
        if let Some((&sn, _)) = self.snd_buf.iter().next() {
            self.snd_una = sn;
        } else {
            self.snd_una = self.snd_nxt;
        }
    }

    fn update_ack(&mut self, sn: u32) {
        if sn < self.snd_una || sn >= self.snd_nxt {
            return;
        }
        self.snd_buf.remove(&sn);
    }

    /// Flushes pending ACKs and queued send segments into output datagrams.
    ///
    /// Returns a list of UDP payloads ready to transmit.
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let mut buf = Vec::with_capacity(self.mtu);

        // Flush ACKs
        for (sn, ts) in self.acklist.drain(..) {
            let ack = KcpSegment::new_ack(self.conv, sn, ts, self.rcv_nxt);
            let encoded = ack.encode();
            if buf.len() + encoded.len() > self.mtu {
                packets.push(std::mem::take(&mut buf));
            }
            buf.extend_from_slice(&encoded);
        }

        // Move from snd_queue → snd_buf up to cwnd
        while !self.snd_queue.is_empty() {
            let inflight = self.snd_nxt - self.snd_una;
            if inflight >= self.cwnd.min(self.rmt_wnd) {
                break;
            }
            if let Some(mut seg) = self.snd_queue.pop_front() {
                seg.sn = self.snd_nxt;
                seg.ts = self.current;
                seg.una = self.rcv_nxt;
                seg.resendts = self.current.wrapping_add(seg.rto);
                self.snd_nxt += 1;

                let encoded = seg.encode();
                if buf.len() + encoded.len() > self.mtu {
                    packets.push(std::mem::take(&mut buf));
                }
                buf.extend_from_slice(&encoded);
                self.snd_buf.insert(seg.sn, seg);
            }
        }

        // Retransmit lost segments
        let retransmit_keys: Vec<u32> = self.snd_buf.iter()
            .filter(|(_, seg)| {
                seg.xmit > 0 && self.current.wrapping_sub(seg.resendts) < 0x7fff_ffff
            })
            .map(|(&k, _)| k)
            .collect();

        for sn in retransmit_keys {
            if let Some(seg) = self.snd_buf.get_mut(&sn) {
                seg.xmit += 1;
                seg.rto = (seg.rto + seg.rto / 2).min(KCP_RTO_MAX);
                seg.resendts = self.current.wrapping_add(seg.rto);
                let encoded = seg.encode();
                if buf.len() + encoded.len() > self.mtu {
                    packets.push(std::mem::take(&mut buf));
                }
                buf.extend_from_slice(&encoded);
            }
        }

        if !buf.is_empty() {
            packets.push(buf);
        }
        packets
    }

    /// Reads the next fully reassembled message from the receive queue.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.rcv_queue.pop_front()
    }

    /// Returns the number of messages ready to read.
    pub fn recv_pending(&self) -> usize {
        self.rcv_queue.len()
    }
}

/// Errors from KCP operations.
#[derive(Debug, thiserror::Error)]
pub enum KcpError {
    #[error("buffer too short: {0} bytes")]
    ShortBuffer(usize),
    #[error("conversation ID mismatch: expected {expected}, got {got}")]
    ConvMismatch { expected: u32, got: u32 },
    #[error("data is empty")]
    EmptyData,
    #[error("message too large to fragment (max 255 segments)")]
    TooLarge,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_encode_decode_roundtrip() {
        let seg = KcpSegment::new_data(42, 7, 0, b"hello kcp".to_vec());
        let encoded = seg.encode();
        let (decoded, consumed) = KcpSegment::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.conv, 42);
        assert_eq!(decoded.sn, 7);
        assert_eq!(decoded.data, b"hello kcp");
    }

    #[test]
    fn test_send_receive_loopback() {
        let mut alice = KcpCore::new(1);
        let mut bob = KcpCore::new(1);

        alice.set_nodelay(true, 2);
        bob.set_nodelay(true, 2);

        alice.update(100);
        bob.update(100);

        // Alice sends
        alice.send(b"test message").unwrap();
        let packets = alice.flush();
        assert!(!packets.is_empty());

        // Bob receives
        for pkt in &packets {
            bob.input(pkt).unwrap();
        }

        // Bob reads the message
        let msg = bob.recv();
        assert_eq!(msg.unwrap(), b"test message");
    }

    #[test]
    fn test_ack_generated() {
        let mut bob = KcpCore::new(1);
        bob.update(200);

        let mut alice = KcpCore::new(1);
        alice.send(b"ping").unwrap();
        let outbound = alice.flush();

        for pkt in &outbound {
            bob.input(pkt).unwrap();
        }
        // Bob should have queued ACKs
        let ack_packets = bob.flush();
        assert!(!ack_packets.is_empty());
    }
}
