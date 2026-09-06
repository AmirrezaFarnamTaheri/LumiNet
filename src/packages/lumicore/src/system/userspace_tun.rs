use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Represents a raw IP packet intercepted from the TUN interface.
#[derive(Clone, Debug)]
pub struct TunPacket {
    pub data: Vec<u8>,
}

/// Active userspace-TUN session evidence.
pub struct UserspaceSession {
    pub id: u64,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct SessionKey {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
}

#[derive(Clone, Copy, Debug)]
struct ParsedPacket {
    key: SessionKey,
    header_len: usize,
    total_len: usize,
    transport_checksum_offset: usize,
    udp_checksum_omitted: bool,
}

/// A bounded userspace packet scheduler used by the legacy Rust TUN simulation.
///
/// This owner is intentionally strict: malformed/fragmented packets are rejected,
/// sessions use the full IPv4 5-tuple, FIFO eviction is deterministic, and any
/// reflected packet has its IPv4 and transport checksums repaired.
pub struct UserspaceTunScheduler {
    rx_queue: mpsc::Receiver<TunPacket>,
    tx_queue: mpsc::Sender<TunPacket>,
    sessions: Arc<Mutex<HashMap<SessionKey, UserspaceSession>>>,
    session_order: VecDeque<SessionKey>,
    next_session_id: u64,
    max_sessions: usize,
}

impl UserspaceTunScheduler {
    pub fn new(
        rx: mpsc::Receiver<TunPacket>,
        tx: mpsc::Sender<TunPacket>,
        max_sessions: usize,
    ) -> Self {
        Self {
            rx_queue: rx,
            tx_queue: tx,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_order: VecDeque::new(),
            next_session_id: 1,
            max_sessions,
        }
    }

    pub async fn run_loop(&mut self) {
        while let Some(packet) = self.rx_queue.recv().await {
            if let Some(translated) = self.translate_packet(packet) {
                let _ = self.tx_queue.send(translated).await;
            }
        }
    }

    /// Reflects a valid unfragmented IPv4 TCP/UDP packet while maintaining
    /// bounded connection evidence. Invalid inputs are rejected without panic.
    pub fn translate_packet(&mut self, packet: TunPacket) -> Option<TunPacket> {
        let parsed = parse_ipv4_transport(&packet.data)?;

        if self.max_sessions == 0 {
            return None;
        }

        {
            let mut sessions = self.sessions.lock().ok()?;
            if !sessions.contains_key(&parsed.key) {
                while sessions.len() >= self.max_sessions {
                    let oldest = self.session_order.pop_front()?;
                    sessions.remove(&oldest);
                }

                let new_session = UserspaceSession {
                    id: self.next_session_id,
                    src_addr: IpAddr::V4(std::net::Ipv4Addr::from(parsed.key.src_ip)),
                    src_port: parsed.key.src_port,
                    dst_addr: IpAddr::V4(std::net::Ipv4Addr::from(parsed.key.dst_ip)),
                    dst_port: parsed.key.dst_port,
                };
                sessions.insert(parsed.key, new_session);
                self.session_order.push_back(parsed.key);
                self.next_session_id = self.next_session_id.saturating_add(1);
            }
        }

        let mut response = packet;
        response.data[12..16].copy_from_slice(&parsed.key.dst_ip);
        response.data[16..20].copy_from_slice(&parsed.key.src_ip);
        let transport = parsed.header_len;
        response.data[transport..transport + 2]
            .copy_from_slice(&parsed.key.dst_port.to_be_bytes());
        response.data[transport + 2..transport + 4]
            .copy_from_slice(&parsed.key.src_port.to_be_bytes());
        repair_checksums(&mut response.data, parsed)?;
        Some(response)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.lock().map(|sessions| sessions.len()).unwrap_or(0)
    }
}

fn parse_ipv4_transport(data: &[u8]) -> Option<ParsedPacket> {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return None;
    }

    let header_len = usize::from(data[0] & 0x0f) * 4;
    if header_len < 20 || header_len > data.len() {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if total_len < header_len || total_len > data.len() {
        return None;
    }

    let fragment = u16::from_be_bytes([data[6], data[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let protocol = data[9];
    let transport_len = total_len.checked_sub(header_len)?;
    let transport_checksum_offset;
    let udp_checksum_omitted;
    match protocol {
        6 => {
            if transport_len < 20 {
                return None;
            }
            let tcp_header_len = usize::from(data[header_len + 12] >> 4) * 4;
            if tcp_header_len < 20 || tcp_header_len > transport_len {
                return None;
            }
            transport_checksum_offset = header_len + 16;
            udp_checksum_omitted = false;
        }
        17 => {
            if transport_len < 8 {
                return None;
            }
            let udp_len = usize::from(u16::from_be_bytes([
                data[header_len + 4],
                data[header_len + 5],
            ]));
            if udp_len < 8 || udp_len != transport_len {
                return None;
            }
            transport_checksum_offset = header_len + 6;
            udp_checksum_omitted = data[transport_checksum_offset] == 0
                && data[transport_checksum_offset + 1] == 0;
        }
        _ => return None,
    }

    Some(ParsedPacket {
        key: SessionKey {
            src_ip: data[12..16].try_into().ok()?,
            dst_ip: data[16..20].try_into().ok()?,
            src_port: u16::from_be_bytes([data[header_len], data[header_len + 1]]),
            dst_port: u16::from_be_bytes([data[header_len + 2], data[header_len + 3]]),
            protocol,
        },
        header_len,
        total_len,
        transport_checksum_offset,
        udp_checksum_omitted,
    })
}

fn repair_checksums(data: &mut [u8], parsed: ParsedPacket) -> Option<()> {
    data[10] = 0;
    data[11] = 0;
    let header_checksum = internet_checksum(&data[..parsed.header_len]);
    data[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    if parsed.udp_checksum_omitted {
        return Some(());
    }

    data[parsed.transport_checksum_offset] = 0;
    data[parsed.transport_checksum_offset + 1] = 0;
    let transport_len = parsed.total_len.checked_sub(parsed.header_len)?;
    let transport_len_u16 = u16::try_from(transport_len).ok()?;
    let mut pseudo = Vec::with_capacity(12 + transport_len);
    pseudo.extend_from_slice(&data[12..20]);
    pseudo.push(0);
    pseudo.push(parsed.key.protocol);
    pseudo.extend_from_slice(&transport_len_u16.to_be_bytes());
    pseudo.extend_from_slice(&data[parsed.header_len..parsed.total_len]);
    let mut checksum = internet_checksum(&pseudo);
    if parsed.key.protocol == 17 && checksum == 0 {
        checksum = 0xffff;
    }
    data[parsed.transport_checksum_offset..parsed.transport_checksum_offset + 2]
        .copy_from_slice(&checksum.to_be_bytes());
    Some(())
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let [last] = chunks.remainder() {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scheduler(max_sessions: usize) -> UserspaceTunScheduler {
        let (_tx1, rx1) = mpsc::channel(10);
        let (tx2, _rx2) = mpsc::channel(10);
        UserspaceTunScheduler::new(rx1, tx2, max_sessions)
    }

    fn tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut data = vec![0u8; 40];
        data[0] = 0x45;
        data[2..4].copy_from_slice(&40u16.to_be_bytes());
        data[8] = 64;
        data[9] = 6;
        data[12..16].copy_from_slice(&src);
        data[16..20].copy_from_slice(&dst);
        data[20..22].copy_from_slice(&src_port.to_be_bytes());
        data[22..24].copy_from_slice(&dst_port.to_be_bytes());
        data[32] = 0x50;
        data
    }

    #[test]
    fn rejects_minimum_ipv4_without_transport_header_without_panicking() {
        let mut s = scheduler(2);
        let mut data = vec![0u8; 20];
        data[0] = 0x45;
        data[2..4].copy_from_slice(&20u16.to_be_bytes());
        data[9] = 6;
        assert!(s.translate_packet(TunPacket { data }).is_none());
    }

    #[test]
    fn rejects_invalid_ihl_total_length_and_fragmentation() {
        let mut s = scheduler(2);
        let mut short_ihl = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80);
        short_ihl[0] = 0x44;
        assert!(s.translate_packet(TunPacket { data: short_ihl }).is_none());

        let mut oversized = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80);
        oversized[2..4].copy_from_slice(&41u16.to_be_bytes());
        assert!(s.translate_packet(TunPacket { data: oversized }).is_none());

        let mut fragment = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80);
        fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(s.translate_packet(TunPacket { data: fragment }).is_none());
    }

    #[test]
    fn respects_ipv4_options_when_locating_ports() {
        let mut s = scheduler(2);
        let mut data = vec![0u8; 44];
        data[0] = 0x46;
        data[2..4].copy_from_slice(&44u16.to_be_bytes());
        data[8] = 64;
        data[9] = 6;
        data[12..16].copy_from_slice(&[10, 0, 0, 1]);
        data[16..20].copy_from_slice(&[10, 0, 0, 2]);
        data[24..26].copy_from_slice(&1234u16.to_be_bytes());
        data[26..28].copy_from_slice(&80u16.to_be_bytes());
        data[36] = 0x50;
        let reply = s.translate_packet(TunPacket { data }).unwrap();
        assert_eq!(u16::from_be_bytes([reply.data[24], reply.data[25]]), 80);
        assert_eq!(u16::from_be_bytes([reply.data[26], reply.data[27]]), 1234);
    }

    #[test]
    fn session_identity_uses_full_five_tuple_and_fifo_eviction() {
        let mut s = scheduler(2);
        for (src, port) in [([10, 0, 0, 1], 1000), ([10, 0, 0, 2], 1000), ([10, 0, 0, 3], 1000)] {
            let packet = tcp_packet(src, [10, 0, 0, 9], port, 443);
            assert!(s.translate_packet(TunPacket { data: packet }).is_some());
        }
        assert_eq!(s.session_count(), 2);
        let sessions = s.sessions.lock().unwrap();
        assert!(!sessions.keys().any(|key| key.src_ip == [10, 0, 0, 1]));
        assert!(sessions.keys().any(|key| key.src_ip == [10, 0, 0, 2]));
        assert!(sessions.keys().any(|key| key.src_ip == [10, 0, 0, 3]));
    }

    #[test]
    fn reflected_packet_repairs_ipv4_and_tcp_checksums() {
        let mut s = scheduler(2);
        let packet = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80);
        let reply = s.translate_packet(TunPacket { data: packet }).unwrap();
        assert_eq!(&reply.data[12..16], &[10, 0, 0, 2]);
        assert_eq!(&reply.data[16..20], &[10, 0, 0, 1]);
        assert_eq!(internet_checksum(&reply.data[..20]), 0);

        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&reply.data[12..20]);
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&20u16.to_be_bytes());
        pseudo.extend_from_slice(&reply.data[20..40]);
        assert_eq!(internet_checksum(&pseudo), 0);
    }
}
