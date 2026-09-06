use rand::{thread_rng, RngCore};
use std::net::Ipv4Addr;

/// PaqetEngine implements userspace raw TCP handshake injection (paqet mode).
/// It bypasses the kernel TCP stack to send custom SYN and PSH-ACK packets,
/// and parses returning SYN-ACK payloads.
pub struct PaqetEngine {
    pub mss: u16,
    pub window_scale: u8,
}

impl PaqetEngine {
    /// Creates a new PaqetEngine instance.
    pub fn new(mss: u16, window_scale: u8) -> Self {
        Self { mss, window_scale }
    }

    /// Constructs a raw TCP SYN packet with customized TCP option fields.
    pub fn build_syn_packet(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
    ) -> Vec<u8> {
        // Options: MSS (4 bytes), NOP (1 byte), Window Scale (3 bytes), SACK Permitted (2 bytes)
        // Total options length: 12 bytes. TCP Header Length = 20 + 12 = 32 bytes (Data Offset = 8).
        let ip_len = 20 + 32;
        let mut packet = vec![0u8; ip_len];

        // 1. IP Header
        packet[0] = 0x45; // Version 4, Header Length 5
        packet[1] = 0x00; // Type of service
        packet[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes()); // Total length

        let mut id_bytes = [0u8; 2];
        thread_rng().fill_bytes(&mut id_bytes);
        packet[4..6].copy_from_slice(&id_bytes);

        packet[6..8].copy_from_slice(&[0x40, 0x00]); // Don't fragment
        packet[8] = 64; // TTL
        packet[9] = 0x06; // Protocol: TCP
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());

        // Calculate IP checksum
        let ip_checksum = self.calculate_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        // 2. TCP Header
        let tcp_offset = 20;
        packet[tcp_offset..tcp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
        packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
        packet[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&seq.to_be_bytes());
        packet[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&[0x00; 4]); // ACK is 0 in SYN

        packet[tcp_offset + 12] = 0x80; // Data Offset = 8 (32 bytes header)
        packet[tcp_offset + 13] = 0x02; // Flags: SYN
        packet[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&[0xfa, 0xf0]); // Window size

        // TCP Options:
        // Option 1: MSS (Kind=2, Length=4, Value=mss)
        packet[tcp_offset + 20] = 2;
        packet[tcp_offset + 21] = 4;
        packet[tcp_offset + 22..tcp_offset + 24].copy_from_slice(&self.mss.to_be_bytes());

        // Option 2: NOP (Kind=1)
        packet[tcp_offset + 24] = 1;

        // Option 3: Window Scale (Kind=3, Length=3, Value=scale)
        packet[tcp_offset + 25] = 3;
        packet[tcp_offset + 26] = 3;
        packet[tcp_offset + 27] = self.window_scale;

        // Option 4: SACK Permitted (Kind=4, Length=2)
        packet[tcp_offset + 28] = 4;
        packet[tcp_offset + 29] = 2;

        // Option 5: End of Options (Kind=0, Length=1, Pad to 32 bytes)
        packet[tcp_offset + 30] = 0;
        packet[tcp_offset + 31] = 0;

        // Calculate TCP checksum
        let tcp_checksum = self.calculate_tcp_checksum(&packet, src_ip, dst_ip);
        packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

        packet
    }

    /// Parses returned SYN-ACK packet and extracts Seq and Ack numbers.
    pub fn parse_syn_ack(&self, packet: &[u8]) -> Option<(u32, u32)> {
        if packet.len() < 40 {
            return None; // Packet too short
        }

        // Validate IP header length and protocol
        let ip_version = packet[0] >> 4;
        let ip_header_len = (packet[0] & 0x0f) as usize * 4;
        let protocol = packet[9];

        if ip_version != 4 || protocol != 0x06 || packet.len() < ip_header_len + 20 {
            return None;
        }

        let tcp_offset = ip_header_len;
        let flags = packet[tcp_offset + 13];

        // Verify SYN-ACK flags (0x12: ACK=0x10, SYN=0x02)
        if (flags & 0x12) == 0x12 {
            let seq = u32::from_be_bytes([
                packet[tcp_offset + 4],
                packet[tcp_offset + 5],
                packet[tcp_offset + 6],
                packet[tcp_offset + 7],
            ]);
            let ack = u32::from_be_bytes([
                packet[tcp_offset + 8],
                packet[tcp_offset + 9],
                packet[tcp_offset + 10],
                packet[tcp_offset + 11],
            ]);
            Some((seq, ack))
        } else {
            None
        }
    }

    fn calculate_checksum(&self, data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;
        while i < data.len() - 1 {
            let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
            sum += word;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while sum >> 16 > 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn calculate_tcp_checksum(&self, packet: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> u16 {
        let tcp_len = packet.len() - 20;
        let mut pseudo_header = Vec::new();
        pseudo_header.extend_from_slice(&src_ip.octets());
        pseudo_header.extend_from_slice(&dst_ip.octets());
        pseudo_header.push(0x00);
        pseudo_header.push(0x06);
        pseudo_header.extend_from_slice(&(tcp_len as u16).to_be_bytes());
        pseudo_header.extend_from_slice(&packet[20..]);

        self.calculate_checksum(&pseudo_header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_syn_packet() {
        let engine = PaqetEngine::new(1460, 7);
        let src_ip = Ipv4Addr::new(192, 168, 1, 50);
        let dst_ip = Ipv4Addr::new(1, 1, 1, 1);
        let packet = engine.build_syn_packet(src_ip, dst_ip, 54321, 80, 1000);

        assert_eq!(packet[0], 0x45); // IPv4
        assert_eq!(packet[9], 0x06); // TCP protocol
        assert_eq!(packet[33], 0x02); // TCP Flags: SYN

        // Options check
        assert_eq!(packet[40], 2); // MSS option kind
        assert_eq!(packet[41], 4); // MSS option len
        let mss_val = u16::from_be_bytes([packet[42], packet[43]]);
        assert_eq!(mss_val, 1460);
    }

    #[test]
    fn test_parse_syn_ack() {
        let engine = PaqetEngine::new(1460, 7);

        // Construct a mock IPv4 SYN-ACK response
        let mut response = vec![0u8; 40];
        response[0] = 0x45;
        response[9] = 0x06; // TCP

        let tcp_offset = 20;
        response[tcp_offset + 13] = 0x12; // SYN-ACK flags
        response[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&5000u32.to_be_bytes()); // Seq
        response[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&1001u32.to_be_bytes()); // Ack

        let parsed = engine.parse_syn_ack(&response);
        assert!(parsed.is_some());
        let (seq, ack) = parsed.unwrap();
        assert_eq!(seq, 5000);
        assert_eq!(ack, 1001);
    }
}
