use rand::{thread_rng, RngCore};
use std::net::Ipv4Addr;

/// Evasion distractor packet type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DistractorType {
    SmallTtl,
    BadChecksum,
    CorruptAck,
    CorruptFlags,
}

/// EvEvasionConfig represents the IDS/IPS evasion parameters.
#[derive(Debug, Clone)]
pub struct EvEvasionConfig {
    pub enabled: bool,
    pub distractor_type: DistractorType,
    pub target_ttl: u8,
}

impl Default for EvEvasionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            distractor_type: DistractorType::SmallTtl,
            target_ttl: 2,
        }
    }
}

/// EvEvasionEngine constructs raw IPv4 TCP distractor packets to desynchronize stateful DPI/IDS.
pub struct EvEvasionEngine {
    pub config: EvEvasionConfig,
}

#[derive(Debug, Clone, Copy)]
pub struct TcpFlow {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
}

impl EvEvasionEngine {
    pub fn new(config: EvEvasionConfig) -> Self {
        Self { config }
    }

    /// Crafts an IPv4 packet header wrapping a TCP segment with customizable evasion features.
    pub fn craft_distractor(&self, flow: TcpFlow, payload: &[u8]) -> Vec<u8> {
        let TcpFlow {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
            ack,
        } = flow;
        let ip_len = 20 + 20 + payload.len();
        let mut packet = vec![0u8; ip_len];

        // 1. IP Header
        packet[0] = 0x45; // Version 4, Header Length 5 (20 bytes)
        packet[1] = 0x00; // DSCP/ECN
        packet[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes()); // Total length

        let mut id_bytes = [0u8; 2];
        thread_rng().fill_bytes(&mut id_bytes);
        packet[4..6].copy_from_slice(&id_bytes); // Identification

        packet[6..8].copy_from_slice(&[0x40, 0x00]); // Flags: Don't Fragment

        // Apply Small TTL Evasion if configured
        let ttl = match self.config.distractor_type {
            DistractorType::SmallTtl => self.config.target_ttl,
            _ => 64,
        };
        packet[8] = ttl; // Time to Live
        packet[9] = 0x06; // Protocol: TCP

        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());

        // Calculate IP Checksum (standard 1's complement)
        let checksum = self.calculate_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());

        // 2. TCP Header
        let tcp_offset = 20;
        packet[tcp_offset..tcp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
        packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
        packet[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&seq.to_be_bytes());
        packet[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&ack.to_be_bytes());

        packet[tcp_offset + 12] = 0x50; // Data Offset (5 = 20 bytes)

        // Set TCP flags including corrupt flags if configured
        let flags = match self.config.distractor_type {
            DistractorType::CorruptFlags => 0xff, // Invalid flags combination to confuse parser
            DistractorType::CorruptAck => 0x10 | 0x04, // ACK + RST (normally invalid together)
            _ => 0x18,                            // PUSH + ACK
        };
        packet[tcp_offset + 13] = flags;
        packet[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&[0xfa, 0xf0]); // Window size

        // Copy payload
        packet[40..].copy_from_slice(payload);

        // Apply Bad Checksum Evasion if configured
        let tcp_checksum = match self.config.distractor_type {
            DistractorType::BadChecksum => 0xdead, // Inject bad checksum so endpoints discard it
            _ => self.calculate_tcp_checksum(&packet, src_ip, dst_ip),
        };
        packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

        packet
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
        pseudo_header.push(0x00); // Reserved byte
        pseudo_header.push(0x06); // Protocol: TCP
        pseudo_header.extend_from_slice(&(tcp_len as u16).to_be_bytes());
        pseudo_header.extend_from_slice(&packet[20..]);

        self.calculate_checksum(&pseudo_header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_craft_distractor_packet() {
        let config = EvEvasionConfig {
            enabled: true,
            distractor_type: DistractorType::SmallTtl,
            target_ttl: 3,
        };
        let engine = EvEvasionEngine::new(config);

        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);
        let packet = engine.craft_distractor(
            TcpFlow {
                src_ip,
                dst_ip,
                src_port: 12345,
                dst_port: 443,
                seq: 100,
                ack: 200,
            },
            b"fake-payload",
        );

        assert_eq!(packet[0], 0x45); // IPv4 version
        assert_eq!(packet[8], 3); // Small TTL set correctly
    }

    #[test]
    fn test_bad_checksum_evasion() {
        let config = EvEvasionConfig {
            enabled: true,
            distractor_type: DistractorType::BadChecksum,
            target_ttl: 64,
        };
        let engine = EvEvasionEngine::new(config);

        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);
        let packet = engine.craft_distractor(
            TcpFlow {
                src_ip,
                dst_ip,
                src_port: 12345,
                dst_port: 443,
                seq: 100,
                ack: 200,
            },
            b"payload",
        );

        // TCP checksum should be set to 0xdead
        let tcp_checksum = u16::from_be_bytes([packet[36], packet[37]]);
        assert_eq!(tcp_checksum, 0xdead);
    }
}
