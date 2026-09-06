/// Internet checksum calculation (RFC 1071 / standard ones' complement sum).
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i < data.len() - 1 {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < data.len() {
        let word = u16::from_be_bytes([data[i], 0]);
        sum += word as u32;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Debug, Clone)]
pub struct IPv4Header {
    pub tos: u8,
    pub id: u16,
    pub flags_fragment: u16, // flags (3 bits) + fragment offset (13 bits)
    pub ttl: u8,
    pub protocol: u8,
    pub src_ip: [u8; 4],
    pub dest_ip: [u8; 4],
}

impl IPv4Header {
    pub fn new(protocol: u8, src_ip: [u8; 4], dest_ip: [u8; 4]) -> Self {
        Self {
            tos: 0,
            id: 54321,
            flags_fragment: 0x4000, // Don't Fragment set by default
            ttl: 64,
            protocol,
            src_ip,
            dest_ip,
        }
    }

    pub fn serialize(&self, payload_len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        buf[0] = 0x45; // Version: 4, IHL: 5 (20 bytes)
        buf[1] = self.tos;
        let total_len = (20 + payload_len) as u16;
        buf[2..4].copy_from_slice(&total_len.to_be_bytes());
        buf[4..6].copy_from_slice(&self.id.to_be_bytes());
        buf[6..8].copy_from_slice(&self.flags_fragment.to_be_bytes());
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        // Checksum at 10..12 is initially 0
        buf[12..16].copy_from_slice(&self.src_ip);
        buf[16..20].copy_from_slice(&self.dest_ip);

        let checksum = internet_checksum(&buf);
        buf[10..12].copy_from_slice(&checksum.to_be_bytes());
        buf
    }
}

#[derive(Debug, Clone)]
pub struct TCPHeader {
    pub src_port: u16,
    pub dest_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub flags: u8, // e.g. SYN=0x02, ACK=0x10, RST=0x04
    pub window_size: u16,
    pub urgent_ptr: u16,
    pub options: Vec<u8>,
}

impl TCPHeader {
    pub fn new(src_port: u16, dest_port: u16) -> Self {
        Self {
            src_port,
            dest_port,
            seq_num: 0,
            ack_num: 0,
            flags: 0x02, // SYN
            window_size: 64240,
            urgent_ptr: 0,
            options: Vec::new(),
        }
    }

    pub fn serialize(&self, src_ip: &[u8; 4], dest_ip: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let options_len = self.options.len();
        // Pad options to a multiple of 4 bytes
        let padded_options_len = (options_len + 3) & !3;
        let header_len = 20 + padded_options_len;
        let mut buf = vec![0u8; header_len];

        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dest_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack_num.to_be_bytes());

        let data_offset = (header_len / 4) as u8;
        buf[12] = (data_offset << 4) & 0xF0;
        buf[13] = self.flags;
        buf[14..16].copy_from_slice(&self.window_size.to_be_bytes());
        // Checksum at 16..18 is initially 0
        buf[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());

        // Copy options and pad with zeros if necessary
        if options_len > 0 {
            buf[20..20 + options_len].copy_from_slice(&self.options);
        }

        // Pseudo header
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(src_ip);
        pseudo.extend_from_slice(dest_ip);
        pseudo.push(0x00);
        pseudo.push(0x06); // Protocol: TCP (6)
        let tcp_len = (header_len + payload.len()) as u16;
        pseudo.extend_from_slice(&tcp_len.to_be_bytes());

        // Combine pseudo-header, TCP header, and payload
        let mut data_to_checksum = pseudo;
        data_to_checksum.extend_from_slice(&buf);
        data_to_checksum.extend_from_slice(payload);

        let checksum = internet_checksum(&data_to_checksum);
        buf[16..18].copy_from_slice(&checksum.to_be_bytes());
        buf
    }
}

#[derive(Debug, Clone)]
pub struct UDPHeader {
    pub src_port: u16,
    pub dest_port: u16,
}

impl UDPHeader {
    pub fn new(src_port: u16, dest_port: u16) -> Self {
        Self {
            src_port,
            dest_port,
        }
    }

    pub fn serialize(&self, src_ip: &[u8; 4], dest_ip: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 8];
        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dest_port.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        buf[4..6].copy_from_slice(&udp_len.to_be_bytes());
        // Checksum at 6..8 is initially 0

        // Pseudo header
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(src_ip);
        pseudo.extend_from_slice(dest_ip);
        pseudo.push(0x00);
        pseudo.push(0x11); // Protocol: UDP (17)
        pseudo.extend_from_slice(&udp_len.to_be_bytes());

        let mut data_to_checksum = pseudo;
        data_to_checksum.extend_from_slice(&buf);
        data_to_checksum.extend_from_slice(payload);

        let checksum = internet_checksum(&data_to_checksum);
        let final_checksum = if checksum == 0 { 0xffff } else { checksum };
        buf[6..8].copy_from_slice(&final_checksum.to_be_bytes());
        buf
    }
}

#[derive(Debug, Clone)]
pub struct ICMPHeader {
    pub icmp_type: u8, // e.g. 8 for Echo Request
    pub icmp_code: u8,
    pub identifier: u16,
    pub sequence: u16,
}

impl ICMPHeader {
    pub fn new(icmp_type: u8, icmp_code: u8, identifier: u16, sequence: u16) -> Self {
        Self {
            icmp_type,
            icmp_code,
            identifier,
            sequence,
        }
    }

    pub fn serialize(&self, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 8];
        buf[0] = self.icmp_type;
        buf[1] = self.icmp_code;
        // Checksum at 2..4 is initially 0
        buf[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        buf[6..8].copy_from_slice(&self.sequence.to_be_bytes());

        let mut data_to_checksum = buf.clone();
        data_to_checksum.extend_from_slice(payload);

        let checksum = internet_checksum(&data_to_checksum);
        buf[2..4].copy_from_slice(&checksum.to_be_bytes());
        buf
    }
}

pub struct PacketCrafting {
    pub active: bool,
}

impl Default for PacketCrafting {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketCrafting {
    pub fn new() -> Self {
        PacketCrafting { active: true }
    }

    /// Craft a raw TCP SYN packet with optional TCP header options.
    pub fn craft_tcp_syn(
        &self,
        src_ip: [u8; 4],
        dest_ip: [u8; 4],
        src_port: u16,
        dest_port: u16,
        options: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = TCPHeader::new(src_port, dest_port);
        tcp.options = options.to_vec();
        let ip = IPv4Header::new(6, src_ip, dest_ip); // 6 = TCP
        let serialized_tcp = tcp.serialize(&src_ip, &dest_ip, payload);
        let mut packet = ip.serialize(serialized_tcp.len() + payload.len());
        packet.extend_from_slice(&serialized_tcp);
        packet.extend_from_slice(payload);
        packet
    }

    /// Craft a raw UDP packet.
    pub fn craft_udp(
        &self,
        src_ip: [u8; 4],
        dest_ip: [u8; 4],
        src_port: u16,
        dest_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp = UDPHeader::new(src_port, dest_port);
        let ip = IPv4Header::new(17, src_ip, dest_ip); // 17 = UDP
        let serialized_udp = udp.serialize(&src_ip, &dest_ip, payload);
        let mut packet = ip.serialize(serialized_udp.len() + payload.len());
        packet.extend_from_slice(&serialized_udp);
        packet.extend_from_slice(payload);
        packet
    }

    /// Craft a raw ICMP Echo Request packet.
    pub fn craft_icmp_echo(
        &self,
        src_ip: [u8; 4],
        dest_ip: [u8; 4],
        identifier: u16,
        sequence: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let icmp = ICMPHeader::new(8, 0, identifier, sequence); // Type 8 Code 0
        let ip = IPv4Header::new(1, src_ip, dest_ip); // 1 = ICMP
        let serialized_icmp = icmp.serialize(payload);
        let mut packet = ip.serialize(serialized_icmp.len() + payload.len());
        packet.extend_from_slice(&serialized_icmp);
        packet.extend_from_slice(payload);
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        let data = vec![
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x7f, 0x00,
            0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        ];
        let cksum = internet_checksum(&data);
        assert_eq!(cksum, 27290);
    }

    #[test]
    fn test_craft_tcp_syn() {
        let crafter = PacketCrafting::new();
        let packet = crafter.craft_tcp_syn([127, 0, 0, 1], [127, 0, 0, 1], 1234, 80, &[], b"hello");
        assert!(packet.len() > 40);
        assert_eq!(packet[0], 0x45); // IPv4 version & IHL
        assert_eq!(packet[9], 6); // Protocol: TCP
    }

    #[test]
    fn test_craft_udp() {
        let crafter = PacketCrafting::new();
        let packet = crafter.craft_udp([127, 0, 0, 1], [127, 0, 0, 1], 1234, 80, b"hello");
        assert!(packet.len() > 28);
        assert_eq!(packet[9], 17); // Protocol: UDP
    }
}
