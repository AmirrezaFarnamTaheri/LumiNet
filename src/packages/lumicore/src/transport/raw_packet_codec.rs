//! Raw Packet Evasion Codec & Wire Protocol
//!
//! Ported and unified from `paqet-master`.
//! Provides raw TCP packet crafting, IPv4/IPv6 pseudo-header checksum computation,
//! TCP flag bitfield encoding/decoding, KCP transport profiles, and multiplexed tunnel framing.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Magic identifier byte for raw packet framing ('P' = 0x50).
pub const RAW_PACKET_MAGIC: u8 = 0x50;

/// Current wire protocol version.
pub const RAW_PACKET_VERSION: u8 = 0x01;

/// Protocol message types.
pub const MSG_PING: u8 = 0x01;
pub const MSG_PONG: u8 = 0x02;
pub const MSG_TCPF: u8 = 0x03;
pub const MSG_TCP: u8 = 0x04;
pub const MSG_UDP: u8 = 0x05;

pub const HEADER_LEN: usize = 5;
pub const MAX_HOST_LEN: usize = 253;
pub const MAX_TCPF_COUNT: usize = 64;
pub const MAX_BODY_LEN: usize = 4096;

pub const FLAG_FIN: u16 = 1 << 0;
pub const FLAG_SYN: u16 = 1 << 1;
pub const FLAG_RST: u16 = 1 << 2;
pub const FLAG_PSH: u16 = 1 << 3;
pub const FLAG_ACK: u16 = 1 << 4;
pub const FLAG_URG: u16 = 1 << 5;
pub const FLAG_ECE: u16 = 1 << 6;
pub const FLAG_CWR: u16 = 1 << 7;
pub const FLAG_NS: u16 = 1 << 8;

/// Structured TCP flags combination for crafted evasion bursts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RawTcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub ns: bool,
}

impl RawTcpFlags {
    /// Encodes TCP flags into wire 16-bit integer bitfield.
    pub fn encode(&self) -> u16 {
        let mut v = 0u16;
        if self.fin { v |= FLAG_FIN; }
        if self.syn { v |= FLAG_SYN; }
        if self.rst { v |= FLAG_RST; }
        if self.psh { v |= FLAG_PSH; }
        if self.ack { v |= FLAG_ACK; }
        if self.urg { v |= FLAG_URG; }
        if self.ece { v |= FLAG_ECE; }
        if self.cwr { v |= FLAG_CWR; }
        if self.ns { v |= FLAG_NS; }
        v
    }

    /// Decodes 16-bit wire bitfield into structured TCP flags.
    pub fn decode(val: u16) -> Self {
        Self {
            fin: (val & FLAG_FIN) != 0,
            syn: (val & FLAG_SYN) != 0,
            rst: (val & FLAG_RST) != 0,
            psh: (val & FLAG_PSH) != 0,
            ack: (val & FLAG_ACK) != 0,
            urg: (val & FLAG_URG) != 0,
            ece: (val & FLAG_ECE) != 0,
            cwr: (val & FLAG_CWR) != 0,
            ns: (val & FLAG_NS) != 0,
        }
    }

    /// Parses a string representation like "PA", "SA", "FA", "FSRPAUECN".
    pub fn parse_str(s: &str) -> Result<Self, RawPacketError> {
        let mut flags = Self::default();
        for ch in s.chars() {
            match ch {
                'F' | 'f' => flags.fin = true,
                'S' | 's' => flags.syn = true,
                'R' | 'r' => flags.rst = true,
                'P' | 'p' => flags.psh = true,
                'A' | 'a' => flags.ack = true,
                'U' | 'u' => flags.urg = true,
                'E' | 'e' => flags.ece = true,
                'C' | 'c' => flags.cwr = true,
                'N' | 'n' => flags.ns = true,
                other => return Err(RawPacketError::InvalidFlagChar(other)),
            }
        }
        Ok(flags)
    }

    /// Formats flags into canonical string representation.
    pub fn to_flag_str(&self) -> String {
        let mut s = String::new();
        if self.fin { s.push('F'); }
        if self.syn { s.push('S'); }
        if self.rst { s.push('R'); }
        if self.psh { s.push('P'); }
        if self.ack { s.push('A'); }
        if self.urg { s.push('U'); }
        if self.ece { s.push('E'); }
        if self.cwr { s.push('C'); }
        if self.ns { s.push('N'); }
        s
    }
}

/// Target endpoint address for proxied connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetEndpoint {
    pub host: String,
    pub port: u16,
}

impl TargetEndpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

/// High-level messages transported over the raw packet channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawPacketMessage {
    Ping,
    Pong,
    Tcpf(Vec<RawTcpFlags>),
    Tcp(TargetEndpoint),
    Udp(TargetEndpoint),
}

/// Errors occurring during packet framing and processing.
#[derive(Debug, PartialEq, Eq)]
pub enum RawPacketError {
    BadMagic(u8),
    UnsupportedVersion(u8),
    UnknownType(u8),
    HostTooLong(usize),
    TcpfCountExceeded(usize),
    BodyTooLong(usize),
    BufferTooShort,
    InvalidFlagChar(char),
    MalformedAddress,
    HeaderTruncated,
}

impl fmt::Display for RawPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic(m) => write!(f, "Invalid magic byte: 0x{:02x}", m),
            Self::UnsupportedVersion(v) => write!(f, "Unsupported version: {}", v),
            Self::UnknownType(t) => write!(f, "Unknown message type: 0x{:02x}", t),
            Self::HostTooLong(len) => write!(f, "Host length {} exceeds maximum {}", len, MAX_HOST_LEN),
            Self::TcpfCountExceeded(c) => write!(f, "TCPF count {} exceeds maximum {}", c, MAX_TCPF_COUNT),
            Self::BodyTooLong(len) => write!(f, "Body length {} exceeds maximum {}", len, MAX_BODY_LEN),
            Self::BufferTooShort => write!(f, "Buffer too short for parsing"),
            Self::InvalidFlagChar(c) => write!(f, "Invalid TCP flag character: '{}'", c),
            Self::MalformedAddress => write!(f, "Malformed address body"),
            Self::HeaderTruncated => write!(f, "Header truncated"),
        }
    }
}

impl std::error::Error for RawPacketError {}

/// Primary codec for encoding and decoding raw packet protocol frames.
pub struct RawPacketCodec;

impl RawPacketCodec {
    /// Encodes a message into a wire byte vector.
    pub fn encode(msg: &RawPacketMessage) -> Result<Vec<u8>, RawPacketError> {
        let mut body = Vec::with_capacity(64);
        let msg_type = match msg {
            RawPacketMessage::Ping => MSG_PING,
            RawPacketMessage::Pong => MSG_PONG,
            RawPacketMessage::Tcp(target) => {
                let host_bytes = target.host.as_bytes();
                if host_bytes.len() > MAX_HOST_LEN {
                    return Err(RawPacketError::HostTooLong(host_bytes.len()));
                }
                body.push(host_bytes.len() as u8);
                body.extend_from_slice(host_bytes);
                body.extend_from_slice(&target.port.to_be_bytes());
                MSG_TCP
            }
            RawPacketMessage::Udp(target) => {
                let host_bytes = target.host.as_bytes();
                if host_bytes.len() > MAX_HOST_LEN {
                    return Err(RawPacketError::HostTooLong(host_bytes.len()));
                }
                body.push(host_bytes.len() as u8);
                body.extend_from_slice(host_bytes);
                body.extend_from_slice(&target.port.to_be_bytes());
                MSG_UDP
            }
            RawPacketMessage::Tcpf(flags) => {
                if flags.len() > MAX_TCPF_COUNT {
                    return Err(RawPacketError::TcpfCountExceeded(flags.len()));
                }
                body.push(flags.len() as u8);
                for f in flags {
                    body.extend_from_slice(&f.encode().to_be_bytes());
                }
                MSG_TCPF
            }
        };

        if body.len() > MAX_BODY_LEN {
            return Err(RawPacketError::BodyTooLong(body.len()));
        }

        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.push(RAW_PACKET_MAGIC);
        out.push(RAW_PACKET_VERSION);
        out.push(msg_type);
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decodes a message from wire bytes. Returns the message and consumed byte length.
    pub fn decode(buf: &[u8]) -> Result<(RawPacketMessage, usize), RawPacketError> {
        if buf.len() < HEADER_LEN {
            return Err(RawPacketError::BufferTooShort);
        }
        if buf[0] != RAW_PACKET_MAGIC {
            return Err(RawPacketError::BadMagic(buf[0]));
        }
        if buf[1] != RAW_PACKET_VERSION {
            return Err(RawPacketError::UnsupportedVersion(buf[1]));
        }

        let msg_type = buf[2];
        let body_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        let total_len = HEADER_LEN + body_len;

        if buf.len() < total_len {
            return Err(RawPacketError::BufferTooShort);
        }

        let body = &buf[HEADER_LEN..total_len];
        let msg = match msg_type {
            MSG_PING => RawPacketMessage::Ping,
            MSG_PONG => RawPacketMessage::Pong,
            MSG_TCP | MSG_UDP => {
                if body.len() < 3 {
                    return Err(RawPacketError::MalformedAddress);
                }
                let host_len = body[0] as usize;
                if host_len > MAX_HOST_LEN || 1 + host_len + 2 != body.len() {
                    return Err(RawPacketError::MalformedAddress);
                }
                let host = match std::str::from_utf8(&body[1..1 + host_len]) {
                    Ok(h) => h.to_string(),
                    Err(_) => return Err(RawPacketError::MalformedAddress),
                };
                let port = u16::from_be_bytes([body[1 + host_len], body[1 + host_len + 1]]);
                let target = TargetEndpoint::new(host, port);
                if msg_type == MSG_TCP {
                    RawPacketMessage::Tcp(target)
                } else {
                    RawPacketMessage::Udp(target)
                }
            }
            MSG_TCPF => {
                if body.is_empty() {
                    return Err(RawPacketError::BufferTooShort);
                }
                let count = body[0] as usize;
                if count > MAX_TCPF_COUNT || 1 + count * 2 != body.len() {
                    return Err(RawPacketError::BufferTooShort);
                }
                let mut flags = Vec::with_capacity(count);
                for i in 0..count {
                    let offset = 1 + i * 2;
                    let val = u16::from_be_bytes([body[offset], body[offset + 1]]);
                    flags.push(RawTcpFlags::decode(val));
                }
                RawPacketMessage::Tcpf(flags)
            }
            other => return Err(RawPacketError::UnknownType(other)),
        };

        Ok((msg, total_len))
    }
}

/// Internet Checksum (RFC 1071) calculation for pseudo-header and raw packets.
pub struct InternetChecksum;

impl InternetChecksum {
    /// Computes 16-bit one's complement sum over a slice.
    pub fn compute(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;
        while i + 1 < data.len() {
            let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            sum += word;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Computes TCP checksum over IPv4 pseudo-header, TCP header, and payload.
    pub fn tcp_ipv4_checksum(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        tcp_hdr_and_payload: &[u8],
    ) -> u16 {
        let mut sum = 0u32;

        // Pseudo-header: SrcIP (4B), DstIP (4B), Zero (1B), Proto=6 (1B), TCP Length (2B)
        let src_octets = src.octets();
        sum += u16::from_be_bytes([src_octets[0], src_octets[1]]) as u32;
        sum += u16::from_be_bytes([src_octets[2], src_octets[3]]) as u32;

        let dst_octets = dst.octets();
        sum += u16::from_be_bytes([dst_octets[0], dst_octets[1]]) as u32;
        sum += u16::from_be_bytes([dst_octets[2], dst_octets[3]]) as u32;

        sum += 6u32; // Protocol 6 (TCP)
        sum += (tcp_hdr_and_payload.len() as u16) as u32;

        // Data
        let mut i = 0;
        while i + 1 < tcp_hdr_and_payload.len() {
            sum += u16::from_be_bytes([tcp_hdr_and_payload[i], tcp_hdr_and_payload[i + 1]]) as u32;
            i += 2;
        }
        if i < tcp_hdr_and_payload.len() {
            sum += (tcp_hdr_and_payload[i] as u32) << 8;
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Computes TCP checksum over IPv6 pseudo-header, TCP header, and payload.
    pub fn tcp_ipv6_checksum(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        tcp_hdr_and_payload: &[u8],
    ) -> u16 {
        let mut sum = 0u32;

        // Pseudo-header: SrcIP (16B), DstIP (16B), TCP Length (4B), NextHeader=6 (4B)
        let src_octets = src.octets();
        for chunk in src_octets.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }

        let dst_octets = dst.octets();
        for chunk in dst_octets.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }

        sum += (tcp_hdr_and_payload.len() as u32) & 0xFFFF;
        sum += (tcp_hdr_and_payload.len() as u32) >> 16;
        sum += 6u32; // Next Header = TCP

        let mut i = 0;
        while i + 1 < tcp_hdr_and_payload.len() {
            sum += u16::from_be_bytes([tcp_hdr_and_payload[i], tcp_hdr_and_payload[i + 1]]) as u32;
            i += 2;
        }
        if i < tcp_hdr_and_payload.len() {
            sum += (tcp_hdr_and_payload[i] as u32) << 8;
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !(sum as u16)
    }
}

/// 64-bit peer/endpoint hash utilities.
pub struct RawPacketHasher;

impl RawPacketHasher {
    /// Hashes an IP and port into a 64-bit bucket key.
    pub fn hash_ip_addr(ip: IpAddr, port: u16) -> u64 {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                let ip_u32 = u32::from_be_bytes(octets);
                ((ip_u32 as u64) << 16) | (port as u64)
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                let h1 = u64::from_be_bytes([octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6], octets[7]]);
                let h2 = u64::from_be_bytes([octets[8], octets[9], octets[10], octets[11], octets[12], octets[13], octets[14], octets[15]]);
                (h1 ^ h2) ^ ((port as u64) << 48)
            }
        }
    }
}

/// KCP transport mode tuning profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KcpTransportProfile {
    pub mode: String,
    pub nodelay: i32,
    pub interval: i32,
    pub resend: i32,
    pub nocongestion: i32,
    pub wdelay: bool,
    pub acknodelay: bool,
    pub mtu: i32,
    pub sndwnd: i32,
    pub rcvwnd: i32,
    pub dscp: i32,
}

impl KcpTransportProfile {
    /// Creates profile preset matching paqet mode specifications.
    pub fn from_mode(mode: &str) -> Self {
        match mode.to_ascii_lowercase().as_str() {
            "fast" => Self {
                mode: "fast".into(),
                nodelay: 0,
                interval: 30,
                resend: 2,
                nocongestion: 1,
                wdelay: true,
                acknodelay: false,
                mtu: 1350,
                sndwnd: 128,
                rcvwnd: 512,
                dscp: 46,
            },
            "fast2" => Self {
                mode: "fast2".into(),
                nodelay: 1,
                interval: 20,
                resend: 2,
                nocongestion: 1,
                wdelay: false,
                acknodelay: true,
                mtu: 1350,
                sndwnd: 128,
                rcvwnd: 512,
                dscp: 46,
            },
            "fast3" => Self {
                mode: "fast3".into(),
                nodelay: 1,
                interval: 10,
                resend: 2,
                nocongestion: 1,
                wdelay: false,
                acknodelay: true,
                mtu: 1350,
                sndwnd: 128,
                rcvwnd: 512,
                dscp: 46,
            },
            _ => Self { // "normal"
                mode: "normal".into(),
                nodelay: 0,
                interval: 40,
                resend: 2,
                nocongestion: 1,
                wdelay: true,
                acknodelay: false,
                mtu: 1350,
                sndwnd: 128,
                rcvwnd: 512,
                dscp: 46,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_parsing_and_bitfield() {
        let flags = RawTcpFlags::parse_str("PA").unwrap();
        assert!(flags.psh);
        assert!(flags.ack);
        assert!(!flags.syn);
        assert_eq!(flags.encode(), FLAG_PSH | FLAG_ACK);

        let decoded = RawTcpFlags::decode(flags.encode());
        assert_eq!(decoded, flags);
        assert_eq!(flags.to_flag_str(), "PA");

        let syn_ack = RawTcpFlags::parse_str("SA").unwrap();
        assert!(syn_ack.syn);
        assert!(syn_ack.ack);
        assert_eq!(syn_ack.encode(), FLAG_SYN | FLAG_ACK);
        assert_eq!(syn_ack.to_flag_str(), "SA");

        let err = RawTcpFlags::parse_str("PX");
        assert!(err.is_err());
    }

    #[test]
    fn test_ping_pong_codec() {
        let ping = RawPacketCodec::encode(&RawPacketMessage::Ping).unwrap();
        assert_eq!(ping, vec![RAW_PACKET_MAGIC, RAW_PACKET_VERSION, MSG_PING, 0, 0]);

        let (msg, len) = RawPacketCodec::decode(&ping).unwrap();
        assert_eq!(len, 5);
        assert_eq!(msg, RawPacketMessage::Ping);

        let pong = RawPacketCodec::encode(&RawPacketMessage::Pong).unwrap();
        assert_eq!(pong, vec![RAW_PACKET_MAGIC, RAW_PACKET_VERSION, MSG_PONG, 0, 0]);

        let (msg_pong, len_pong) = RawPacketCodec::decode(&pong).unwrap();
        assert_eq!(len_pong, 5);
        assert_eq!(msg_pong, RawPacketMessage::Pong);
    }

    #[test]
    fn test_tcp_address_codec() {
        let target = TargetEndpoint::new("127.0.0.1", 9999);
        let encoded = RawPacketCodec::encode(&RawPacketMessage::Tcp(target.clone())).unwrap();
        let (decoded, len) = RawPacketCodec::decode(&encoded).unwrap();
        assert_eq!(len, encoded.len());
        assert_eq!(decoded, RawPacketMessage::Tcp(target));
    }

    #[test]
    fn test_tcpf_flags_codec() {
        let flags = vec![
            RawTcpFlags::parse_str("S").unwrap(),
            RawTcpFlags::parse_str("SA").unwrap(),
            RawTcpFlags::parse_str("PA").unwrap(),
        ];
        let encoded = RawPacketCodec::encode(&RawPacketMessage::Tcpf(flags.clone())).unwrap();
        let (decoded, len) = RawPacketCodec::decode(&encoded).unwrap();
        assert_eq!(len, encoded.len());
        assert_eq!(decoded, RawPacketMessage::Tcpf(flags));
    }

    #[test]
    fn test_checksum_computation() {
        let src = Ipv4Addr::new(192, 168, 1, 100);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let dummy_tcp = [
            0x04, 0x00, 0x1f, 0x90, // src 1024, dst 8080
            0x00, 0x00, 0x00, 0x01, // seq 1
            0x00, 0x00, 0x00, 0x00, // ack 0
            0x50, 0x02, 0xff, 0xff, // data offset 5, SYN, window 65535
            0x00, 0x00, 0x00, 0x00, // checksum 0, urgent 0
        ];
        let csum = InternetChecksum::tcp_ipv4_checksum(src, dst, &dummy_tcp);
        assert_ne!(csum, 0);
    }

    #[test]
    fn test_kcp_profiles() {
        let fast = KcpTransportProfile::from_mode("fast");
        assert_eq!(fast.interval, 30);
        assert_eq!(fast.dscp, 46);

        let fast3 = KcpTransportProfile::from_mode("fast3");
        assert_eq!(fast3.interval, 10);
        assert!(fast3.acknodelay);
        assert!(!fast3.wdelay);
    }

    #[test]
    fn test_ip_hasher() {
        let ip4: IpAddr = "192.168.1.1".parse().unwrap();
        let h1 = RawPacketHasher::hash_ip_addr(ip4, 8080);
        let h2 = RawPacketHasher::hash_ip_addr(ip4, 8081);
        assert_ne!(h1, h2);
    }
}
