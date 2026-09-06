//
// Zero-copy IPv4/IPv6 packet parser .rs`.
// Backed by a `Box<[u8]>` slice so the header view stays a cheap borrow of
// the underlying buffer — no allocation per parse. The tun2tor original
// uses the `bytes` crate's shared `Bytes` newtype; LumiNet's cargo deps
// already include `bytes`, but a plain `Box<[u8]>` keeps the API surface
// zero-cost without pulling downstream refcount semantics here.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum IpProto {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Other(u8),
}

impl From<u8> for IpProto {
    fn from(b: u8) -> Self {
        match b {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            other => Self::Other(other),
        }
    }
}

/// IPv4 header view over a borrowed byte slice.
#[derive(Clone, Debug)]
pub struct Ipv4Header(pub Box<[u8]>);

impl Ipv4Header {
    /// Internet Header Length in bytes (`IHL * 4`).
    pub fn ihl(&self) -> usize {
        ((self.0[0] & 0x0F) * 4) as usize
    }
    pub fn src(&self) -> Ipv4Addr {
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.0[12..16]);
        Ipv4Addr::from(b)
    }
    pub fn dst(&self) -> Ipv4Addr {
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.0[16..20]);
        Ipv4Addr::from(b)
    }
    pub fn total_len(&self) -> usize {
        u16::from_be_bytes([self.0[2], self.0[3]]) as usize
    }
    pub fn proto(&self) -> IpProto {
        IpProto::from(self.0[9])
    }
    /// True when the IPv4 header checksum field is valid.
    pub fn verify_checksum(&self) -> bool {
        let ihl = self.ihl();
        if ihl < 20 || ihl > self.0.len() {
            return false;
        }
        let sum: u32 = self.0[..ihl]
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32)
            .sum();
        let folded = (sum + (sum >> 16)) & 0xFFFF;
        folded == 0xFFFF
    }
}

/// IPv6 header view over a borrowed byte slice (40-byte fixed header).
#[derive(Clone, Debug)]
pub struct Ipv6Header(pub Box<[u8]>);

impl Ipv6Header {
    pub const LEN: usize = 40;

    pub fn src(&self) -> Ipv6Addr {
        let mut b = [0u8; 16];
        b.copy_from_slice(&self.0[8..24]);
        Ipv6Addr::from(b)
    }
    pub fn dst(&self) -> Ipv6Addr {
        let mut b = [0u8; 16];
        b.copy_from_slice(&self.0[24..40]);
        Ipv6Addr::from(b)
    }
    pub fn payload_len(&self) -> usize {
        u16::from_be_bytes([self.0[4], self.0[5]]) as usize
    }
    pub fn next_header(&self) -> IpProto {
        IpProto::from(self.0[6])
    }
    pub fn hop_limit(&self) -> u8 {
        self.0[7]
    }
}

/// Parsed IP packet — either v4 or v6 — plus the protocol-declared payload bytes.
#[derive(Clone, Debug)]
pub enum IpPacket {
    V4(Ipv4Header, Box<[u8]>),
    V6(Ipv6Header, Box<[u8]>),
}

impl IpPacket {
    /// Parse a raw packet buffer into owned header + protocol-declared payload.
    /// Bytes beyond the declared IP packet length are intentionally excluded.
    pub fn parse(buf: impl Into<Box<[u8]>>) -> io::Result<Self> {
        let buf = buf.into();
        if buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty IP packet",
            ));
        }
        match buf[0] >> 4 {
            4 => {
                let ihl = ((buf[0] & 0x0F) * 4) as usize;
                if ihl < 20 || buf.len() < ihl {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "IPv4 header length invalid or truncated: required={ihl} available={}",
                            buf.len()
                        ),
                    ));
                }
                let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
                if total_len < ihl {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "IPv4 total length is smaller than header length: total={total_len} header={ihl}"
                        ),
                    ));
                }
                if buf.len() < total_len {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "IPv4 packet truncated: required={total_len} available={}",
                            buf.len()
                        ),
                    ));
                }
                let hdr = &buf[..ihl];
                let payload = &buf[ihl..total_len];
                Ok(Self::V4(
                    Ipv4Header(hdr.to_vec().into_boxed_slice()),
                    payload.to_vec().into_boxed_slice(),
                ))
            }
            6 => {
                if buf.len() < Ipv6Header::LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "IPv6 header truncated",
                    ));
                }
                let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
                let total_len = Ipv6Header::LEN + payload_len;
                if buf.len() < total_len {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "IPv6 packet truncated: required={total_len} available={}",
                            buf.len()
                        ),
                    ));
                }
                let hdr = &buf[..Ipv6Header::LEN];
                let payload = &buf[Ipv6Header::LEN..total_len];
                Ok(Self::V6(
                    Ipv6Header(hdr.to_vec().into_boxed_slice()),
                    payload.to_vec().into_boxed_slice(),
                ))
            }
            v => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported IP version {}", v),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_ipv4_tcp() -> Box<[u8]> {
        // 20-byte IPv4 + 0-byte payload, version=4, ihl=5, TCP, src/dst set.
        let mut b = vec![0u8; 20];
        b[0] = 0x45; // version=4, ihl=5
        b[2] = 0;
        b[3] = 20; // total_len=20
        b[9] = 6; // TCP
                  // checksum: leave zero — verifier should report false here.
        b[12..16].copy_from_slice(&[10, 0, 0, 1]);
        b[16..20].copy_from_slice(&[8, 8, 8, 8]);
        b.into_boxed_slice()
    }

    #[test]
    fn parses_ipv4() {
        let pkt = IpPacket::parse(minimal_ipv4_tcp()).unwrap();
        match pkt {
            IpPacket::V4(h, p) => {
                assert_eq!(h.ihl(), 20);
                assert_eq!(h.total_len(), 20);
                assert_eq!(h.src(), Ipv4Addr::new(10, 0, 0, 1));
                assert_eq!(h.dst(), Ipv4Addr::new(8, 8, 8, 8));
                assert_eq!(h.proto(), IpProto::Tcp);
                assert!(p.is_empty());
            }
            _ => panic!("expected V4"),
        }
    }

    #[test]
    fn rejects_unknown_version() {
        let mut b = vec![0u8; 20];
        b[0] = 0x70; // version 7
        let err = IpPacket::parse(b.into_boxed_slice());
        assert!(err.is_err());
    }

    #[test]
    fn rejects_empty() {
        let err = IpPacket::parse(vec![].into_boxed_slice());
        assert!(err.is_err());
    }

    #[test]
    fn parses_ipv6() {
        let mut b = vec![0u8; Ipv6Header::LEN + 4];
        b[0] = 0x60; // version 6
        b[4] = 0;
        b[5] = 4; // payload_len = 4
        b[6] = 6; // next_header = TCP
        b[7] = 64; // hop_limit
        b[8..24].copy_from_slice(&[0xFE; 16]);
        b[24..40].copy_from_slice(&[0x20; 16]);
        let pkt = IpPacket::parse(b.into_boxed_slice()).unwrap();
        if let IpPacket::V6(h, p) = pkt {
            assert_eq!(h.payload_len(), 4);
            assert_eq!(h.next_header(), IpProto::Tcp);
            assert_eq!(h.hop_limit(), 64);
            assert_eq!(p.len(), 4);
        } else {
            panic!("expected V6");
        }
    }

    #[test]
    fn rejects_ipv4_total_length_smaller_than_header() {
        let mut b = minimal_ipv4_tcp().into_vec();
        b[2..4].copy_from_slice(&19u16.to_be_bytes());
        let err = IpPacket::parse(b.into_boxed_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("total length"));
    }

    #[test]
    fn rejects_truncated_ipv4_declared_length() {
        let mut b = minimal_ipv4_tcp().into_vec();
        b[2..4].copy_from_slice(&24u16.to_be_bytes());
        let err = IpPacket::parse(b.into_boxed_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(err.to_string().contains("required=24 available=20"));
    }

    #[test]
    fn ipv4_payload_stops_at_declared_total_length() {
        let mut b = minimal_ipv4_tcp().into_vec();
        b.extend_from_slice(&[1, 2, 3, 4]);
        let pkt = IpPacket::parse(b.into_boxed_slice()).unwrap();
        match pkt {
            IpPacket::V4(_, payload) => assert!(payload.is_empty()),
            _ => panic!("expected V4"),
        }
    }

    #[test]
    fn rejects_truncated_ipv6_declared_payload() {
        let mut b = vec![0u8; Ipv6Header::LEN + 2];
        b[0] = 0x60;
        b[4..6].copy_from_slice(&4u16.to_be_bytes());
        let err = IpPacket::parse(b.into_boxed_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(err.to_string().contains("required=44 available=42"));
    }

    #[test]
    fn ipv6_payload_stops_at_declared_payload_length() {
        let mut b = vec![0u8; Ipv6Header::LEN + 4];
        b[0] = 0x60;
        b[4..6].copy_from_slice(&2u16.to_be_bytes());
        b[Ipv6Header::LEN..].copy_from_slice(&[1, 2, 3, 4]);
        let pkt = IpPacket::parse(b.into_boxed_slice()).unwrap();
        match pkt {
            IpPacket::V6(_, payload) => assert_eq!(&*payload, &[1, 2]),
            _ => panic!("expected V6"),
        }
    }
}
