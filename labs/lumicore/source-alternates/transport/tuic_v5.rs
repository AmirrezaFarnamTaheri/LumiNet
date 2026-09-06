// Ported from: tuic-main & tuic-master
// Target path: core/src/transport/tuic_v5.rs

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::marker::PhantomData;
use bytes::{Bytes, BytesMut, Buf, BufMut};
use thiserror::Error;

// ── Address Code & Types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    None = 0xff,
    Domain = 0x00,
    IPv4 = 0x01,
    IPv6 = 0x02,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    None,
    Domain(String, u16),
    IPv4(SocketAddr),
    IPv6(SocketAddr),
}

impl Address {
    pub const TYPE_CODE_NONE: u8 = 0xff;
    pub const TYPE_CODE_DOMAIN: u8 = 0x00;
    pub const TYPE_CODE_IPV4: u8 = 0x01;
    pub const TYPE_CODE_IPV6: u8 = 0x02;

    pub fn read(buf: &mut &[u8]) -> Result<Self, UnmarshalError> {
        if !buf.has_remaining() {
            return Err(UnmarshalError::UnexpectedEof);
        }
        let type_code = buf.get_u8();
        match type_code {
            Self::TYPE_CODE_NONE => Ok(Address::None),
            Self::TYPE_CODE_DOMAIN => {
                if !buf.has_remaining() {
                    return Err(UnmarshalError::UnexpectedEof);
                }
                let len = buf.get_u8() as usize;
                if buf.remaining() < len + 2 {
                    return Err(UnmarshalError::UnexpectedEof);
                }
                let mut domain_bytes = vec![0u8; len];
                buf.copy_to_slice(&mut domain_bytes);
                let domain = String::from_utf8(domain_bytes)
                    .map_err(|_| UnmarshalError::InvalidAddress)?;
                let port = buf.get_u16();
                Ok(Address::Domain(domain, port))
            }
            Self::TYPE_CODE_IPV4 => {
                if buf.remaining() < 6 {
                    return Err(UnmarshalError::UnexpectedEof);
                }
                let mut ip_bytes = [0u8; 4];
                buf.copy_to_slice(&mut ip_bytes);
                let port = buf.get_u16();
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_bytes)), port);
                Ok(Address::IPv4(addr))
            }
            Self::TYPE_CODE_IPV6 => {
                if buf.remaining() < 18 {
                    return Err(UnmarshalError::UnexpectedEof);
                }
                let mut ip_bytes = [0u8; 16];
                buf.copy_to_slice(&mut ip_bytes);
                let port = buf.get_u16();
                let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port);
                Ok(Address::IPv6(addr))
            }
            _ => Err(UnmarshalError::InvalidAddressType),
        }
    }

    pub async fn async_read<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<Self, UnmarshalError> {
        use tokio::io::AsyncReadExt;
        let type_code = reader.read_u8().await.map_err(|_| UnmarshalError::UnexpectedEof)?;
        match type_code {
            Self::TYPE_CODE_NONE => Ok(Address::None),
            Self::TYPE_CODE_DOMAIN => {
                let len = reader.read_u8().await.map_err(|_| UnmarshalError::UnexpectedEof)? as usize;
                let mut domain_bytes = vec![0u8; len];
                reader.read_exact(&mut domain_bytes).await.map_err(|_| UnmarshalError::UnexpectedEof)?;
                let domain = String::from_utf8(domain_bytes)
                    .map_err(|_| UnmarshalError::InvalidAddress)?;
                let port = reader.read_u16().await.map_err(|_| UnmarshalError::UnexpectedEof)?;
                Ok(Address::Domain(domain, port))
            }
            Self::TYPE_CODE_IPV4 => {
                let mut ip_bytes = [0u8; 4];
                reader.read_exact(&mut ip_bytes).await.map_err(|_| UnmarshalError::UnexpectedEof)?;
                let port = reader.read_u16().await.map_err(|_| UnmarshalError::UnexpectedEof)?;
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_bytes)), port);
                Ok(Address::IPv4(addr))
            }
            Self::TYPE_CODE_IPV6 => {
                let mut ip_bytes = [0u8; 16];
                reader.read_exact(&mut ip_bytes).await.map_err(|_| UnmarshalError::UnexpectedEof)?;
                let port = reader.read_u16().await.map_err(|_| UnmarshalError::UnexpectedEof)?;
                let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip_bytes)), port);
                Ok(Address::IPv6(addr))
            }
            _ => Err(UnmarshalError::InvalidAddressType),
        }
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        match self {
            Address::None => {
                buf.put_u8(Self::TYPE_CODE_NONE);
            }
            Address::Domain(domain, port) => {
                buf.put_u8(Self::TYPE_CODE_DOMAIN);
                buf.put_u8(domain.len() as u8);
                buf.put_slice(domain.as_bytes());
                buf.put_u16(*port);
            }
            Address::IPv4(addr) => {
                buf.put_u8(Self::TYPE_CODE_IPV4);
                if let IpAddr::V4(ip) = addr.ip() {
                    buf.put_slice(&ip.octets());
                }
                buf.put_u16(addr.port());
            }
            Address::IPv6(addr) => {
                buf.put_u8(Self::TYPE_CODE_IPV6);
                if let IpAddr::V6(ip) = addr.ip() {
                    buf.put_slice(&ip.octets());
                }
                buf.put_u16(addr.port());
            }
        }
    }
}

// ── Unmarshal Errors ───────────────────────────────────────────────────────────

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum UnmarshalError {
    #[error("Unexpected end of payload buffer")]
    UnexpectedEof,
    #[error("Invalid protocol version")]
    InvalidVersion,
    #[error("Invalid command")]
    InvalidCommand,
    #[error("Invalid address format")]
    InvalidAddress,
    #[error("Unsupported address type code")]
    InvalidAddressType,
}

// ── Side Phantom Markers ───────────────────────────────────────────────────────

pub mod side {
    #[derive(Debug)]
    pub struct Tx;
    #[derive(Debug)]
    pub struct Rx;
}

// ── Connect Command Struct ─────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Connect<M> {
    pub version: u8,
    pub command: u8,
    pub address: Address,
    _marker: PhantomData<M>,
}

impl Connect<side::Tx> {
    pub fn new(address: Address) -> Self {
        Connect {
            version: 5,
            command: 0x01, // CONNECT command
            address,
            _marker: PhantomData,
        }
    }

    pub fn header(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(self.version);
        buf.put_u8(self.command);
        self.address.write_to(&mut buf);
        buf.freeze()
    }
}

impl Connect<side::Rx> {
    pub fn new(mut data: &[u8]) -> Result<Self, UnmarshalError> {
        if data.remaining() < 2 {
            return Err(UnmarshalError::UnexpectedEof);
        }
        let version = data.get_u8();
        if version != 5 {
            return Err(UnmarshalError::InvalidVersion);
        }
        let command = data.get_u8();
        if command != 0x01 {
            return Err(UnmarshalError::InvalidCommand);
        }
        let address = Address::read(&mut data)?;
        Ok(Connect {
            version,
            command,
            address,
            _marker: PhantomData,
        })
    }

    pub fn addr(&self) -> &Address {
        &self.address
    }
}

// ── Dissociate Command Struct ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct Dissociate<M> {
    pub version: u8,
    pub command: u8,
    pub assoc_id: u16,
    _marker: PhantomData<M>,
}

impl Dissociate<side::Tx> {
    pub fn new(assoc_id: u16) -> Self {
        Dissociate {
            version: 5,
            command: 0x02, // DISSOCIATE command
            assoc_id,
            _marker: PhantomData,
        }
    }

    pub fn header(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.put_u8(self.version);
        buf.put_u8(self.command);
        buf.put_u16(self.assoc_id);
        buf.freeze()
    }
}

impl Dissociate<side::Rx> {
    pub fn new(mut data: &[u8]) -> Result<Self, UnmarshalError> {
        if data.remaining() < 4 {
            return Err(UnmarshalError::UnexpectedEof);
        }
        let version = data.get_u8();
        if version != 5 {
            return Err(UnmarshalError::InvalidVersion);
        }
        let command = data.get_u8();
        if command != 0x02 {
            return Err(UnmarshalError::InvalidCommand);
        }
        let assoc_id = data.get_u16();
        Ok(Dissociate {
            version,
            command,
            assoc_id,
            _marker: PhantomData,
        })
    }

    pub fn assoc_id(&self) -> u16 {
        self.assoc_id
    }
}

// ── Config Descriptor ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub congestion_control: String,
    pub alpn: Vec<String>,
    pub udp_relay_ipv6: bool,
    pub zero_rtt_handshake: bool,
    pub auth_timeout: u64,
    pub max_idle_time: u64,
    pub max_external_packet_size: usize,
    pub gc_interval: u64,
    pub gc_lifetime: u64,
    pub log_level: String,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization/Deserialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Invalid configuration setting: {0}")]
    InvalidSetting(String),
}

impl Config {
    pub fn parse(json_str: &str) -> Result<Self, ConfigError> {
        let cfg: Config = serde_json::from_str(json_str)?;
        Ok(cfg)
    }
}

// Congestion Control defaults
pub mod default {
    pub fn congestion_control() -> String {
        "cubic".to_string()
    }

    pub fn alpn() -> Vec<String> {
        vec![]
    }

    pub fn udp_relay_ipv6() -> bool {
        false
    }

    pub fn zero_rtt_handshake() -> bool {
        true
    }

    pub fn auth_timeout() -> u64 {
        5
    }

    pub fn max_idle_time() -> u64 {
        10
    }

    pub fn max_external_packet_size() -> usize {
        1500
    }

    pub fn gc_interval() -> u64 {
        10
    }

    pub fn gc_lifetime() -> u64 {
        30
    }

    pub fn log_level() -> String {
        "info".to_string()
    }
}
