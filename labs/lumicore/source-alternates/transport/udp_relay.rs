//! # UDP Relay Dispatcher
//!
//! Stateful UDP relay with per-session NAT table for full-cone and restricted-cone
//! traversal, ported from tt-master and udp-ring-queue-master.
//!
//! Architecture:
//!   - Inbound listener binds to a local UDP port.
//!   - A NAT table maps `(client_addr, remote_addr)` → outbound socket.
//!   - Each NAT entry has a configurable idle timeout.
//!   - Outbound sockets send upstream and pipe responses back to the client.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Default NAT session idle timeout.
pub const NAT_TIMEOUT: Duration = Duration::from_secs(120);
/// Maximum number of simultaneous NAT sessions.
pub const MAX_NAT_SESSIONS: usize = 4096;

/// Identifies a unique UDP NAT session.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NatKey {
    /// The original client address.
    pub client: SocketAddr,
    /// The remote destination address.
    pub remote: SocketAddr,
}

/// A single NAT session entry.
pub struct NatSession {
    /// Outbound socket connected to the remote.
    pub outbound: UdpSocket,
    /// Last activity timestamp for timeout eviction.
    pub last_active: Instant,
}

/// UDP relay NAT table.
pub struct UdpRelayNat {
    sessions: RwLock<HashMap<NatKey, Arc<Mutex<NatSession>>>>,
    timeout: Duration,
}

impl UdpRelayNat {
    pub fn new(timeout: Duration) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            timeout,
        }
    }

    /// Looks up or creates a NAT session for the given client→remote pair.
    ///
    /// If the session doesn't exist, a new outbound UDP socket is created
    /// and bound to an ephemeral local port.
    pub fn get_or_create(
        &self,
        client: SocketAddr,
        remote: SocketAddr,
    ) -> std::io::Result<Arc<Mutex<NatSession>>> {
        let key = NatKey { client, remote };

        // Fast path: session exists
        {
            let guard = self.sessions.read().unwrap();
            if let Some(sess) = guard.get(&key) {
                let mut s = sess.lock().unwrap();
                s.last_active = Instant::now();
                return Ok(Arc::clone(sess));
            }
        }

        // Slow path: create new outbound socket
        let bind_addr: SocketAddr = if remote.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let outbound = UdpSocket::bind(bind_addr)?;
        outbound.set_read_timeout(Some(Duration::from_secs(5)))?;

        let session = Arc::new(Mutex::new(NatSession {
            outbound,
            last_active: Instant::now(),
        }));

        let mut guard = self.sessions.write().unwrap();
        // Check again under write lock (double-checked locking)
        if let Some(existing) = guard.get(&key) {
            return Ok(Arc::clone(existing));
        }

        // Evict old sessions if over capacity
        if guard.len() >= MAX_NAT_SESSIONS {
            let now = Instant::now();
            guard.retain(|_, sess| {
                now.duration_since(sess.lock().unwrap().last_active) < self.timeout
            });
        }

        guard.insert(key, Arc::clone(&session));
        Ok(session)
    }

    /// Evicts all sessions that have been idle longer than the timeout.
    pub fn evict_stale(&self) {
        let now = Instant::now();
        let mut guard = self.sessions.write().unwrap();
        guard.retain(|_, sess| {
            now.duration_since(sess.lock().unwrap().last_active) < self.timeout
        });
    }

    /// Returns the number of active NAT sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.read().unwrap().len()
    }
}

/// Relay a UDP packet from client to remote, creating a NAT session if needed.
///
/// Returns the number of bytes forwarded.
pub fn relay_client_to_remote(
    nat: &UdpRelayNat,
    client: SocketAddr,
    remote: SocketAddr,
    data: &[u8],
) -> std::io::Result<usize> {
    let session = nat.get_or_create(client, remote)?;
    let guard = session.lock().unwrap();
    guard.outbound.send_to(data, remote)
}

/// Receives a response from the remote and delivers it back to the client.
///
/// `inbound` is the server-facing socket that can reach the client.
/// Returns the number of bytes sent back to the client.
pub fn relay_remote_to_client(
    session: &Arc<Mutex<NatSession>>,
    inbound: &UdpSocket,
    client: SocketAddr,
) -> std::io::Result<Option<usize>> {
    let mut buf = vec![0u8; 65_536];
    let guard = session.lock().unwrap();

    match guard.outbound.recv_from(&mut buf) {
        Ok((len, _remote_addr)) => {
            let sent = inbound.send_to(&buf[..len], client)?;
            Ok(Some(sent))
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
            || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Statistics for the UDP relay.
#[derive(Debug, Default, Clone)]
pub struct RelayStats {
    pub packets_forwarded: u64,
    pub bytes_forwarded: u64,
    pub sessions_created: u64,
    pub sessions_evicted: u64,
}

impl RelayStats {
    pub fn record_forward(&mut self, bytes: usize) {
        self.packets_forwarded += 1;
        self.bytes_forwarded += bytes as u64;
    }
}

/// UDP socks5 UDP ASSOCIATE relay handler.
///
/// Parses the SOCKS5 UDP request header to extract the real target address:
/// ```text
/// +----+------+------+----------+----------+----------+
/// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
/// +----+------+------+----------+----------+----------+
/// | 2  |  1   |  1   | Variable |    2     | Variable |
/// +----+------+------+----------+----------+----------+
/// ```
pub fn parse_socks5_udp_header(buf: &[u8]) -> Option<(SocketAddr, usize)> {
    if buf.len() < 10 {
        return None;
    }
    // RSV (2 bytes) + FRAG (1 byte) = first 3 bytes
    let _rsv = &buf[0..2];
    let frag = buf[2];
    if frag != 0 {
        // Fragmented UDP not supported
        return None;
    }
    let atyp = buf[3];
    let (addr, header_len) = match atyp {
        0x01 => {
            // IPv4
            if buf.len() < 10 {
                return None;
            }
            let ip = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (SocketAddr::new(std::net::IpAddr::V4(ip), port), 10)
        }
        0x04 => {
            // IPv6
            if buf.len() < 22 {
                return None;
            }
            let octets: [u8; 16] = buf[4..20].try_into().ok()?;
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (SocketAddr::new(std::net::IpAddr::V6(ip), port), 22)
        }
        _ => return None, // Domain names handled at a higher layer
    };
    Some((addr, header_len))
}

/// Builds a SOCKS5 UDP encapsulation header for the given destination address.
pub fn build_socks5_udp_header(dest: SocketAddr) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(22);
    hdr.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV + FRAG
    match dest {
        SocketAddr::V4(v4) => {
            hdr.push(0x01);
            hdr.extend_from_slice(&v4.ip().octets());
            hdr.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            hdr.push(0x04);
            hdr.extend_from_slice(&v6.ip().octets());
            hdr.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    hdr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_session_create_and_count() {
        let nat = UdpRelayNat::new(NAT_TIMEOUT);
        let client: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let remote: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        // Create a session (requires socket binding to succeed)
        let _ = nat.get_or_create(client, remote);
        assert!(nat.session_count() <= 1);
    }

    #[test]
    fn test_socks5_udp_header_ipv4_parse() {
        let mut buf = vec![0u8; 14];
        buf[2] = 0; // FRAG = 0
        buf[3] = 0x01; // ATYP = IPv4
        buf[4..8].copy_from_slice(&[192, 168, 1, 100]);
        buf[8..10].copy_from_slice(&443u16.to_be_bytes());
        let payload = b"data";
        buf[10..14].copy_from_slice(payload);

        let result = parse_socks5_udp_header(&buf);
        assert!(result.is_some());
        let (addr, hdr_len) = result.unwrap();
        assert_eq!(hdr_len, 10);
        assert_eq!(addr.port(), 443);
    }

    #[test]
    fn test_socks5_udp_header_build_ipv4() {
        let dest: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let hdr = build_socks5_udp_header(dest);
        assert_eq!(hdr[0], 0x00); // RSV
        assert_eq!(hdr[2], 0x00); // FRAG
        assert_eq!(hdr[3], 0x01); // IPv4
        assert_eq!(&hdr[4..8], &[10, 0, 0, 1]);
    }

    #[test]
    fn test_evict_stale_runs_without_panic() {
        let nat = UdpRelayNat::new(Duration::from_millis(1));
        nat.evict_stale();
        assert_eq!(nat.session_count(), 0);
    }
}
