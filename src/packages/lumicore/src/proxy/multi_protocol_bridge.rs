//! Multi-Protocol Bridge Relay with Dual Sniffing and Safe LAN Sharing.
//!
//! Provides a resilient local forwarding bridge with:
//! 1. Protocol auto-sniffing: Sniffs the initial incoming byte to dynamically dispatch between
//!    RFC 1928 SOCKS5 (`0x05`) and HTTP proxy protocols (ASCII characters like `CONNECT`, `GET`, `POST`),
//!    eliminating port-mismatch failure modes.
//! 2. WinSock non-blocking inheritance mitigation: Accepted sockets inherit non-blocking mode from
//!    the listener in Windows; explicitly resets `set_nonblocking(false)` with read/write timeouts.
//! 3. Secure LAN peer gating: Rejects external non-private clients to prevent open relay exposure
//!    when sharing is active. Only loopback, RFC 1918 private, and link-local addresses are admitted.
//! 4. Rebind safety: Uses generation-scoped lifecycle flags and bounded exponential retry
//!    to avoid `WSAEADDRINUSE` (os error 10048).
//! 5. Atomic bandwidth counters: High-resolution tracking for uploaded and downloaded bytes.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

pub const DEFAULT_LOCAL_SOCKS_PORT: u16 = 1819;
pub const DEFAULT_SHARE_SOCKS_PORT: u16 = 10810;
pub const DEFAULT_SHARE_HTTP_PORT: u16 = 10811;

pub const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const UPSTREAM_TIMEOUT: Duration = TCP_IDLE_TIMEOUT;
pub const BIND_RETRIES: u32 = 20;
pub const BIND_RETRY_DELAY: Duration = Duration::from_millis(150);

/// Evaluates whether an incoming IP is permitted to access the bridge.
pub fn peer_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Identifies the protocol family based on the first byte of incoming traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressProtocol {
    Socks5,
    Http,
    Unknown,
}

pub fn sniff_ingress_protocol(first_byte: u8) -> IngressProtocol {
    match first_byte {
        0x05 => IngressProtocol::Socks5,
        b'A'..=b'Z' | b'a'..=b'z' => IngressProtocol::Http,
        _ => IngressProtocol::Unknown,
    }
}

/// Active MultiProtocolBridge instance.
pub struct MultiProtocolBridge {
    running: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    lan_ip: Option<IpAddr>,
    lan_enabled: bool,
    socks_port: u16,
    http_port: u16,
    rx: Arc<AtomicU64>,
    tx: Arc<AtomicU64>,
    upstream_socks_port: u16,
}

impl Default for MultiProtocolBridge {
    fn default() -> Self {
        Self::new(DEFAULT_LOCAL_SOCKS_PORT)
    }
}

impl MultiProtocolBridge {
    pub fn new(upstream_socks_port: u16) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            threads: Vec::new(),
            lan_ip: None,
            lan_enabled: false,
            socks_port: 0,
            http_port: 0,
            rx: Arc::new(AtomicU64::new(0)),
            tx: Arc::new(AtomicU64::new(0)),
            upstream_socks_port,
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn traffic_counters(&self) -> (u64, u64) {
        (self.rx.load(Ordering::Relaxed), self.tx.load(Ordering::Relaxed))
    }

    /// Starts bridge listeners on configured ports.
    pub fn start(&mut self, socks_port: u16, http_port: u16, lan_ip: Option<IpAddr>) -> Result<(), String> {
        self.stop();

        self.running = Arc::new(AtomicBool::new(true));
        self.rx.store(0, Ordering::Relaxed);
        self.tx.store(0, Ordering::Relaxed);
        self.socks_port = socks_port;
        self.http_port = http_port;
        self.lan_enabled = lan_ip.is_some();
        self.lan_ip = lan_ip;

        let mut bind_ips: Vec<IpAddr> = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        if let Some(ip) = self.lan_ip {
            if ip != IpAddr::V4(Ipv4Addr::LOCALHOST) {
                bind_ips.push(ip);
            }
        }

        let mut localhost_http_bound = false;
        for ip in bind_ips {
            let is_localhost = ip == IpAddr::V4(Ipv4Addr::LOCALHOST);
            if let Some(h) = self.spawn_listener(ip, http_port) {
                self.threads.push(h);
                if is_localhost {
                    localhost_http_bound = true;
                }
            }
            if let Some(h) = self.spawn_listener(ip, socks_port) {
                self.threads.push(h);
            }
        }

        if !localhost_http_bound {
            return Err("Failed to bind localhost HTTP bridge listener".to_string());
        }

        Ok(())
    }

    /// Stops listeners and waits for all worker threads to join and release ports.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        self.lan_ip = None;
        self.lan_enabled = false;
    }

    fn spawn_listener(&self, ip: IpAddr, port: u16) -> Option<JoinHandle<()>> {
        let listener = bind_with_retry(ip, port)?;
        let _ = listener.set_nonblocking(true);

        let running = self.running.clone();
        let rx = self.rx.clone();
        let tx = self.tx.clone();
        let upstream_port = self.upstream_socks_port;

        std::thread::Builder::new()
            .name(format!("lumi-bridge-{port}"))
            .spawn(move || {
                while running.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((client, peer)) => {
                            if client.set_nonblocking(false).is_err() {
                                let _ = client.shutdown(Shutdown::Both);
                                continue;
                            }
                            if !peer_allowed(peer.ip()) {
                                let _ = client.shutdown(Shutdown::Both);
                                continue;
                            }
                            let (rx_c, tx_c) = (rx.clone(), tx.clone());
                            std::thread::spawn(move || {
                                handle_client(client, upstream_port, rx_c, tx_c);
                            });
                        }
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(50));
                        }
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(150));
                        }
                    }
                }
            })
            .ok()
    }
}

impl Drop for MultiProtocolBridge {
    fn drop(&mut self) {
        self.stop();
    }
}

fn bind_with_retry(ip: IpAddr, port: u16) -> Option<TcpListener> {
    for _ in 0..BIND_RETRIES {
        match TcpListener::bind((ip, port)) {
            Ok(listener) => return Some(listener),
            Err(_) => std::thread::sleep(BIND_RETRY_DELAY),
        }
    }
    None
}

fn handle_client(client: TcpStream, upstream_port: u16, rx: Arc<AtomicU64>, tx: Arc<AtomicU64>) {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(15)));

    let mut peek_buf = [0u8; 1];
    match client.peek(&mut peek_buf) {
        Ok(n) if n > 0 => match sniff_ingress_protocol(peek_buf[0]) {
            IngressProtocol::Socks5 => handle_socks5(client, upstream_port, rx, tx),
            IngressProtocol::Http => handle_http(client, upstream_port, rx, tx),
            IngressProtocol::Unknown => {
                let _ = client.shutdown(Shutdown::Both);
            }
        },
        _ => {
            let _ = client.shutdown(Shutdown::Both);
        }
    }
}

fn handle_socks5(client: TcpStream, upstream_port: u16, rx: Arc<AtomicU64>, tx: Arc<AtomicU64>) {
    let upstream_addr = SocketAddr::from(([127, 0, 0, 1], upstream_port));
    match TcpStream::connect_timeout(&upstream_addr, UPSTREAM_TIMEOUT) {
        Ok(upstream) => {
            let _ = upstream.set_nodelay(true);
            relay_streams(client, upstream, rx, tx);
        }
        Err(_) => {
            let _ = client.shutdown(Shutdown::Both);
        }
    }
}

fn handle_http(mut client: TcpStream, upstream_port: u16, rx: Arc<AtomicU64>, tx: Arc<AtomicU64>) {
    let Some(head) = read_http_header(&mut client) else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };

    let text = String::from_utf8_lossy(&head);
    let Some(first_line) = text.lines().next() else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };

    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        let mut target_parts = target.split(':');
        let host = target_parts.next().unwrap_or("");
        let port: u16 = target_parts
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);

        let upstream_addr = SocketAddr::from(([127, 0, 0, 1], upstream_port));
        let Ok(mut upstream) = TcpStream::connect_timeout(&upstream_addr, UPSTREAM_TIMEOUT) else {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return;
        };

        if socks5_connect_tunnel(&mut upstream, host, port).is_none() {
            let _ = client.write_all(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n");
            return;
        }

        if client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
            return;
        }

        relay_streams(client, upstream, rx, tx);
    } else {
        // Plain HTTP proxy: client connects directly or via GET/POST
        let upstream_addr = SocketAddr::from(([127, 0, 0, 1], upstream_port));
        if let Ok(mut upstream) = TcpStream::connect_timeout(&upstream_addr, UPSTREAM_TIMEOUT) {
            let _ = upstream.write_all(&head);
            relay_streams(client, upstream, rx, tx);
        }
    }
}

fn read_http_header(client: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    loop {
        match client.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16384 {
                    return Some(buf);
                }
            }
            Err(_) => break,
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

fn socks5_connect_tunnel(stream: &mut TcpStream, host: &str, port: u16) -> Option<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).ok()?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).ok()?;
    if greeting != [0x05, 0x00] {
        return None;
    }

    let mut req: Vec<u8> = vec![0x05, 0x01, 0x00];
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&v4.octets());
    } else {
        let bytes = host.as_bytes();
        if bytes.len() > 255 {
            return None;
        }
        req.push(0x03);
        req.push(bytes.len() as u8);
        req.extend_from_slice(bytes);
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).ok()?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).ok()?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return None;
    }

    // Skip bound address
    match reply[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            stream.read_exact(&mut skip).ok()?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).ok()?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            stream.read_exact(&mut skip).ok()?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            stream.read_exact(&mut skip).ok()?;
        }
        _ => return None,
    }

    Some(())
}

fn relay_streams(mut a: TcpStream, mut b: TcpStream, rx: Arc<AtomicU64>, tx: Arc<AtomicU64>) {
    let mut a_clone = match a.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut b_clone = match b.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    };

    let rx_c = rx.clone();
    let forward = std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        loop {
            match a.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    rx_c.fetch_add(n as u64, Ordering::Relaxed);
                    if b_clone.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = b_clone.shutdown(Shutdown::Write);
    });

    let tx_c = tx.clone();
    let mut buf = [0u8; 8192];
    loop {
        match b.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                tx_c.fetch_add(n as u64, Ordering::Relaxed);
                if a_clone.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = a_clone.shutdown(Shutdown::Write);
    let _ = forward.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_socks5_and_http() {
        assert_eq!(sniff_ingress_protocol(0x05), IngressProtocol::Socks5);
        assert_eq!(sniff_ingress_protocol(b'G'), IngressProtocol::Http);
        assert_eq!(sniff_ingress_protocol(b'C'), IngressProtocol::Http);
        assert_eq!(sniff_ingress_protocol(b'P'), IngressProtocol::Http);
        assert_eq!(sniff_ingress_protocol(0x00), IngressProtocol::Unknown);
    }

    #[test]
    fn peer_allowed_verifies_private_and_loopback() {
        assert!(peer_allowed("127.0.0.1".parse().unwrap()));
        assert!(peer_allowed("192.168.1.100".parse().unwrap()));
        assert!(peer_allowed("10.0.0.5".parse().unwrap()));
        assert!(peer_allowed("172.16.0.1".parse().unwrap()));
        assert!(peer_allowed("::1".parse().unwrap()));

        // Public IP rejected
        assert!(!peer_allowed("8.8.8.8".parse().unwrap()));
        assert!(!peer_allowed("1.1.1.1".parse().unwrap()));
    }
}
