//! # Android TUN Bridge & FakeDNS SOCKS5 Address Rewriter
//!
//! Provides safe file-descriptor duplication (preventing Android ParcelFileDescriptor double-close SIGSEGV),
//! dynamic RFC 2544 FakeIP address mapping (198.18.0.0/16), and SOCKS5 destination rewriting.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TunBridgeError {
    #[error("File descriptor duplication failed: OS error {0}")]
    DupFailed(i32),
    #[error("Invalid file descriptor {0}")]
    InvalidFd(i32),
    #[error("Malformed SOCKS5 request payload")]
    MalformedSocks5Request,
}

/// Duplicates a file descriptor so the native TUN engine and Android's ParcelFileDescriptor
/// each possess an independent handle, eliminating double-close panics upon teardown.
pub fn dup_fd(fd: i32) -> Result<i32, TunBridgeError> {
    if fd < 0 {
        return Err(TunBridgeError::InvalidFd(fd));
    }
    #[cfg(unix)]
    {
        let dup = unsafe { libc::dup(fd) };
        if dup < 0 {
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(TunBridgeError::DupFailed(err));
        }
        Ok(dup)
    }
    #[cfg(not(unix))]
    {
        // On non-Unix platforms (e.g. Windows unit tests), return the fd as is
        Ok(fd)
    }
}

/// Thread-safe bidirectional FakeDNS IP <-> Hostname mapping table (198.18.0.0/16).
pub struct FakeDnsMapper {
    counter: AtomicU32,
    hostname_to_ip: RwLock<HashMap<String, Ipv4Addr>>,
    ip_to_hostname: RwLock<HashMap<Ipv4Addr, String>>,
}

impl Default for FakeDnsMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeDnsMapper {
    pub fn new() -> Self {
        Self {
            counter: AtomicU32::new(1),
            hostname_to_ip: RwLock::new(HashMap::new()),
            ip_to_hostname: RwLock::new(HashMap::new()),
        }
    }

    /// Allocates or retrieves an existing synthetic IPv4 in the 198.18.0.0/16 range for a hostname.
    pub fn get_fake_ip(&self, hostname: &str) -> Ipv4Addr {
        let clean = hostname.trim().to_ascii_lowercase();
        {
            let r = self.hostname_to_ip.read().unwrap();
            if let Some(&ip) = r.get(&clean) {
                return ip;
            }
        }

        let mut cnt = self.counter.fetch_add(1, Ordering::SeqCst);
        if cnt > 65535 {
            self.counter.store(1, Ordering::SeqCst);
            cnt = 1;
        }

        let octet3 = (cnt >> 8) as u8;
        let octet4 = (cnt & 0xFF) as u8;
        let fake_ip = Ipv4Addr::new(198, 18, octet3, octet4);

        {
            let mut w_h2i = self.hostname_to_ip.write().unwrap();
            let mut w_i2h = self.ip_to_hostname.write().unwrap();
            w_h2i.insert(clean.clone(), fake_ip);
            w_i2h.insert(fake_ip, clean);
        }

        fake_ip
    }

    /// Resolves a synthetic FakeIP back to its original domain name.
    pub fn get_hostname(&self, ip: &Ipv4Addr) -> Option<String> {
        let r = self.ip_to_hostname.read().unwrap();
        r.get(ip).cloned()
    }

    /// Returns the number of active host mappings.
    pub fn mapping_count(&self) -> usize {
        self.hostname_to_ip.read().unwrap().len()
    }

    /// Clears all stored mappings.
    pub fn clear(&self) {
        self.hostname_to_ip.write().unwrap().clear();
        self.ip_to_hostname.write().unwrap().clear();
        self.counter.store(1, Ordering::SeqCst);
    }
}

/// SOCKS5 address type constants.
pub const SOCKS5_ATYP_IPV4: u8 = 0x01;
pub const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
pub const SOCKS5_ATYP_IPV6: u8 = 0x04;

/// Rewrites a SOCKS5 CONNECT (CMD=1) request from a synthetic FakeIP (198.18.x.y)
/// back into an explicit domain name destination (ATYP=3).
pub fn rewrite_socks5_connect_request(
    request: &[u8],
    mapper: &FakeDnsMapper,
) -> Result<Option<Vec<u8>>, TunBridgeError> {
    if request.len() < 7 {
        return Err(TunBridgeError::MalformedSocks5Request);
    }

    let ver = request[0];
    let cmd = request[1];
    let rsv = request[2];
    let atyp = request[3];

    if ver != 5 {
        return Err(TunBridgeError::MalformedSocks5Request);
    }

    // Only rewrite TCP CONNECT (CMD=1) targeting IPv4 (ATYP=1)
    if cmd != 1 || atyp != SOCKS5_ATYP_IPV4 {
        return Ok(None);
    }

    if request.len() < 10 {
        return Err(TunBridgeError::MalformedSocks5Request);
    }

    let ip = Ipv4Addr::new(request[4], request[5], request[6], request[7]);
    let port_bytes = &request[8..10];

    if let Some(hostname) = mapper.get_hostname(&ip) {
        let host_bytes = hostname.as_bytes();
        if host_bytes.len() > 255 {
            return Ok(None); // Domain exceeds max SOCKS5 length
        }

        let mut rewritten = Vec::with_capacity(7 + host_bytes.len());
        rewritten.push(ver);
        rewritten.push(cmd);
        rewritten.push(rsv);
        rewritten.push(SOCKS5_ATYP_DOMAIN);
        rewritten.push(host_bytes.len() as u8);
        rewritten.extend_from_slice(host_bytes);
        rewritten.extend_from_slice(port_bytes);

        return Ok(Some(rewritten));
    }

    Ok(None)
}

/// TunBridge traffic bandwidth statistics tracker.
#[derive(Debug, Default)]
pub struct TunBridgeStats {
    pub upload_bytes: AtomicU64,
    pub download_bytes: AtomicU64,
}

impl TunBridgeStats {
    pub fn new() -> Self {
        Self {
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
        }
    }

    pub fn add_upload(&self, n: u64) {
        self.upload_bytes.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_download(&self, n: u64) {
        self.download_bytes.fetch_add(n, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.upload_bytes.load(Ordering::Relaxed),
            self.download_bytes.load(Ordering::Relaxed),
        )
    }

    pub fn reset(&self) {
        self.upload_bytes.store(0, Ordering::Relaxed);
        self.download_bytes.store(0, Ordering::Relaxed);
    }
}
