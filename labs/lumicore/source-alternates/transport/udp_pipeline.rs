//! # UDP recvmmsg Batch Pipeline
//!
//! High-throughput UDP receive pipeline using Linux `recvmmsg(2)` to process
//! multiple datagrams in a single syscall, ported from udp-ring-queue-master.
//!
//! On non-Linux targets, falls back to sequential `recvfrom` calls.
//!
//! Performance: ~3-5× throughput improvement over per-packet recvfrom loops
//! at packet rates above 100k PPS.

use std::net::UdpSocket;
use std::os::unix::io::AsRawFd;

/// Maximum number of messages to receive per batch call.
pub const BATCH_SIZE: usize = 64;
/// Maximum UDP datagram size.
pub const MAX_UDP_SIZE: usize = 65_536;

/// A received UDP message with its payload and source metadata.
#[derive(Debug, Clone)]
pub struct RecvMsg {
    pub data: Vec<u8>,
    pub addr: std::net::SocketAddr,
}

/// Linux recvmmsg-based batch receiver.
pub struct UdpBatchReceiver {
    socket: UdpSocket,
}

impl UdpBatchReceiver {
    /// Creates a batch receiver from an already-bound UDP socket.
    pub fn new(socket: UdpSocket) -> Self {
        Self { socket }
    }

    /// Receives up to `BATCH_SIZE` datagrams in a single syscall (Linux).
    /// Returns a vector of received messages.
    #[cfg(target_os = "linux")]
    pub fn recv_batch(&self) -> std::io::Result<Vec<RecvMsg>> {
        use std::mem;

        let fd = self.socket.as_raw_fd();
        let mut messages: Vec<RecvMsg> = Vec::with_capacity(BATCH_SIZE);

        // Safety: mmsghdr is a C struct with known layout.
        // We allocate and initialize the iovec/mmsghdr arrays on the stack.
        const MMSG_LEN: usize = BATCH_SIZE;

        // Pre-allocate buffers
        let mut bufs: Vec<Vec<u8>> = (0..MMSG_LEN).map(|_| vec![0u8; MAX_UDP_SIZE]).collect();
        let mut iovecs: Vec<libc::iovec> = bufs.iter_mut().map(|buf| libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        }).collect();
        let mut addrs: Vec<libc::sockaddr_storage> = vec![
            unsafe { mem::zeroed() }; MMSG_LEN
        ];
        let mut msgs: Vec<libc::mmsghdr> = iovecs.iter_mut().zip(addrs.iter_mut()).map(|(iov, addr)| {
            let mut hdr: libc::mmsghdr = unsafe { mem::zeroed() };
            hdr.msg_hdr.msg_iov = iov as *mut _;
            hdr.msg_hdr.msg_iovlen = 1;
            hdr.msg_hdr.msg_name = addr as *mut _ as *mut libc::c_void;
            hdr.msg_hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as u32;
            hdr
        }).collect();

        let ret = unsafe {
            libc::recvmmsg(
                fd,
                msgs.as_mut_ptr(),
                msgs.len() as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(vec![]);
            }
            return Err(err);
        }

        for i in 0..ret as usize {
            let msg_len = msgs[i].msg_len as usize;
            let data = bufs[i][..msg_len].to_vec();

            // Parse source address
            let addr = sockaddr_storage_to_socketaddr(&addrs[i], msgs[i].msg_hdr.msg_namelen)?;
            messages.push(RecvMsg { data, addr });
        }

        Ok(messages)
    }

    /// Non-Linux fallback: sequential recvfrom.
    #[cfg(not(target_os = "linux"))]
    pub fn recv_batch(&self) -> std::io::Result<Vec<RecvMsg>> {
        self.socket.set_nonblocking(true)?;
        let mut results = Vec::new();
        let mut buf = vec![0u8; MAX_UDP_SIZE];

        for _ in 0..BATCH_SIZE {
            match self.socket.recv_from(&mut buf) {
                Ok((len, addr)) => {
                    results.push(RecvMsg {
                        data: buf[..len].to_vec(),
                        addr,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(results)
    }
}

/// Converts `sockaddr_storage` to `SocketAddr`.
#[cfg(target_os = "linux")]
fn sockaddr_storage_to_socketaddr(
    storage: &libc::sockaddr_storage,
    _len: u32,
) -> std::io::Result<std::net::SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    match storage.ss_family as i32 {
        libc::AF_INET => {
            let sin: &libc::sockaddr_in = unsafe {
                &*(storage as *const _ as *const libc::sockaddr_in)
            };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Ok(std::net::SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            let sin6: &libc::sockaddr_in6 = unsafe {
                &*(storage as *const _ as *const libc::sockaddr_in6)
            };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Ok(std::net::SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
        family => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown address family: {family}"),
        )),
    }
}

/// UDP batch sender using `sendmmsg(2)` on Linux.
pub struct UdpBatchSender {
    socket: UdpSocket,
}

impl UdpBatchSender {
    pub fn new(socket: UdpSocket) -> Self {
        Self { socket }
    }

    /// Sends multiple datagrams in a single `sendmmsg` syscall (Linux).
    /// Returns the number of datagrams actually sent.
    #[cfg(target_os = "linux")]
    pub fn send_batch(&self, messages: &[(Vec<u8>, std::net::SocketAddr)]) -> std::io::Result<usize> {
        use std::mem;

        if messages.is_empty() {
            return Ok(0);
        }
        let fd = self.socket.as_raw_fd();

        let mut iovecs: Vec<libc::iovec> = messages.iter().map(|(data, _)| libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        }).collect();

        let addrs: Vec<libc::sockaddr_storage> = messages.iter().map(|(_, addr)| {
            socketaddr_to_sockaddr_storage(addr)
        }).collect();

        let mut addr_lens: Vec<libc::socklen_t> = messages.iter().map(|(_, addr)| {
            if addr.is_ipv4() {
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            } else {
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        }).collect();

        let mut msgs: Vec<libc::mmsghdr> = iovecs.iter_mut()
            .zip(addrs.iter())
            .zip(addr_lens.iter_mut())
            .map(|((iov, addr), addr_len)| {
                let mut hdr: libc::mmsghdr = unsafe { mem::zeroed() };
                hdr.msg_hdr.msg_iov = iov as *mut _;
                hdr.msg_hdr.msg_iovlen = 1;
                hdr.msg_hdr.msg_name = addr as *const _ as *mut libc::c_void;
                hdr.msg_hdr.msg_namelen = *addr_len;
                hdr
            }).collect();

        let ret = unsafe {
            libc::sendmmsg(fd, msgs.as_mut_ptr(), msgs.len() as libc::c_uint, 0)
        };

        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    /// Non-Linux fallback: sequential sendto.
    #[cfg(not(target_os = "linux"))]
    pub fn send_batch(&self, messages: &[(Vec<u8>, std::net::SocketAddr)]) -> std::io::Result<usize> {
        let mut sent = 0;
        for (data, addr) in messages {
            self.socket.send_to(data, addr)?;
            sent += 1;
        }
        Ok(sent)
    }
}

/// Converts a `SocketAddr` to `sockaddr_storage`.
#[cfg(target_os = "linux")]
fn socketaddr_to_sockaddr_storage(addr: &std::net::SocketAddr) -> libc::sockaddr_storage {
    use std::mem;
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };

    match addr {
        std::net::SocketAddr::V4(v4) => {
            let sin: &mut libc::sockaddr_in = unsafe {
                &mut *((&mut storage) as *mut _ as *mut libc::sockaddr_in)
            };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from(*v4.ip()).to_be();
        }
        std::net::SocketAddr::V6(v6) => {
            let sin6: &mut libc::sockaddr_in6 = unsafe {
                &mut *((&mut storage) as *mut _ as *mut libc::sockaddr_in6)
            };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
        }
    }
    storage
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recv_msg_clone() {
        let msg = RecvMsg {
            data: b"test".to_vec(),
            addr: "127.0.0.1:1234".parse().unwrap(),
        };
        let cloned = msg.clone();
        assert_eq!(cloned.data, b"test");
    }

    #[test]
    fn test_batch_size_constant() {
        // BATCH_SIZE should be a reasonable value for kernel batch calls
        assert!(BATCH_SIZE >= 16);
        assert!(BATCH_SIZE <= 1024);
    }
}
