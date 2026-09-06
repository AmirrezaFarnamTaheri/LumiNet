//! # Socket Protector Platform Hook
//!
//! Provides a thread-safe hook allowing mobile and operating system VPN services
//! (such as Android VpnService.protect, iOS PacketTunnelProvider, and Linux SO_MARK)
//! to protect outbound sockets created by the daemon from being looped back into
//! the local TUN interface.

use std::sync::{Arc, OnceLock, RwLock};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SocketProtectError {
    #[error("socket protector lock was poisoned")]
    LockPoisoned,
    #[error("platform VPN service rejected socket fd {0}")]
    Rejected(i32),
}

pub type SocketProtector = Arc<dyn Fn(i32) -> bool + Send + Sync + 'static>;

fn global_protector() -> &'static RwLock<Option<SocketProtector>> {
    static PROTECTOR: OnceLock<RwLock<Option<SocketProtector>>> = OnceLock::new();
    PROTECTOR.get_or_init(|| RwLock::new(None))
}

/// Sets or clears the active platform socket protector callback.
pub fn set_socket_protector(callback: Option<SocketProtector>) {
    if let Ok(mut current) = global_protector().write() {
        *current = callback;
    }
}

/// Returns true if a platform socket protector callback is currently registered.
pub fn is_protector_registered() -> bool {
    global_protector()
        .read()
        .map(|guard| guard.is_some())
        .unwrap_or(false)
}

/// Protects a raw file descriptor from being routed back into the local VPN tunnel.
pub fn protect_socket_fd(fd: i32) -> Result<(), SocketProtectError> {
    let callback = global_protector()
        .read()
        .map_err(|_| SocketProtectError::LockPoisoned)?
        .clone();

    if let Some(cb) = callback {
        if !cb(fd) {
            return Err(SocketProtectError::Rejected(fd));
        }
    }

    Ok(())
}

#[cfg(unix)]
pub fn protect_socket<T: std::os::fd::AsRawFd>(socket: &T) -> Result<(), SocketProtectError> {
    protect_socket_fd(socket.as_raw_fd())
}

#[cfg(not(unix))]
pub fn protect_socket<T>(_socket: &T) -> Result<(), SocketProtectError> {
    // Windows/non-unix platform fallback
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

    #[test]
    fn test_socket_protector_lifecycle() {
        assert!(!is_protector_registered());
        assert!(protect_socket_fd(42).is_ok());

        let last_fd = Arc::new(AtomicI32::new(0));
        let should_pass = Arc::new(AtomicBool::new(true));

        let last_fd_clone = Arc::clone(&last_fd);
        let should_pass_clone = Arc::clone(&should_pass);

        set_socket_protector(Some(Arc::new(move |fd| {
            last_fd_clone.store(fd, Ordering::SeqCst);
            should_pass_clone.load(Ordering::SeqCst)
        })));

        assert!(is_protector_registered());

        // Test successful protection
        assert!(protect_socket_fd(100).is_ok());
        assert_eq!(last_fd.load(Ordering::SeqCst), 100);

        // Test rejected socket
        should_pass.store(false, Ordering::SeqCst);
        let err = protect_socket_fd(101).unwrap_err();
        assert_eq!(err, SocketProtectError::Rejected(101));
        assert_eq!(last_fd.load(Ordering::SeqCst), 101);

        // Clear protector
        set_socket_protector(None);
        assert!(!is_protector_registered());
        assert!(protect_socket_fd(102).is_ok());
    }
}
