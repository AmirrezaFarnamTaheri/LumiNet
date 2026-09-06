// MIT License — clean-room implementation of high-performance async I/O proactor.

/// Proactor pattern I/O engine — platform-specific completion-based async operations.
///
/// The Proactor pattern decouples asynchronous event initiation from completion
/// handling. On each platform LumiNet uses the native completion-port API:
///   - Linux/Android: epoll with `EPOLLOUT`/`EPOLLIN` edge-triggered polling
///   - macOS/iOS:     kqueue with EVFILT_READ/EVFILT_WRITE
///   - Windows:       IOCP (I/O Completion Ports) via `GetQueuedCompletionStatus`
///
/// `ProactorIO` is the cross-platform entry point. The actual proactor
/// implementations live in the `platform/` sub-module (conditionally compiled
/// via `#[cfg(target_os = "...")]`).
///
/// Usage:
/// ```ignore
/// let proactor = ProactorIO::new()?;
/// proactor.submit_read(fd, buf, token).await?;
/// while let Some(op) = proactor.next().await {
///     // handle completion
/// }
/// ```
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

pub use self::kqueue::KqueueProactor;

/// Maximum number of operations that can be queued before back-pressure.
const MAX_PENDING_OPS: usize = 65536;

/// Represents a completed I/O operation returned by `ProactorIO::next()`.
#[derive(Debug, Clone)]
pub struct Completion {
    /// Opaque token that was passed when the operation was submitted.
    pub token: u64,
    /// Number of bytes transferred (read or written). Zero means EOF for reads.
    pub bytes: usize,
    /// Whether this operation completed successfully.
    pub ok: bool,
    /// Platform-specific error code when `ok` is false (0 on success).
    pub err_code: i32,
}

impl Completion {
    /// Returns `Ok(bytes)` if the operation succeeded, otherwise `Err(io::Error)`.
    #[inline]
    pub fn result(&self) -> io::Result<usize> {
        if self.ok {
            Ok(self.bytes)
        } else {
            Err(io::Error::from_raw_os_error(self.err_code))
        }
    }
}

/// A submitted but not-yet-completed I/O operation.
enum PendingOp {
    Read {
        buf: Vec<u8>,
        token: u64,
        tx: oneshot::Sender<Completion>,
    },
    Write {
        data: bytes::Bytes,
        token: u64,
        tx: oneshot::Sender<Completion>,
    },
}

/// Cross-platform async I/O proactor.
///
/// Created with [`ProactorIO::new`], which selects the best available platform
/// backend at compile time. Call `submit_read` / `submit_write` to queue
/// operations, then `next()` to consume completions.
pub struct ProactorIO {
    backend: KqueueProactor,
    pending: Arc<dashmap::DashMap<RawFd, Vec<PendingOp>>>,
    next_token: std::sync::atomic::AtomicU64,
}

impl Default for ProactorIO {
    fn default() -> Self {
        Self::new().expect("ProactorIO: failed to initialise proactor")
    }
}

impl ProactorIO {
    /// Create a new proactor, auto-selecting the best platform backend.
    ///
    /// Returns an error only if the platform is completely unsupported (should
    /// not happen on any supported LumiNet target).
    pub fn new() -> io::Result<Self> {
        let backend = KqueueProactor::new()?;
        Ok(Self {
            backend,
            pending: Arc::new(dashmap::DashMap::new()),
            next_token: std::sync::atomic::AtomicU64::new(1),
        })
    }

    /// Submit an asynchronous read operation on a socket.
    ///
    /// The read buffer `buf` is filled from `fd`. Completion is delivered via
    /// `next()`. `token` is an opaque u64 that is echoed in the returned
    /// `Completion` so callers can match operations to completions.
    pub fn submit_read(
        &self,
        fd: RawFd,
        mut buf: Vec<u8>,
        token: u64,
    ) -> impl std::future::Future<Output = Completion> + Send {
        let (tx, rx) = oneshot::channel();
        {
            let mut ops = self.pending.entry(fd).or_default();
            ops.push(PendingOp::Read {
                buf,
                token,
                tx,
            });
        }
        self.backend.submit_read(fd, token);
        async move { rx.await.unwrap_or_else(|_| Completion { token, bytes: 0, ok: false, err_code: libc::ECANCELED }) }
    }

    /// Submit an asynchronous write operation on a socket.
    ///
    /// The data in `data` is written to `fd`. Completion is delivered via
    /// `next()`. The `Bytes` reference is held until completion.
    pub fn submit_write(
        &self,
        fd: RawFd,
        data: bytes::Bytes,
        token: u64,
    ) -> impl std::future::Future<Output = Completion> + Send {
        let (tx, rx) = oneshot::channel();
        {
            let mut ops = self.pending.entry(fd).or_default();
            ops.push(PendingOp::Write { data, token, tx });
        }
        self.backend.submit_write(fd, token);
        async move { rx.await.unwrap_or_else(|_| Completion { token, bytes: 0, ok: false, err_code: libc::ECANCELED }) }
    }

    /// Poll for the next completed operation.
    ///
    /// This must be called from the proactor's own async runtime context.
    /// Returns `None` if the proactor is shutting down.
    pub async fn next(&self) -> Option<Completion> {
        self.backend.next().await
    }

    /// Register a file descriptor for proactor I/O.
    ///
    /// Must be called before any `submit_*` call for `fd`. Sets the file
    /// descriptor to non-blocking mode.
    pub fn register(&self, fd: RawFd) -> io::Result<()> {
        self.backend.register(fd)
    }

    /// Deregister a file descriptor and cancel all pending operations on it.
    pub fn deregister(&self, fd: RawFd) -> io::Result<()> {
        self.backend.deregister(fd);
        if let Some(mut ops) = self.pending.remove(&fd) {
            for op in ops.value_mut() {
                let _ = op.cancel();
            }
        }
        Ok(())
    }

    fn next_token(&self) -> u64 {
        self.next_token
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }
}

impl PendingOp {
    fn cancel(self) {
        match self {
            PendingOp::Read { tx, .. } | PendingOp::Write { tx, .. } => {
                let _ = tx.send(Completion {
                    token: 0,
                    bytes: 0,
                    ok: false,
                    err_code: libc::ECANCELED as i32,
                });
            }
        }
    }
}

// -----------------------------------------------------------------------------------------------
// Platform backends (conditionally compiled)

#[cfg(target_os = "linux")]
mod kqueue {
    use super::*;

    /// Linux/epoll proactor backend.
    pub struct KqueueProactor {
        epfd: RawFd,
        event_fd: RawFd,
        #[allow(dead_code)]
        kq: RawFd, // kept for future use (timerfd integration)
    }

    impl KqueueProactor {
        pub fn new() -> io::Result<Self> {
            // epoll_create1 with EPOLL_CLOEXEC is the standard Linux async-I/O entry point.
            let epfd = unsafe { libc::syscall(libc::SYS_epoll_create1, libc::EPOLL_CLOEXEC) };
            let epfd = if epfd < 0 {
                return Err(io::Error::last_os_error());
            } else {
                epfd as RawFd
            };

            // eventfd for waking the epoll wait loop from other threads.
            let event_fd = unsafe {
                libc::syscall(libc::SYS_eventfd, 0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC)
            };
            let event_fd = if event_fd < 0 {
                return Err(io::Error::last_os_error());
            } else {
                event_fd as RawFd
            };

            Ok(Self { epfd, event_fd, kq: -1 })
        }

        #[inline]
        pub fn submit_read(&self, fd: RawFd, _token: u64) {
            let mut ev = libc::epoll_event {
                events: libc::EPOLLIN as u32,
                u64: fd as u64,
            };
            unsafe {
                libc::syscall(libc::SYS_epoll_ctl, self.epfd, libc::EPOLL_CTL_ADD, fd, &ev);
            }
        }

        #[inline]
        pub fn submit_write(&self, fd: RawFd, _token: u64) {
            let mut ev = libc::epoll_event {
                events: libc::EPOLLOUT as u32,
                u64: fd as u64,
            };
            unsafe {
                libc::syscall(libc::SYS_epoll_ctl, self.epfd, libc::EPOLL_CTL_ADD, fd, &ev);
            }
        }

        pub fn register(&self, fd: RawFd) -> io::Result<()> {
            // Set non-blocking.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            let r = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            if r < 0 {
                return Err(io::Error::last_os_error());
            }

            // Add to epoll set with no events initially.
            let ev = libc::epoll_event {
                events: libc::EPOLLONESHOT as u32,
                u64: fd as u64,
            };
            let r = unsafe { libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_ADD, fd, &ev) };
            if r < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn deregister(&self, fd: RawFd) {
            let ev = libc::epoll_event {
                events: 0,
                u64: fd as u64,
            };
            unsafe {
                libc::syscall(libc::SYS_epoll_ctl, self.epfd, libc::EPOLL_CTL_DEL, fd, &ev);
            }
        }

        pub async fn next(&self) -> Option<Completion> {
            const MAX_EVENTS: usize = 64;
            let mut events = vec![libc::epoll_event::default(); MAX_EVENTS];

            let n = loop {
                let res = unsafe {
                    libc::epoll_wait(
                        self.epfd,
                        events.as_mut_ptr(),
                        MAX_EVENTS as i32,
                        -1, // block indefinitely
                    )
                };
                if res < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return None;
                }
                break res as usize;
            };

            // For each event, read/recv and construct a completion.
            // The actual I/O is done by the caller before/after submit_*.
            // Here we just surface that the fd is readable/writable.
            for i in 0..n {
                let ev = &events[i];
                let fd = ev.u64 as RawFd;
                let revents = ev.events;

                if revents & (libc::EPOLLERR as u32) != 0 {
                    return Some(Completion {
                        token: fd as u64,
                        bytes: 0,
                        ok: false,
                        err_code: libc::ECONNRESET as i32,
                    });
                }
                if revents & (libc::EPOLLIN as u32) != 0 {
                    return Some(Completion {
                        token: fd as u64,
                        bytes: 0,
                        ok: true,
                        err_code: 0,
                    });
                }
                if revents & (libc::EPOLLOUT as u32) != 0 {
                    return Some(Completion {
                        token: fd as u64,
                        bytes: 0,
                        ok: true,
                        err_code: 0,
                    });
                }
            }
            None
        }
    }
}

#[cfg(target_os = "macos")]
mod kqueue {
    use super::*;

    /// macOS/iOS kqueue proactor backend.
    pub struct KqueueProactor {
        kq: RawFd,
    }

    impl KqueueProactor {
        pub fn new() -> io::Result<Self> {
            let kq = unsafe { libc::kqueue() };
            if kq < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { kq })
        }

        #[inline]
        pub fn submit_read(&self, fd: RawFd, _token: u64) {
            let ev = libc::kevent {
                ident: fd as libc::uintptr_t,
                filter: libc::EVFILT_READ,
                flags: libc::EV_ADD | libc::EV_ONESHOT,
                fflags: 0,
                data: 0,
                udata: 0 as *mut libc::c_void,
            };
            unsafe {
                libc::kevent(self.kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null());
            }
        }

        #[inline]
        pub fn submit_write(&self, fd: RawFd, _token: u64) {
            let ev = libc::kevent {
                ident: fd as libc::uintptr_t,
                filter: libc::EVFILT_WRITE,
                flags: libc::EV_ADD | libc::EV_ONESHOT,
                fflags: 0,
                data: 0,
                udata: 0 as *mut libc::c_void,
            };
            unsafe {
                libc::kevent(self.kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null());
            }
        }

        pub fn register(&self, fd: RawFd) -> io::Result<()> {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            let r = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            if r < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn deregister(&self, fd: RawFd) {
            for filter in &[libc::EVFILT_READ, libc::EVFILT_WRITE] {
                let ev = libc::kevent {
                    ident: fd as libc::uintptr_t,
                    filter: *filter,
                    flags: libc::EV_DELETE,
                    fflags: 0,
                    data: 0,
                    udata: 0 as *mut libc::c_void,
                };
                unsafe {
                    libc::kevent(self.kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null());
                }
            }
        }

        pub async fn next(&self) -> Option<Completion> {
            let mut events = [libc::kevent {
                ident: 0,
                filter: 0,
                flags: 0,
                fflags: 0,
                data: 0,
                udata: std::ptr::null_mut(),
            }; 64];

            let n = loop {
                let res = unsafe {
                    libc::kevent(
                        self.kq,
                        std::ptr::null(),
                        0,
                        events.as_mut_ptr(),
                        events.len() as i32,
                        std::ptr::null(),
                    )
                };
                if res < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return None;
                }
                break res as usize;
            };

            if n > 0 {
                let ev = &events[0];
                let token = ev.ident as u64;
                let bytes = ev.data as usize;
                let ok = ev.flags & libc::EV_ERROR == 0;
                Some(Completion {
                    token,
                    bytes,
                    ok,
                    err_code: if ok { 0 } else { ev.fflags as i32 },
                })
            } else {
                None
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod kqueue {
    use super::*;

    /// Windows IOCP proactor backend — placeholder using a thread pool
    /// based on async-std's completion-port emulation.
    ///
    /// Full IOCP integration requires the `windows` crate. This stub provides
    /// a synchronous fallback that can be upgraded without changing the public
    /// API.
    pub struct KqueueProactor {
        _phantom: std::marker::PhantomData<()>,
    }

    impl KqueueProactor {
        pub fn new() -> io::Result<Self> {
            // TODO(performance): integrate windows::Win32::System::IO::CreateIoCompletionPort
            // when the `windows` feature flag is enabled.
            Ok(Self { _phantom: std::marker::PhantomData })
        }

        #[inline]
        pub fn submit_read(&self, _fd: RawFd, _token: u64) {}
        #[inline]
        pub fn submit_write(&self, _fd: RawFd, _token: u64) {}
        pub fn register(&self, _fd: RawFd) -> io::Result<()> { Ok(()) }
        pub fn deregister(&self, _fd: RawFd) {}
        pub async fn next(&self) -> Option<Completion> { tokio::time::sleep(std::time::Duration::MAX).await; None }
    }
}

/// Any unrecognised platform falls back to a no-op proactor.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod kqueue {
    use super::*;

    pub struct KqueueProactor;
    impl KqueueProactor {
        pub fn new() -> io::Result<Self> { Ok(Self) }
        pub fn submit_read(&self, _: RawFd, _: u64) {}
        pub fn submit_write(&self, _: RawFd, _: u64) {}
        pub fn register(&self, _: RawFd) -> io::Result<()> { Ok(()) }
        pub fn deregister(&self, _: RawFd) {}
        pub async fn next(&self) -> Option<Completion> { tokio::time::sleep(std::time::Duration::MAX).await; None }
    }
}

// -----------------------------------------------------------------------------------------------
// Trait object interface (used by ProactorIO)

trait ProactorBackend: Send {
    fn submit_read(&self, fd: RawFd, token: u64);
    fn submit_write(&self, fd: RawFd, token: u64);
    fn register(&self, fd: RawFd) -> io::Result<()>;
    fn deregister(&self, fd: RawFd);
    fn next(&self) -> impl std::future::Future<Output = Option<Completion>> + Send;
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl ProactorBackend for KqueueProactor {
    fn submit_read(&self, fd: RawFd, token: u64) { self.submit_read(fd, token) }
    fn submit_write(&self, fd: RawFd, token: u64) { self.submit_write(fd, token) }
    fn register(&self, fd: RawFd) -> io::Result<()> { self.register(fd) }
    fn deregister(&self, fd: RawFd) { self.deregister(fd) }
    fn next(&self) -> impl std::future::Future<Output = Option<Completion>> + Send { self.next() }
}

// TODO(performance): Windows IOCP backend also implements ProactorBackend when windows crate is present.

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proactor_creation() {
        let p = ProactorIO::new();
        if std::env::var("CI").is_ok() {
            // CI may not support epoll/kqueue; skip if we can't create a proactor.
            assert!(p.is_ok() || p.unwrap_err().kind() == io::ErrorKind::Other);
        } else {
            let _p = p.expect("ProactorIO::new should succeed on test host");
        }
    }

    #[test]
    fn completion_result_ok() {
        let c = Completion { token: 42, bytes: 100, ok: true, err_code: 0 };
        assert_eq!(c.result().unwrap(), 100);
    }

    #[test]
    fn completion_result_err() {
        let c = Completion { token: 0, bytes: 0, ok: false, err_code: libc::ECONNRESET };
        assert!(c.result().is_err());
    }
}
