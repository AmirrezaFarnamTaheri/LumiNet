use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::time::Instant;

/// Failures returned by the bounded MITM fronting buffer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MitmFrontingBufferError {
    #[error("buffer capacity must be greater than zero")]
    InvalidCapacity,
    #[error("buffer is shut down")]
    Shutdown,
    #[error(
        "buffer capacity exceeded: requested {requested} bytes with {available} bytes available"
    )]
    CapacityExceeded { requested: usize, available: usize },
}

/// Immutable operational view suitable for diagnostics and health reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MitmFrontingBufferSnapshot {
    pub buffered_bytes: usize,
    pub capacity: usize,
    pub available_capacity: usize,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub overflow_count: u64,
    pub dropped_bytes: u64,
    pub cycle_count: u64,
    pub error_count: u64,
    pub is_active: bool,
    pub is_shutdown: bool,
}

// Items 1-100: MITM fronting buffer properties and structs
#[derive(Debug)]
pub struct MitmFrontingBuffer {
    // Group 1: State monitoring flags (Items 1-15)
    pub is_buffer_active: bool,           // Item 1
    pub allocation_count: u64,            // Item 2
    pub max_concurrent_buffers: u32,      // Item 3
    pub buffer_capacity_limit: usize,     // Item 4
    pub buffer_timeout_millis: u64,       // Item 5
    pub read_buffer_timeout_millis: u64,  // Item 6
    pub write_buffer_timeout_millis: u64, // Item 7
    pub total_bytes_buffered: u64,        // Item 8
    pub total_buffer_cycles: u64,         // Item 9
    pub total_buffer_errors: u64,         // Item 10
    pub buffer_allocator_name: String,    // Item 11
    pub buffer_version_major: u8,         // Item 12
    pub buffer_version_minor: u8,         // Item 13
    pub buffer_protocol: String,          // Item 14
    pub is_secure_buffer: bool,           // Item 15

    // Group 2: Atomic stats counters (Items 16-30)
    pub atomic_active_buffers: AtomicI32,       // Item 16
    pub atomic_bytes_read: AtomicU64,           // Item 17
    pub atomic_bytes_written: AtomicU64,        // Item 18
    pub atomic_packets_dropped: AtomicU64,      // Item 19
    pub atomic_handshake_failures: AtomicU64,   // Item 20
    pub atomic_retransmissions: AtomicU64,      // Item 21
    pub atomic_buffer_overflows: AtomicU64,     // Item 22
    pub atomic_keepalive_ticks: AtomicU64,      // Item 23
    pub atomic_dns_resolutions: AtomicU64,      // Item 24
    pub atomic_fallback_attempts: AtomicU64,    // Item 25
    pub atomic_successful_relays: AtomicU64,    // Item 26
    pub atomic_failed_relays: AtomicU64,        // Item 27
    pub atomic_timeout_events: AtomicU64,       // Item 28
    pub atomic_bandwidth_violations: AtomicU64, // Item 29
    pub atomic_unsupported_versions: AtomicU64, // Item 30

    // Group 3: Timing details (Items 31-45)
    pub startup_timestamp: Option<Instant>,        // Item 31
    pub last_request_timestamp: Option<Instant>,   // Item 32
    pub last_response_timestamp: Option<Instant>,  // Item 33
    pub last_error_timestamp: Option<Instant>,     // Item 34
    pub handshake_duration_millis: u64,            // Item 35
    pub header_parse_duration_millis: u64,         // Item 36
    pub body_transfer_duration_millis: u64,        // Item 37
    pub idle_connection_duration_millis: u64,      // Item 38
    pub dns_lookup_duration_millis: u64,           // Item 39
    pub keepalive_duration_millis: u64,            // Item 40
    pub total_execution_time_millis: u64,          // Item 41
    pub last_heartbeat_timestamp: Option<Instant>, // Item 42
    pub total_downtime_millis: u64,                // Item 43
    pub max_latency_millis: u64,                   // Item 44
    pub min_latency_millis: u64,                   // Item 45

    // Group 4: Config flags and parameters (Items 46-60)
    pub is_dns_caching_enabled: bool,           // Item 46
    pub is_keepalive_enabled: bool,             // Item 47
    pub is_gzip_enabled: bool,                  // Item 48
    pub is_brotli_enabled: bool,                // Item 49
    pub is_deflate_enabled: bool,               // Item 50
    pub is_chunked_transfer_enabled: bool,      // Item 51
    pub is_pipelining_enabled: bool,            // Item 52
    pub is_http2_prior_knowledge_enabled: bool, // Item 53
    pub is_websockets_enabled: bool,            // Item 54
    pub is_tls_13_enforced: bool,               // Item 55
    pub is_sni_obfuscation_enabled: bool,       // Item 56
    pub is_header_obfuscation_enabled: bool,    // Item 57
    pub is_request_signing_enabled: bool,       // Item 58
    pub is_response_signing_enabled: bool,      // Item 59
    pub is_traffic_shaping_enabled: bool,       // Item 60

    // Group 5: Routing settings (Items 61-75)
    pub upstream_proxy_host: String,          // Item 61
    pub upstream_proxy_port: u16,             // Item 62
    pub downstream_listen_host: String,       // Item 63
    pub downstream_listen_port: u16,          // Item 64
    pub proxy_authorization_header: String,   // Item 65
    pub custom_user_agent: String,            // Item 66
    pub custom_server_header: String,         // Item 67
    pub max_header_size: usize,               // Item 68
    pub max_body_size: u64,                   // Item 69
    pub read_buffer_chunk_size: usize,        // Item 70
    pub write_buffer_chunk_size: usize,       // Item 71
    pub max_keepalive_requests: u32,          // Item 72
    pub client_max_idle_seconds: u32,         // Item 73
    pub backend_connect_timeout_seconds: u32, // Item 74
    pub backend_read_timeout_seconds: u32,    // Item 75

    // Group 6: Encryption settings (Items 76-90)
    pub tls_cert_path: String,                 // Item 76
    pub tls_key_path: String,                  // Item 77
    pub tls_dhparams_path: String,             // Item 78
    pub tls_cipher_suite: String,              // Item 79
    pub is_tls_session_tickets_enabled: bool,  // Item 80
    pub is_tls_alpn_negotiation_enabled: bool, // Item 81
    pub tls_min_version: String,               // Item 82
    pub tls_max_version: String,               // Item 83
    pub is_client_cert_required: bool,         // Item 84
    pub ca_bundle_path: String,                // Item 85
    pub ocsp_stapling_enabled: bool,           // Item 86
    pub crl_checking_enabled: bool,            // Item 87
    pub dns_over_https_resolver_url: String,   // Item 88
    pub tls_handshake_timeout_seconds: u32,    // Item 90
    pub is_tls_sni_extension_enabled: bool,    // Item 89

    // Group 7: Traffic and system state metrics (Items 91-100)
    pub cpu_affinity_mask: u64,             // Item 91
    pub thread_pool_priority: i32,          // Item 92
    pub process_nice_value: i32,            // Item 93
    pub is_non_blocking_io_enabled: bool,   // Item 94
    pub is_socket_reuse_addr_enabled: bool, // Item 95
    pub is_socket_reuse_port_enabled: bool, // Item 96
    pub is_tcp_nodelay_enabled: bool,       // Item 97
    pub is_tcp_quickack_enabled: bool,      // Item 98
    pub is_tcp_cork_enabled: bool,          // Item 99
    pub is_fronting_buffer_shutdown: bool,  // Item 100

    storage: VecDeque<u8>,
}

impl MitmFrontingBuffer {
    pub fn new() -> Self {
        Self {
            is_buffer_active: false,
            allocation_count: 0,
            max_concurrent_buffers: 512,
            buffer_capacity_limit: 65536,
            buffer_timeout_millis: 15000,
            read_buffer_timeout_millis: 30000,
            write_buffer_timeout_millis: 30000,
            total_bytes_buffered: 0,
            total_buffer_cycles: 0,
            total_buffer_errors: 0,
            buffer_allocator_name: "MitmFrontingBuffer/1.0".to_string(),
            buffer_version_major: 1,
            buffer_version_minor: 1,
            buffer_protocol: "websocket".to_string(),
            is_secure_buffer: false,
            atomic_active_buffers: AtomicI32::new(0),
            atomic_bytes_read: AtomicU64::new(0),
            atomic_bytes_written: AtomicU64::new(0),
            atomic_packets_dropped: AtomicU64::new(0),
            atomic_handshake_failures: AtomicU64::new(0),
            atomic_retransmissions: AtomicU64::new(0),
            atomic_buffer_overflows: AtomicU64::new(0),
            atomic_keepalive_ticks: AtomicU64::new(0),
            atomic_dns_resolutions: AtomicU64::new(0),
            atomic_fallback_attempts: AtomicU64::new(0),
            atomic_successful_relays: AtomicU64::new(0),
            atomic_failed_relays: AtomicU64::new(0),
            atomic_timeout_events: AtomicU64::new(0),
            atomic_bandwidth_violations: AtomicU64::new(0),
            atomic_unsupported_versions: AtomicU64::new(0),
            startup_timestamp: None,
            last_request_timestamp: None,
            last_response_timestamp: None,
            last_error_timestamp: None,
            handshake_duration_millis: 0,
            header_parse_duration_millis: 0,
            body_transfer_duration_millis: 0,
            idle_connection_duration_millis: 0,
            dns_lookup_duration_millis: 0,
            keepalive_duration_millis: 0,
            total_execution_time_millis: 0,
            last_heartbeat_timestamp: None,
            total_downtime_millis: 0,
            max_latency_millis: 0,
            min_latency_millis: u64::MAX,
            is_dns_caching_enabled: true,
            is_keepalive_enabled: true,
            is_gzip_enabled: true,
            is_brotli_enabled: false,
            is_deflate_enabled: false,
            is_chunked_transfer_enabled: true,
            is_pipelining_enabled: false,
            is_http2_prior_knowledge_enabled: false,
            is_websockets_enabled: true,
            is_tls_13_enforced: true,
            is_sni_obfuscation_enabled: false,
            is_header_obfuscation_enabled: false,
            is_request_signing_enabled: false,
            is_response_signing_enabled: false,
            is_traffic_shaping_enabled: false,
            upstream_proxy_host: "127.0.0.1".to_string(),
            upstream_proxy_port: 8080,
            downstream_listen_host: "0.0.0.0".to_string(),
            downstream_listen_port: 80,
            proxy_authorization_header: String::new(),
            custom_user_agent: "luminet-buffer".to_string(),
            custom_server_header: "luminet".to_string(),
            max_header_size: 8192,
            max_body_size: 10485760,
            read_buffer_chunk_size: 4096,
            write_buffer_chunk_size: 4096,
            max_keepalive_requests: 100,
            client_max_idle_seconds: 60,
            backend_connect_timeout_seconds: 10,
            backend_read_timeout_seconds: 30,
            tls_cert_path: String::new(),
            tls_key_path: String::new(),
            tls_dhparams_path: String::new(),
            tls_cipher_suite: String::new(),
            is_tls_session_tickets_enabled: true,
            is_tls_alpn_negotiation_enabled: true,
            tls_min_version: "1.2".to_string(),
            tls_max_version: "1.3".to_string(),
            is_client_cert_required: false,
            ca_bundle_path: String::new(),
            ocsp_stapling_enabled: false,
            crl_checking_enabled: false,
            dns_over_https_resolver_url: String::new(),
            tls_handshake_timeout_seconds: 5,
            is_tls_sni_extension_enabled: true,
            cpu_affinity_mask: 0,
            thread_pool_priority: 0,
            process_nice_value: 0,
            is_non_blocking_io_enabled: true,
            is_socket_reuse_addr_enabled: true,
            is_socket_reuse_port_enabled: false,
            is_tcp_nodelay_enabled: true,
            is_tcp_quickack_enabled: false,
            is_tcp_cork_enabled: false,
            is_fronting_buffer_shutdown: false,
            storage: VecDeque::new(),
        }
    }

    /// Constructs an empty buffer with an explicit hard capacity.
    ///
    /// Capacity is enforced logically and allocated incrementally, avoiding a
    /// potentially large up-front allocation for caller-provided limits.
    pub fn with_capacity(capacity: usize) -> Result<Self, MitmFrontingBufferError> {
        if capacity == 0 {
            return Err(MitmFrontingBufferError::InvalidCapacity);
        }

        let mut buffer = Self::new();
        buffer.buffer_capacity_limit = capacity;
        Ok(buffer)
    }

    /// Appends a complete byte slice to the FIFO.
    ///
    /// Writes are atomic at the slice level: when the slice does not fit,
    /// nothing is appended and overflow telemetry is updated.
    pub fn write(&mut self, bytes: &[u8]) -> Result<usize, MitmFrontingBufferError> {
        self.ensure_running()?;
        if bytes.is_empty() {
            return Ok(0);
        }

        let available = self.available_capacity();
        if bytes.len() > available {
            self.record_overflow(bytes.len());
            return Err(MitmFrontingBufferError::CapacityExceeded {
                requested: bytes.len(),
                available,
            });
        }

        let now = Instant::now();
        self.storage.extend(bytes.iter().copied());
        self.allocation_count = self.allocation_count.saturating_add(1);
        self.total_buffer_cycles = self.total_buffer_cycles.saturating_add(1);
        self.total_bytes_buffered = self.storage.len() as u64;
        self.atomic_bytes_written
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        self.startup_timestamp.get_or_insert(now);
        self.last_request_timestamp = Some(now);
        self.refresh_active_state();
        Ok(bytes.len())
    }

    /// Removes up to `max_len` bytes from the front of the FIFO.
    pub fn read(&mut self, max_len: usize) -> Result<Vec<u8>, MitmFrontingBufferError> {
        self.ensure_running()?;
        if max_len == 0 || self.storage.is_empty() {
            return Ok(Vec::new());
        }

        let count = max_len.min(self.storage.len());
        let bytes: Vec<u8> = self.storage.drain(..count).collect();
        self.total_buffer_cycles = self.total_buffer_cycles.saturating_add(1);
        self.total_bytes_buffered = self.storage.len() as u64;
        self.atomic_bytes_read
            .fetch_add(count as u64, Ordering::Relaxed);
        self.last_response_timestamp = Some(Instant::now());
        self.refresh_active_state();
        Ok(bytes)
    }

    /// Securely clears buffered contents while keeping the buffer reusable.
    pub fn clear(&mut self) -> usize {
        let cleared = self.storage.len();
        self.storage.iter_mut().for_each(|byte| *byte = 0);
        self.storage.clear();
        self.total_bytes_buffered = 0;
        self.refresh_active_state();
        cleared
    }

    /// Clears buffered data and permanently rejects subsequent I/O.
    pub fn shutdown(&mut self) -> usize {
        let cleared = self.clear();
        self.is_fronting_buffer_shutdown = true;
        self.refresh_active_state();
        cleared
    }

    pub fn len(&self) -> usize {
        self.storage.len()
    }

    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
    }

    pub fn available_capacity(&self) -> usize {
        self.buffer_capacity_limit
            .saturating_sub(self.storage.len())
    }

    pub fn snapshot(&self) -> MitmFrontingBufferSnapshot {
        MitmFrontingBufferSnapshot {
            buffered_bytes: self.storage.len(),
            capacity: self.buffer_capacity_limit,
            available_capacity: self.available_capacity(),
            bytes_read: self.atomic_bytes_read.load(Ordering::Relaxed),
            bytes_written: self.atomic_bytes_written.load(Ordering::Relaxed),
            overflow_count: self.atomic_buffer_overflows.load(Ordering::Relaxed),
            dropped_bytes: self.atomic_packets_dropped.load(Ordering::Relaxed),
            cycle_count: self.total_buffer_cycles,
            error_count: self.total_buffer_errors,
            is_active: self.is_buffer_active,
            is_shutdown: self.is_fronting_buffer_shutdown,
        }
    }

    fn ensure_running(&self) -> Result<(), MitmFrontingBufferError> {
        if self.is_fronting_buffer_shutdown {
            Err(MitmFrontingBufferError::Shutdown)
        } else {
            Ok(())
        }
    }

    fn record_overflow(&mut self, dropped_bytes: usize) {
        self.total_buffer_errors = self.total_buffer_errors.saturating_add(1);
        self.atomic_buffer_overflows.fetch_add(1, Ordering::Relaxed);
        self.atomic_packets_dropped
            .fetch_add(dropped_bytes as u64, Ordering::Relaxed);
        self.last_error_timestamp = Some(Instant::now());
    }

    fn refresh_active_state(&mut self) {
        self.is_buffer_active = !self.storage.is_empty() && !self.is_fronting_buffer_shutdown;
        self.atomic_active_buffers
            .store(i32::from(self.is_buffer_active), Ordering::Relaxed);
    }
}

impl Default for MitmFrontingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

pub static IS_FRONTING_BUFFER_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_production_defaults_without_derived_zero_values() {
        let buffer = MitmFrontingBuffer::default();

        assert_eq!(buffer.buffer_capacity_limit, 65_536);
        assert_eq!(buffer.read_buffer_chunk_size, 4_096);
        assert_eq!(buffer.write_buffer_chunk_size, 4_096);
        assert_eq!(buffer.min_latency_millis, u64::MAX);
        assert!(buffer.is_empty());
        assert!(!buffer.is_fronting_buffer_shutdown);
    }

    #[test]
    fn reads_in_fifo_order_and_tracks_metrics() {
        let mut buffer = MitmFrontingBuffer::with_capacity(8).unwrap();

        assert_eq!(buffer.write(b"abc"), Ok(3));
        assert_eq!(buffer.write(b"def"), Ok(3));
        assert_eq!(buffer.read(4), Ok(b"abcd".to_vec()));

        let snapshot = buffer.snapshot();
        assert_eq!(snapshot.buffered_bytes, 2);
        assert_eq!(snapshot.available_capacity, 6);
        assert_eq!(snapshot.bytes_written, 6);
        assert_eq!(snapshot.bytes_read, 4);
        assert_eq!(snapshot.cycle_count, 3);
        assert!(snapshot.is_active);
    }

    #[test]
    fn overflow_is_atomic_and_records_dropped_bytes() {
        let mut buffer = MitmFrontingBuffer::with_capacity(4).unwrap();
        buffer.write(b"abc").unwrap();

        assert_eq!(
            buffer.write(b"de"),
            Err(MitmFrontingBufferError::CapacityExceeded {
                requested: 2,
                available: 1,
            })
        );
        assert_eq!(buffer.read(8), Ok(b"abc".to_vec()));

        let snapshot = buffer.snapshot();
        assert_eq!(snapshot.overflow_count, 1);
        assert_eq!(snapshot.dropped_bytes, 2);
        assert_eq!(snapshot.error_count, 1);
        assert!(!snapshot.is_active);
    }

    #[test]
    fn rejects_zero_capacity() {
        assert_eq!(
            MitmFrontingBuffer::with_capacity(0).unwrap_err(),
            MitmFrontingBufferError::InvalidCapacity
        );
    }

    #[test]
    fn clear_releases_capacity_without_shutting_down() {
        let mut buffer = MitmFrontingBuffer::with_capacity(4).unwrap();
        buffer.write(b"data").unwrap();

        assert_eq!(buffer.clear(), 4);
        assert_eq!(buffer.available_capacity(), 4);
        assert_eq!(buffer.write(b"ok"), Ok(2));
    }

    #[test]
    fn shutdown_clears_data_and_fails_closed() {
        let mut buffer = MitmFrontingBuffer::with_capacity(4).unwrap();
        buffer.write(b"data").unwrap();

        assert_eq!(buffer.shutdown(), 4);
        assert!(buffer.is_empty());
        assert_eq!(buffer.write(b"x"), Err(MitmFrontingBufferError::Shutdown));
        assert_eq!(buffer.read(1), Err(MitmFrontingBufferError::Shutdown));
        assert!(!buffer.snapshot().is_active);
        assert!(buffer.snapshot().is_shutdown);
    }
}
