/// Packed scan configuration used by the versioned binary scan payload.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PackedScanConfig {
    pub timeout_ms: u32,
    pub max_concurrent: u32,
    pub rate_limit_pps: u32,
}

/// Packed scan target retained for Rust-internal callback/result plumbing.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PackedTarget {
    pub ip_bytes: [u8; 16],
    pub is_ipv6: u8,
    pub pad: [u8; 7],
}

/// Packed probe result retained for Rust-internal callback/result plumbing.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PackedResult {
    pub ip_bytes: [u8; 16],
    pub is_ipv6: u8,
    pub is_alive: u8,
    pub reason_code: u16,
    pub latency_us: u64,
}
