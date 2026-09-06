pub const LUMICORE_ABI_VERSION: u16 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FfiEnvelope {
    pub abi_version: u16,  // must equal LUMICORE_ABI_VERSION
    pub op_code: u16,      // see OpCode enum below
    pub flags: u32,        // FLAG_COMPRESS=0x01, FLAG_ENCRYPT=0x02, FLAG_STREAM=0x04
    pub trace_id_hi: u64,  // upper 64 bits of 128-bit trace ID (for distributed tracing)
    pub trace_id_lo: u64,  // lower 64 bits
    pub input_len: usize,  // byte length of payload that follows this header
    pub output_cap: usize, // caller-allocated output buffer capacity in bytes
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FfiStatus {
    pub code: i32,         // 0=OK, negative=error (see constants below)
    pub output_len: usize, // bytes actually written to output buffer
    pub error_code: u16,   // domain-specific sub-error
    pub reserved: u16,
}

// Status codes
pub const FFI_OK: i32 = 0;
pub const FFI_ERR_NULL: i32 = -1; // null pointer argument
pub const FFI_ERR_PANIC: i32 = -2; // Rust panic caught by guard_ffi
pub const FFI_ERR_ABI: i32 = -3; // abi_version mismatch
pub const FFI_ERR_CAPACITY: i32 = -4; // output buffer too small
pub const FFI_ERR_DECODE: i32 = -5; // payload deserialization failed
/// The operation is part of the negotiated ABI but has no production
/// implementation in this core build. Callers must surface this capability as
/// unavailable rather than treating a no-op as successful work.
pub const FFI_ERR_UNSUPPORTED: i32 = -6;

#[repr(u16)]
pub enum OpCode {
    Scan = 1,        // IP/port scan via Rust scan engine
    RouteUpdate = 2, // push new routing table into mmap config
    EchGrease = 3,   // generate ECH GREASE ClientHello bytes
    TlsFragment = 4, // compute TLS record split offsets
    PoolRefresh = 5, // trigger SNI/IP pool health refresh
    SniRotate = 6,   // fetch next SNI from rotating pool
}

/// Panic-safe wrapper. Catches any Rust panic and converts to FFI_ERR_PANIC.
/// Must wrap every extern "C" handler body.
///
/// # Safety
///
/// The closure must uphold every pointer and aliasing invariant of the FFI
/// operation it encloses. Catching a panic does not make invalid memory access safe.
#[inline]
pub unsafe fn guard_ffi<F>(f: F) -> FfiStatus
where
    F: FnOnce() -> FfiStatus + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(status) => status,
        Err(_) => FfiStatus {
            code: FFI_ERR_PANIC,
            output_len: 0,
            error_code: 0,
            reserved: 0,
        },
    }
}
