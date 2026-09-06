//! # C FFI Layer
//!
//! Provides C-compatible ABI exports for host integration. The Go daemon consumes
//! only its declared subset through `apps/daemon/internal/bridge/lumicore_abi.h`;
//! that private header is checked against these Rust implementations. Exports include
//! both retained JSON/string compatibility functions and versioned binary/streaming calls.

pub mod async_exports;
pub mod binary_bridge;
pub mod binary_scan;
pub mod callbacks;
pub mod envelope;
pub mod exports;
pub mod json_bridge;
pub mod memory_bridge;
pub mod panic_guard;
pub mod streaming;
pub mod version;


#[cfg(target_os = "ios")]
pub mod ios_ffi;

use std::ffi::CString;
use std::os::raw::c_char;

/// Helper to convert a Rust string/JSON into a raw C string.
/// The caller is responsible for freeing this memory using `free_string`.
pub fn str_to_c_char(s: &str) -> *mut c_char {
    let c_str = CString::new(s)
        .unwrap_or_else(|_| CString::new("{\"error\":\"CString conversion failed\"}").unwrap());
    c_str.into_raw()
}

/// Frees a string that was allocated by Rust and passed to C.
///
/// # Safety
/// This function must only be called with a pointer returned by Rust FFI.
#[no_mangle]
pub unsafe extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

/// Frees a raw byte buffer allocated by Rust and passed to Go/C.
/// This is the safe pattern for FFI memory ownership transfer.
///
/// # Safety
/// - `ptr` must have been allocated by Rust (via Vec::into_raw or similar)
/// - `len` must match the original allocation length
/// - Must not be called more than once for the same pointer
#[no_mangle]
pub unsafe extern "C" fn free_rust_buffer(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        // Reconstruct the Vec and let it drop
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

/// Allocates a buffer in Rust that can be written to by Go/C.
/// Returns a pointer to the allocated buffer.
/// Must be freed with `free_rust_buffer`.
///
/// # Safety
/// The returned pointer must be freed with `free_rust_buffer` after use.
#[no_mangle]
pub unsafe extern "C" fn alloc_rust_buffer(len: usize) -> *mut u8 {
    if len == 0 {
        return std::ptr::null_mut();
    }
    let mut buf = vec![0; len];
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf); // Prevent Vec from being dropped
    ptr
}
