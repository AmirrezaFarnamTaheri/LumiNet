use crate::ffi::binary_scan::PackedResult;

/// FFI callback context passed from the host (Go/C#/Java) into the Rust core.
///
/// # Safety Contract for Send + Sync
///
/// The `context` pointer is owned by the host language runtime and is guaranteed
/// by the FFI contract to:
/// 1. Remain valid for the entire duration of the scan operation.
/// 2. Be exclusively owned by the Rust worker thread during execution
///    (the host must not access or free it concurrently).
/// 3. The callback function pointers (`on_result`, `on_progress`) are safe to
///    call from any thread — the host is responsible for internal synchronization.
///
/// Violating these invariants from the host side is a programming error on the
/// caller's part, not a Rust safety issue.
#[repr(C)]
pub struct FfiCallbackContext {
    pub context: *mut std::ffi::c_void,
    pub on_result:
        Option<unsafe extern "C" fn(context: *mut std::ffi::c_void, result: *const PackedResult)>,
    pub on_progress: Option<
        unsafe extern "C" fn(context: *mut std::ffi::c_void, completed: usize, total: usize),
    >,
}

// SAFETY: See the safety contract documented on FfiCallbackContext.
// The host language guarantees exclusive ownership transfer to the worker thread.
unsafe impl Send for FfiCallbackContext {}
// SAFETY: The callback function pointers are stateless dispatchers; the host
// is responsible for any internal synchronization on the context pointer.
unsafe impl Sync for FfiCallbackContext {}
