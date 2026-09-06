use std::any::Any;
use std::panic;

/// Like guard_ffi but writes the panic message to output[0..].
/// output[0..4] = b"PNIC" magic tag
/// output[4..4+msg_len] = UTF-8 panic message (truncated at output_cap-4)
/// Always returns FFI_ERR_PANIC (-2).
///
/// # Safety
///
/// When non-null, `output` must reference `output_cap` writable bytes. The
/// closure must uphold the safety contract of the FFI operation being guarded.
pub unsafe fn guard_ffi_verbose<F>(f: F, output: *mut u8, output_cap: usize) -> i32
where
    F: FnOnce() -> i32 + panic::UnwindSafe,
{
    match panic::catch_unwind(f) {
        Ok(code) => code,
        Err(payload) => {
            let msg = panic_to_string(&payload);
            write_pnic(msg.as_bytes(), output, output_cap);
            -2 // FFI_ERR_PANIC
        }
    }
}

fn write_pnic(msg: &[u8], output: *mut u8, cap: usize) {
    if cap < 4 || output.is_null() {
        return;
    }
    let out = unsafe { std::slice::from_raw_parts_mut(output, cap) };
    out[..4].copy_from_slice(b"PNIC");
    let copy_len = msg.len().min(cap - 4);
    out[4..4 + copy_len].copy_from_slice(&msg[..copy_len]);
}

pub fn panic_to_string(payload: &Box<dyn Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        return s.to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    format!("unknown panic payload type: {:?}", (**payload).type_id())
}
