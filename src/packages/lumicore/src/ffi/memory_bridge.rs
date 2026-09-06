use std::os::raw::c_uchar;
use std::slice;

#[no_mangle]
/// Applies the in-place LumiCore buffer transform.
///
/// # Safety
///
/// `buf_ptr` must reference `buf_len` writable bytes for the duration of the call.
pub unsafe extern "C" fn lumicore_process_buffer(buf_ptr: *mut c_uchar, buf_len: usize) -> i32 {
    if buf_ptr.is_null() || buf_len == 0 {
        return -1;
    }

    let buffer = slice::from_raw_parts_mut(buf_ptr, buf_len);
    // Process zero-copy buffer slice safely
    for byte in buffer.iter_mut() {
        *byte ^= 0xAA;
    }

    0
}
