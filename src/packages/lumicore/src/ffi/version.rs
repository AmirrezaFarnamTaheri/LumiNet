pub const ABI_MAJOR: u16 = 3;
pub const ABI_MINOR: u16 = 0;
pub const ABI_PATCH: u16 = 0;

/// Returns packed u64: bits[47:32]=major, bits[31:16]=minor, bits[15:0]=patch.
/// Returns 0 if the library is older than minimum_required_major.
#[no_mangle]
pub extern "C" fn lumicore_version(minimum_required_major: u16) -> u64 {
    if ABI_MAJOR < minimum_required_major {
        return 0;
    }
    ((ABI_MAJOR as u64) << 32) | ((ABI_MINOR as u64) << 16) | (ABI_PATCH as u64)
}

/// Writes "lumicore/3.0.0" into buf. Returns bytes written. Thread-safe.
///
/// # Safety
///
/// `buf` must reference at least `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn lumicore_version_string(buf: *mut u8, buf_len: usize) -> usize {
    if buf.is_null() || buf_len == 0 {
        return 0;
    }
    let s = format!("lumicore/{}.{}.{}", ABI_MAJOR, ABI_MINOR, ABI_PATCH);
    let bytes = s.as_bytes();
    let n = bytes.len().min(buf_len);
    std::slice::from_raw_parts_mut(buf, n).copy_from_slice(&bytes[..n]);
    n
}
