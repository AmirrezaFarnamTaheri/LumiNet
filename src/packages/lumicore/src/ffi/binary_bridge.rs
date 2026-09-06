use super::binary_scan::PackedScanConfig;
use super::envelope::*;

/// Primary FFI entry point. Called from Go via CGo.
/// Layout: input = FfiEnvelope (36 bytes) | payload (env.input_len bytes)
///
/// # Safety
///
/// `env` must point to a valid `FfiEnvelope`; `input` must reference at least
/// `env.input_len` readable bytes when that length is non-zero (it may be null
/// for an empty payload); and `output` must reference at least
/// `env.output_cap` writable bytes. The buffers must not alias.
#[no_mangle]
pub unsafe extern "C" fn lumicore_call(
    env: *const FfiEnvelope,
    input: *const u8,
    output: *mut u8,
) -> FfiStatus {
    guard_ffi(|| {
        let env = match env.as_ref() {
            None => {
                return FfiStatus {
                    code: FFI_ERR_NULL,
                    output_len: 0,
                    error_code: 0,
                    reserved: 0,
                }
            }
            Some(e) => e,
        };
        if env.abi_version != LUMICORE_ABI_VERSION {
            return FfiStatus {
                code: FFI_ERR_ABI,
                output_len: 0,
                error_code: env.abi_version,
                reserved: 0,
            };
        }
        if output.is_null() {
            return FfiStatus {
                code: FFI_ERR_NULL,
                output_len: 0,
                error_code: 1,
                reserved: 0,
            };
        }
        if env.input_len != 0 && input.is_null() {
            return FfiStatus {
                code: FFI_ERR_NULL,
                output_len: 0,
                error_code: 2,
                reserved: 0,
            };
        }
        // `from_raw_parts` requires a non-null pointer even for length zero;
        // C callers commonly use NULL to represent an empty payload.
        let payload = if env.input_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(input, env.input_len)
        };
        let out_buf = std::slice::from_raw_parts_mut(output, env.output_cap);
        dispatch(env.op_code, env.flags, payload, out_buf)
    })
}

fn dispatch(op: u16, _flags: u32, input: &[u8], output: &mut [u8]) -> FfiStatus {
    match op {
        1 => handle_scan(input, output),
        2 => handle_route_update(input, output),
        3 => handle_ech_grease(input, output),
        4 => handle_tls_fragment(input, output),
        5 => handle_pool_refresh(input, output),
        6 => handle_sni_rotate(input, output),
        _ => FfiStatus {
            code: FFI_ERR_DECODE,
            output_len: 0,
            error_code: op,
            reserved: 0,
        },
    }
}

fn err_status(code: i32, error_code: u16) -> FfiStatus {
    FfiStatus {
        code,
        output_len: 0,
        error_code,
        reserved: 0,
    }
}

fn handle_scan(input: &[u8], _output: &mut [u8]) -> FfiStatus {
    if input.len() < std::mem::size_of::<PackedScanConfig>() {
        return err_status(FFI_ERR_DECODE, 0);
    }
    // Keep validating the legacy payload shape so a caller can distinguish a
    // malformed request from an unavailable capability.  The actual scan
    // engine has not been connected to this synchronous ABI path yet.
    let _cfg: PackedScanConfig = unsafe { std::ptr::read_unaligned(input.as_ptr() as *const _) };
    err_status(FFI_ERR_UNSUPPORTED, OpCode::Scan as u16)
}

fn handle_ech_grease(input: &[u8], _output: &mut [u8]) -> FfiStatus {
    // input[0..2] = u16 outer_version (e.g. 0x0304 = TLS 1.3)
    // input[2..34] = 32-byte random seed for GREASE extension bytes
    if input.len() < 34 {
        return err_status(FFI_ERR_DECODE, 0);
    }
    err_status(FFI_ERR_UNSUPPORTED, OpCode::EchGrease as u16)
}

fn handle_tls_fragment(input: &[u8], _output: &mut [u8]) -> FfiStatus {
    // input = TLS ClientHello bytes
    // output = split-offset pairs (u16 pairs: split_at, record_end)
    if input.len() < 5 {
        return err_status(FFI_ERR_DECODE, 0);
    }
    err_status(FFI_ERR_UNSUPPORTED, OpCode::TlsFragment as u16)
}

fn handle_route_update(_input: &[u8], _output: &mut [u8]) -> FfiStatus {
    err_status(FFI_ERR_UNSUPPORTED, OpCode::RouteUpdate as u16)
}
fn handle_pool_refresh(_input: &[u8], _output: &mut [u8]) -> FfiStatus {
    err_status(FFI_ERR_UNSUPPORTED, OpCode::PoolRefresh as u16)
}
fn handle_sni_rotate(_input: &[u8], _output: &mut [u8]) -> FfiStatus {
    err_status(FFI_ERR_UNSUPPORTED, OpCode::SniRotate as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_but_unimplemented_operations_fail_explicitly() {
        let envelope = FfiEnvelope {
            abi_version: LUMICORE_ABI_VERSION,
            op_code: OpCode::RouteUpdate as u16,
            flags: 0,
            trace_id_hi: 0,
            trace_id_lo: 0,
            input_len: 0,
            output_cap: 1,
        };
        let input = [0u8; 1];
        let mut output = [0u8; 1];
        let status = unsafe { lumicore_call(&envelope, input.as_ptr(), output.as_mut_ptr()) };
        assert_eq!(status.code, FFI_ERR_UNSUPPORTED);
        assert_eq!(status.error_code, OpCode::RouteUpdate as u16);
        assert_eq!(status.output_len, 0);
    }

    #[test]
    fn zero_length_payload_accepts_null_input() {
        let envelope = FfiEnvelope {
            abi_version: LUMICORE_ABI_VERSION,
            op_code: OpCode::RouteUpdate as u16,
            flags: 0,
            trace_id_hi: 0,
            trace_id_lo: 0,
            input_len: 0,
            output_cap: 1,
        };
        let mut output = [0u8; 1];
        let status = unsafe { lumicore_call(&envelope, std::ptr::null(), output.as_mut_ptr()) };
        assert_eq!(status.code, FFI_ERR_UNSUPPORTED);
    }

    #[test]
    fn nonempty_payload_rejects_null_input() {
        let envelope = FfiEnvelope {
            abi_version: LUMICORE_ABI_VERSION,
            op_code: OpCode::RouteUpdate as u16,
            flags: 0,
            trace_id_hi: 0,
            trace_id_lo: 0,
            input_len: 1,
            output_cap: 1,
        };
        let mut output = [0u8; 1];
        let status = unsafe { lumicore_call(&envelope, std::ptr::null(), output.as_mut_ptr()) };
        assert_eq!(status.code, FFI_ERR_NULL);
        assert_eq!(status.error_code, 2);
    }
}
