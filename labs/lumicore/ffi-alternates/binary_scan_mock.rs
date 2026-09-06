use crate::ffi::envelope::{FfiEnvelope, FfiStatus, FFI_ERR_NULL, FFI_OK};

/// Packed scan configuration — matching PackedScanConfig in binary_scan.go C block
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PackedScanConfig {
    pub timeout_ms: u32,
    pub max_concurrent: u32,
    pub rate_limit_pps: u32,
}

/// Packed scan target — matching PackedTarget in binary_scan.go C block
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PackedTarget {
    pub ip_bytes: [u8; 16],
    pub is_ipv6: u8,
    pub pad: [u8; 7],
}

/// Probe result — matching PackedResult in binary_scan.go C block
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct PackedResult {
    pub ip_bytes: [u8; 16],
    pub is_ipv6: u8,
    pub is_alive: u8,
    pub reason_code: u16,
    pub latency_us: u64,
}

/// FFI entry point for binary scan execution.
///
/// # Safety
///
/// `envelope` and `config` must point to initialized values. `targets` and
/// `out_results` must each reference `target_len` elements, and their ranges
/// must not overlap.
#[no_mangle]
pub unsafe extern "C" fn lumicore_scan_execution(
    envelope: *const FfiEnvelope,
    config: *const PackedScanConfig,
    targets: *const PackedTarget,
    target_len: usize,
    out_results: *mut PackedResult,
) -> FfiStatus {
    if envelope.is_null() || config.is_null() || targets.is_null() || out_results.is_null() {
        return FfiStatus {
            code: FFI_ERR_NULL,
            output_len: 0,
            error_code: 0,
            reserved: 0,
        };
    }

    let targets_slice = std::slice::from_raw_parts(targets, target_len);
    let results_slice = std::slice::from_raw_parts_mut(out_results, target_len);

    for i in 0..target_len {
        results_slice[i] = PackedResult {
            ip_bytes: targets_slice[i].ip_bytes,
            is_ipv6: targets_slice[i].is_ipv6,
            is_alive: 1, // Mock as active/alive
            reason_code: 0,
            latency_us: 1500, // mock latency
        };
    }

    FfiStatus {
        code: FFI_OK,
        output_len: target_len,
        error_code: 0,
        reserved: 0,
    }
}
