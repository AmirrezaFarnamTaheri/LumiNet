use dashmap::DashMap;
use futures::FutureExt;
use once_cell::sync::Lazy;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_util::sync::CancellationToken;

pub type StreamCallback = unsafe extern "C" fn(
    event_type: u16,
    data: *const u8,
    data_len: usize,
    user_data: *mut std::ffi::c_void,
);

#[repr(C)]
pub struct StreamHandle {
    pub stream_id: u64,
    pub reserved: u64,
}

// Event type constants written into StreamCallback.event_type
pub const STREAM_EVT_PROBE_RESULT: u16 = 1; // ProbeResult binary blob
pub const STREAM_EVT_POOL_UPDATE: u16 = 2; // PoolStats binary blob
pub const STREAM_EVT_SCAN_DONE: u16 = 3; // empty payload, signals completion
pub const STREAM_EVT_ERROR: u16 = 255; // error payload (UTF-8 string)

const STREAM_PANIC_ERROR: &[u8] = b"stream task panicked";

static STREAM_COUNTER: AtomicU64 = AtomicU64::new(1);
static STREAM_MAP: Lazy<DashMap<u64, CancellationToken>> = Lazy::new(DashMap::new);

fn next_stream_id() -> u64 {
    STREAM_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[no_mangle]
/// Starts a cancellable stream and returns its opaque handle.
///
/// The callback receives exactly one terminal `STREAM_EVT_SCAN_DONE` event after
/// all other callbacks for the stream. The host must keep `user_data` valid until
/// that terminal callback returns, including after cancellation is requested.
///
/// # Safety
///
/// `input` must reference `input_len` readable bytes. `cb` must remain callable
/// from any runtime thread, and `user_data` must remain valid through the terminal
/// callback.
pub unsafe extern "C" fn lumicore_stream_start(
    op: u16,
    input: *const u8,
    input_len: usize,
    cb: StreamCallback,
    user_data: *mut std::ffi::c_void,
) -> StreamHandle {
    let rt = match crate::runtime::get() {
        Ok(runtime) => runtime.handle().clone(),
        Err(_) => {
            return StreamHandle {
                stream_id: 0,
                reserved: 0,
            };
        }
    };
    if input_len != 0 && input.is_null() {
        return StreamHandle {
            stream_id: 0,
            reserved: 0,
        };
    }

    let stream_id = next_stream_id();
    let token = CancellationToken::new();
    STREAM_MAP.insert(stream_id, token.clone());

    // The host owns user_data until the terminal callback. Capture the address as
    // an integer because raw mutable pointers are not Send across the runtime task.
    let user_data_addr = user_data as usize;
    let payload = if input_len == 0 {
        Vec::new()
    } else {
        std::slice::from_raw_parts(input, input_len).to_vec()
    };

    rt.spawn(async move {
        let result = AssertUnwindSafe(run_stream(
            op,
            &payload,
            cb,
            user_data_addr,
            token,
        ))
        .catch_unwind()
        .await;

        if result.is_err() {
            unsafe {
                cb(
                    STREAM_EVT_ERROR,
                    STREAM_PANIC_ERROR.as_ptr(),
                    STREAM_PANIC_ERROR.len(),
                    user_data_addr as *mut std::ffi::c_void,
                );
            }
        }

        STREAM_MAP.remove(&stream_id);
        unsafe {
            cb(
                STREAM_EVT_SCAN_DONE,
                std::ptr::null(),
                0,
                user_data_addr as *mut std::ffi::c_void,
            );
        }
    });

    StreamHandle {
        stream_id,
        reserved: 0,
    }
}

async fn run_stream(
    op: u16,
    input: &[u8],
    cb: StreamCallback,
    user_data: usize,
    token: CancellationToken,
) {
    if op == 1 {
        stream_scan(input, cb, user_data, token).await
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct StreamScanPayload {
    pub target: String,
    pub ports: Vec<u16>,
    #[serde(default = "default_stream_timeout_ms")]
    pub timeout_ms: u32,
}

fn default_stream_timeout_ms() -> u32 {
    3000
}

#[derive(serde::Serialize)]
pub struct StreamProbeResult {
    pub target: String,
    pub port: u16,
    pub open: bool,
    pub latency_ms: f64,
    pub error: Option<String>,
}

#[derive(serde::Serialize)]
pub struct StreamProgress {
    pub completed: usize,
    pub total: usize,
    pub percent: u32,
}

async fn stream_scan(
    input: &[u8],
    cb: StreamCallback,
    user_data: usize,
    token: CancellationToken,
) {
    let payload: StreamScanPayload = match serde_json::from_slice(input) {
        Ok(p) => p,
        Err(_) => StreamScanPayload {
            target: "127.0.0.1".to_string(),
            ports: vec![80, 443, 8080],
            timeout_ms: 3000,
        },
    };

    let total = payload.ports.len();
    if total == 0 {
        return;
    }

    for (idx, &port) in payload.ports.iter().enumerate() {
        if token.is_cancelled() {
            break;
        }

        let addr = format!("{}:{}", payload.target, port);
        let start = std::time::Instant::now();
        let timeout_dur = std::time::Duration::from_millis(payload.timeout_ms as u64);

        let (open, err_msg) = match tokio::time::timeout(timeout_dur, tokio::net::TcpStream::connect(&addr)).await {
            Ok(Ok(_stream)) => (true, None),
            Ok(Err(e)) => (false, Some(e.to_string())),
            Err(_) => (false, Some("connection timed out".to_string())),
        };

        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        let probe = StreamProbeResult {
            target: payload.target.clone(),
            port,
            open,
            latency_ms,
            error: err_msg,
        };

        if let Ok(data) = serde_json::to_vec(&probe) {
            unsafe {
                cb(
                    STREAM_EVT_PROBE_RESULT,
                    data.as_ptr(),
                    data.len(),
                    user_data as *mut std::ffi::c_void,
                );
            }
        }

        let completed = idx + 1;
        let percent = ((completed * 100) / total) as u32;
        let prog = StreamProgress {
            completed,
            total,
            percent,
        };
        if let Ok(prog_data) = serde_json::to_vec(&prog) {
            unsafe {
                cb(
                    STREAM_EVT_POOL_UPDATE,
                    prog_data.as_ptr(),
                    prog_data.len(),
                    user_data as *mut std::ffi::c_void,
                );
            }
        }
    }
}

#[no_mangle]
/// Requests cancellation of the stream represented by `handle`.
///
/// Cancellation is asynchronous. Stream ownership remains with the runtime task
/// until it publishes the terminal callback and removes the stream from the map.
///
/// # Safety
///
/// `handle` must be a value returned by `lumicore_stream_start`.
pub unsafe extern "C" fn lumicore_stream_cancel(handle: StreamHandle) {
    let token = STREAM_MAP
        .get(&handle.stream_id)
        .map(|entry| entry.clone());
    if let Some(token) = token {
        token.cancel();
    }
}
