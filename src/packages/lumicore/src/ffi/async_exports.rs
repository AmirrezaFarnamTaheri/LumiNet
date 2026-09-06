use super::json_bridge::{json_error_string, parse_json_input, read_c_string_owned};
use crate::ffi::exports::get_runtime;
use serde_json::Value;
use std::net::SocketAddr;
use std::os::raw::c_char;

/// Decode a hex string into bytes (accepts optional 0x prefix and
/// whitespace). Errors carry the offending character index.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let cleaned = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned);
    if cleaned.len() % 2 != 0 {
        return Err("odd-length hex input".to_string());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|e| format!("bad hex at byte {}: {e}", i / 2))
        })
        .collect()
}

/// Lowercase hex encode, byte-paired.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap_or('0'));
    }
    out
}

pub type FfiCallback = unsafe extern "C" fn(u64, *const c_char);

struct CallbackGuard {
    req_id: u64,
    cb: FfiCallback,
    called: bool,
}

impl Drop for CallbackGuard {
    fn drop(&mut self) {
        if !self.called {
            let c_res =
                std::ffi::CString::new("{\"error\":\"Internal Rust Panic or Task Dropped\"}")
                    .unwrap();
            unsafe { (self.cb)(self.req_id, c_res.as_ptr()) };
        }
    }
}

impl CallbackGuard {
    fn call(&mut self, res: &str) {
        self.called = true;
        let c_res = std::ffi::CString::new(res).unwrap_or_else(|_| {
            std::ffi::CString::new("{\"error\":\"CString allocation failed\"}").unwrap()
        });
        unsafe { (self.cb)(self.req_id, c_res.as_ptr()) };
    }
}

fn callback_error(req_id: u64, cb: FfiCallback, error: impl std::fmt::Display) {
    let mut guard = CallbackGuard {
        req_id,
        cb,
        called: false,
    };
    guard.call(&json_error_string(error));
}

#[no_mangle]
/// Starts an asynchronous core operation and reports exactly one result through `cb`.
///
/// # Safety
///
/// `endpoint` and `input_json` must point to readable NUL-terminated strings for the
/// duration of this call. They are copied before asynchronous work starts. `cb` must
/// remain callable from any thread until exactly one callback has been delivered.
pub unsafe extern "C" fn call_core_async_ffi(
    endpoint: *const c_char,
    input_json: *const c_char,
    req_id: u64,
    cb: FfiCallback,
) {
    let endpoint_str = match read_c_string_owned(endpoint) {
        Ok(value) => value,
        Err(err) => {
            callback_error(req_id, cb, err);
            return;
        }
    };
    let input: Value = match parse_json_input(input_json) {
        Ok(value) => value,
        Err(err) => {
            callback_error(req_id, cb, err);
            return;
        }
    };

    let rt = match get_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            callback_error(req_id, cb, e);
            return;
        }
    };

    if endpoint_str == "probe_tcp" {
        std::thread::spawn(move || {
            let mut guard = CallbackGuard {
                req_id,
                cb,
                called: false,
            };
            let target = input["target"].as_str().unwrap_or("");
            let port = input["port"].as_u64().unwrap_or(80) as u16;
            let timeout = input["timeout_ms"].as_u64().unwrap_or(1000) as u32;

            let target_owned = target.to_string();
            let res = crate::ffi::exports::block_on_compio(async move {
                crate::tcp::tcp_connect(&target_owned, port, timeout).await
            });

            let json_res = match res {
                Ok(Ok(result)) => serde_json::to_string(&result)
                    .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
                Ok(Err(e)) => format!("{{\"error\":\"{}\"}}", e),
                Err(e) => format!("{{\"error\":\"{}\"}}", e),
            };
            guard.call(&json_res);
        });
        return;
    }

    rt.spawn(async move {
        let mut guard = CallbackGuard {
            req_id,
            cb,
            called: false,
        };

        let json_res = match endpoint_str.as_str() {
            "scan_dns" => {
                let server = input["server"].as_str().unwrap_or("").to_string();
                let domain = input["domain"].as_str().unwrap_or("").to_string();
                let rtype_str = input["record_type"].as_str().unwrap_or("A");
                let rtype = match rtype_str.to_uppercase().as_str() {
                    "A" => crate::dns::TYPE_A,
                    "AAAA" => crate::dns::TYPE_AAAA,
                    "CNAME" => crate::dns::TYPE_CNAME,
                    "MX" => crate::dns::TYPE_MX,
                    "NS" => crate::dns::TYPE_NS,
                    "TXT" => crate::dns::TYPE_TXT,
                    "SOA" => crate::dns::TYPE_SOA,
                    "PTR" => crate::dns::TYPE_PTR,
                    "HTTPS" => crate::dns::TYPE_HTTPS,
                    _ => crate::dns::TYPE_A,
                };
                let protocol = input["protocol"].as_str().unwrap_or("udp");
                let timeout = input["timeout_ms"].as_u64().unwrap_or(3000) as u32;
                let start = std::time::Instant::now();

                let dns_res = match protocol.to_lowercase().as_str() {
                    "doh" | "https" => {
                        match crate::dns::resolve_doh(&server, &domain, rtype_str).await {
                            Ok(records) => serde_json::json!({
                                "server": server, "protocol": "doh", "latency_ms": start.elapsed().as_secs_f64() * 1000.0, "success": true, "records": records
                            }),
                            Err(e) => serde_json::json!({
                                "server": server, "protocol": "doh", "latency_ms": start.elapsed().as_secs_f64() * 1000.0, "success": false, "error": e.to_string()
                            }),
                        }
                    }
                    "dot" | "tls" => {
                        let (host, port) = if let Some((h, p)) = server.rsplit_once(':') {
                            (h.to_string(), p.parse().unwrap_or(853))
                        } else {
                            (server.clone(), 853)
                        };
                        match crate::dns::resolve_dot(&host, port, &domain, rtype).await {
                            Ok(records) => serde_json::json!({
                                "server": server, "protocol": "dot", "latency_ms": start.elapsed().as_secs_f64() * 1000.0, "success": true, "records": records
                            }),
                            Err(e) => serde_json::json!({
                                "server": server, "protocol": "dot", "latency_ms": start.elapsed().as_secs_f64() * 1000.0, "success": false, "error": e.to_string()
                            }),
                        }
                    }
                    _ => match crate::dns::resolve(&server, &domain, rtype, timeout).await {
                        Ok(records) => serde_json::json!({
                            "server": server, "protocol": "udp", "latency_ms": start.elapsed().as_secs_f64() * 1000.0, "success": true, "records": records
                        }),
                        Err(e) => serde_json::json!({
                            "server": server, "protocol": "udp", "latency_ms": start.elapsed().as_secs_f64() * 1000.0, "success": false, "error": e.to_string()
                        }),
                    },
                };
                serde_json::to_string(&dns_res)
                    .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e))
            }
            "scan_quic" => {
                // Passive QUIC Initial fingerprinting over the FFI bridge.
                // Input: {addr: "ip:port", datagram_hex: "...", server_side?: bool}
                // Output: {found: bool, addr, num_id, hex_id, client_hello_hex}
                //   or {"error": "..."} on decrypt/parse failure.
                use crate::quic::scan::scan_initial_datagram;
                let addr_str = input["addr"].as_str().unwrap_or("").to_string();
                let datagram_hex = input["datagram_hex"].as_str().unwrap_or("").to_string();
                let server_side = input["server_side"].as_bool().unwrap_or(false);
                let json_res = (|| -> Result<serde_json::Value, String> {
                    let addr: SocketAddr = addr_str
                        .parse()
                        .map_err(|e| format!("bad addr: {e}"))?;
                    let datagram = decode_hex(&datagram_hex)?;
                    match scan_initial_datagram(addr, &datagram, server_side) {
                        Ok(Some(sc)) => Ok(serde_json::json!({
                            "found": true,
                            "addr": sc.addr.to_string(),
                            "num_id": sc.num_id,
                            "hex_id": sc.hex_id,
                            "client_hello_hex": hex_encode(&sc.client_hello),
                        })),
                        Ok(None) => Ok(serde_json::json!({ "found": false })),
                        Err(e) => Err(e),
                    }
                })();
                match json_res {
                    Ok(v) => v.to_string(),
                    Err(e) => format!("{{\"error\":\"{}\"}}", e.replace('"', "'")),
                }
            }
            _ => format!(
                "{{\"error\":\"Unknown or unsupported async endpoint: {}\"}}",
                endpoint_str
            ),
        };

        guard.call(&json_res);
    });
}
