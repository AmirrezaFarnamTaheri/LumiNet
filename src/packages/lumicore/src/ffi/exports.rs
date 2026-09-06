//! # C FFI Exported Functions
//!
//! CGO-compatible export functions for the Go host application.
//! All functions accept JSON strings for config/input and return JSON results.

use super::json_bridge::{catch_json_ffi, json_error, parse_json_input};
use super::str_to_c_char;
use crate::types::*;
use serde::{Deserialize, Serialize};
use std::os::raw::c_char;
use tokio::runtime::Runtime;

/// Returns the canonical process-wide Tokio runtime used by FFI operations.
pub(crate) fn get_runtime() -> Result<&'static Runtime, String> {
    crate::runtime::get()
}

/// Executes a future on a thread-local Compio runtime.
/// Runtime initialization failure is retained for the thread and returned to
/// the FFI caller instead of panicking across the C ABI.
pub(crate) fn block_on_compio<F, R>(f: F) -> Result<R, String>
where
    F: std::future::Future<Output = R>,
{
    thread_local! {
        static COMPIO_RUNTIME: Result<compio::runtime::Runtime, String> = {
            let mut proactor = compio::driver::ProactorBuilder::new();
            proactor.capacity(4096);
            compio::runtime::RuntimeBuilder::new()
                .with_proactor(proactor)
                .build()
                .map_err(|err| format!("Failed to build Compio runtime: {err}"))
        };
    }
    COMPIO_RUNTIME.with(|rt| match rt {
        Ok(rt) => Ok(rt.block_on(f)),
        Err(err) => Err(err.clone()),
    })
}

// ─── Input Structs for FFI ────────────────────────────────────────

#[derive(Deserialize)]
struct IcmpScanInput {
    targets: Vec<String>,
    config: Option<ScanConfig>,
}

#[derive(Deserialize)]
struct TcpProbeInput {
    target: String,
    port: u16,
    timeout_ms: u32,
}

#[derive(Deserialize)]
struct PortScanInput {
    target: String,
    ports: Vec<u16>,
    config: Option<ScanConfig>,
}

#[derive(Deserialize)]
struct DnsScanInput {
    server: String,
    domain: String,
    record_type: String,
    protocol: Option<String>,
    timeout_ms: Option<u32>,
}

#[derive(Deserialize)]
struct TlsProbeInput {
    target: String,
    port: u16,
    timeout_ms: u32,
    sni: Option<String>,
}

#[derive(Deserialize)]
struct Socks5ProbeInput {
    proxy_addr: String,
    #[allow(dead_code)]
    target: String,
    timeout_ms: u32,
}

#[derive(Deserialize)]
struct HttpProbeInput {
    url: String,
    timeout_ms: u32,
    proxy: Option<String>,
}

#[derive(Deserialize)]
struct SniDetectInput {
    domain: String,
    timeout_ms: u32,
}

#[derive(Deserialize)]
struct SpeedTestInput {
    server_url: String,
    timeout_ms: u32,
}

#[derive(Deserialize)]
struct CidrExpandInput {
    cidr: String,
}

#[derive(Deserialize)]
struct WgProbeInput {
    ip: String,
    port: u16,
    timeout_ms: u32,
    padding_len: Option<u32>,
    decoy_count: Option<u32>,
}

// ─── FFI Export Implementations ───────────────────────────────────

/// Wrapper for ICMP scanning.
///
/// Input JSON: `{"targets": ["192.168.1.1"], "config": <ScanConfig>}`
/// Output JSON: `{"results": [<ProbeResult>]}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn scan_icmp_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: IcmpScanInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let rt = match get_runtime() {
            Ok(r) => r,
            Err(e) => return str_to_c_char(&format!("{{\"error\":\"{}\"}}", e)),
        };
        let res = rt.block_on(async {
            let config = input.config.unwrap_or_default();
            let scanner = crate::icmp::IcmpScanner::new(config);

            let mut parsed_targets = Vec::new();
            for t in input.targets {
                if let Ok(ips) = crate::cidr::expand_cidr(&t) {
                    parsed_targets.extend(ips);
                } else if let Ok(ip) = t.parse::<std::net::IpAddr>() {
                    parsed_targets.push(ip);
                }
            }

            scanner.scan_targets(parsed_targets).await
        });

        let json_res = match res {
            Ok(results) => serde_json::to_string(&results)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{:?}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Wrapper for TCP probing.
///
/// Input JSON: `{"target": "127.0.0.1", "port": 80, "timeout_ms": 1000}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn probe_tcp_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: TcpProbeInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let res = block_on_compio(async move {
            crate::tcp::tcp_connect(&input.target, input.port, input.timeout_ms).await
        });

        let json_res = match res {
            Ok(Ok(result)) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Ok(Err(e)) => format!("{{\"error\":\"{}\"}}", e),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Wrapper for Port scanning.
///
/// Input JSON: `{"target": "127.0.0.1", "ports": [80, 443], "config": <ScanConfig>}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn scan_ports_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: PortScanInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let res = block_on_compio(async move {
            let config = input.config.unwrap_or_default();
            crate::tcp::port_scan(&input.target, input.ports, config).await
        });

        let json_res = match res {
            Ok(results) => serde_json::to_string(&results)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Wrapper for DNS scanning.
///
/// Input JSON: `{"server": "8.8.8.8", "domain": "example.com", "record_type": "A", "protocol": "udp", "timeout_ms": 3000}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn scan_dns_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: DnsScanInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let rt = match get_runtime() {
            Ok(r) => r,
            Err(e) => return str_to_c_char(&format!("{{\"error\":\"{}\"}}", e)),
        };
        let res: Result<DnsServerResult, String> = rt.block_on(async {
            let rtype = match input.record_type.to_uppercase().as_str() {
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

            let protocol = input.protocol.as_deref().unwrap_or("udp");
            let timeout = input.timeout_ms.unwrap_or(3000);
            let start = std::time::Instant::now();

            let dns_res = match protocol.to_lowercase().as_str() {
                "doh" | "https" => {
                    match crate::dns::resolve_doh(&input.server, &input.domain, &input.record_type)
                        .await
                    {
                        Ok(records) => Ok(DnsServerResult {
                            server: input.server.clone(),
                            protocol: "doh".to_string(),
                            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                            success: true,
                            records,
                            error: None,
                        }),
                        Err(e) => Ok(DnsServerResult {
                            server: input.server.clone(),
                            protocol: "doh".to_string(),
                            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                            success: false,
                            records: vec![],
                            error: Some(e.to_string()),
                        }),
                    }
                }
                "dot" | "tls" => {
                    let (host, port) = if let Some((h, p)) = input.server.rsplit_once(':') {
                        (h.to_string(), p.parse().unwrap_or(853))
                    } else {
                        (input.server.clone(), 853)
                    };
                    match crate::dns::resolve_dot(&host, port, &input.domain, rtype).await {
                        Ok(records) => Ok(DnsServerResult {
                            server: input.server.clone(),
                            protocol: "dot".to_string(),
                            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                            success: true,
                            records,
                            error: None,
                        }),
                        Err(e) => Ok(DnsServerResult {
                            server: input.server.clone(),
                            protocol: "dot".to_string(),
                            latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                            success: false,
                            records: vec![],
                            error: Some(e.to_string()),
                        }),
                    }
                }
                _ => {
                    if input.server.starts_with("https://") {
                        match crate::dns::resolve_doh(
                            &input.server,
                            &input.domain,
                            &input.record_type,
                        )
                        .await
                        {
                            Ok(records) => Ok(DnsServerResult {
                                server: input.server.clone(),
                                protocol: "doh".to_string(),
                                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                                success: true,
                                records,
                                error: None,
                            }),
                            Err(e) => Ok(DnsServerResult {
                                server: input.server.clone(),
                                protocol: "doh".to_string(),
                                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                                success: false,
                                records: vec![],
                                error: Some(e.to_string()),
                            }),
                        }
                    } else {
                        match crate::dns::resolve(&input.server, &input.domain, rtype, timeout)
                            .await
                        {
                            Ok(records) => Ok(DnsServerResult {
                                server: input.server.clone(),
                                protocol: "udp".to_string(),
                                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                                success: true,
                                records,
                                error: None,
                            }),
                            Err(e) => Ok(DnsServerResult {
                                server: input.server.clone(),
                                protocol: "udp".to_string(),
                                latency_ms: start.elapsed().as_secs_f64() * 1000.0,
                                success: false,
                                records: vec![],
                                error: Some(e.to_string()),
                            }),
                        }
                    }
                }
            };
            dns_res
        });

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Wrapper for TLS probing.
///
/// Input JSON: `{"target": "example.com", "port": 443, "timeout_ms": 2000}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn probe_tls_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: TlsProbeInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let rt = match get_runtime() {
            Ok(r) => r,
            Err(e) => return str_to_c_char(&format!("{{\"error\":\"{}\"}}", e)),
        };
        let res = rt.block_on(async {
            let sni = input.sni.as_deref().unwrap_or(&input.target);
            crate::tls::tls_handshake(&input.target, input.port, sni, input.timeout_ms).await
        });

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Wrapper for SOCKS5 probing.
///
/// Input JSON: `{"proxy_addr": "127.0.0.1:1080", "target": "example.com:80", "timeout_ms": 2000}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn probe_socks5_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: Socks5ProbeInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let rt = match get_runtime() {
            Ok(r) => r,
            Err(e) => return str_to_c_char(&format!("{{\"error\":\"{}\"}}", e)),
        };
        let res = rt.block_on(async {
            // Parse proxy_addr as host:port
            let (proxy_host, proxy_port) = if let Some((h, p)) = input.proxy_addr.rsplit_once(':') {
                (h.to_string(), p.parse().unwrap_or(1080))
            } else {
                (input.proxy_addr.clone(), 1080u16)
            };
            crate::socks::socks5_handshake(&proxy_host, proxy_port, input.timeout_ms).await
        });

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Wrapper for HTTP client probing.
///
/// Input JSON: `{"url": "http://example.com", "timeout_ms": 2000, "proxy": null}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn probe_http_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: HttpProbeInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let rt = match get_runtime() {
            Ok(r) => r,
            Err(e) => return str_to_c_char(&format!("{{\"error\":\"{}\"}}", e)),
        };
        let res = rt.block_on(async {
            let proxy = input.proxy.as_deref();
            match crate::http::http_get(&input.url, input.timeout_ms, proxy).await {
                Ok(resp) => {
                    let body_preview =
                        String::from_utf8_lossy(&resp.body[..resp.body.len().min(512)]).to_string();
                    let response = HttpProbeResponse {
                        status_code: resp.status,
                        headers: resp.headers,
                        body_preview,
                        latency_ms: resp.latency_ms,
                        content_length: resp.content_length,
                        redirected: false,
                        final_url: input.url.clone(),
                    };
                    Ok::<HttpProbeResponse, String>(response)
                }
                Err(e) => Err(e.to_string()),
            }
        });

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Wrapper for SNI detection.
///
/// Input JSON: `{"domain": "blocked.com", "timeout_ms": 2000}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn detect_sni_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: SniDetectInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let rt = match get_runtime() {
            Ok(r) => r,
            Err(e) => return str_to_c_char(&format!("{{\"error\":\"{}\"}}", e)),
        };
        let res = rt.block_on(async {
            let config = crate::types::ScanConfig {
                timeout_ms: input.timeout_ms,
                max_concurrent: 1,
                rate_limit_pps: 100,
                retry_count: 1,
                adaptive_rate: false,
                ipv6: false,
                shuffle: false,
                shuffle_seed: 0,
            };
            let results = crate::sni::detect_sni_blocking(vec![input.domain], config).await;
            results
                .into_iter()
                .next()
                .ok_or_else(|| "No result".to_string())
        });

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Wrapper for Speed testing.
///
/// Input JSON: `{"server_url": "http://speedtest.example.com", "timeout_ms": 5000}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn test_speed_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: SpeedTestInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let rt = match get_runtime() {
            Ok(r) => r,
            Err(e) => return str_to_c_char(&format!("{{\"error\":\"{}\"}}", e)),
        };
        let res = rt.block_on(async {
            let tester = crate::speed::SpeedTester::new(input.server_url, input.timeout_ms);
            tester.run_test().await
        });

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Wrapper for CIDR expansion.
///
/// Input JSON: `{"cidr": "192.168.1.0/24"}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn expand_cidr_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: CidrExpandInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let res = crate::cidr::expand_cidr(&input.cidr);

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Wrapper for WireGuard probing.
///
/// Input JSON: `{"ip": "10.0.0.1", "port": 51820, "timeout_ms": 2000}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn probe_wg_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: WgProbeInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let rt = match get_runtime() {
            Ok(r) => r,
            Err(e) => return str_to_c_char(&format!("{{\"error\":\"{}\"}}", e)),
        };
        let res = rt.block_on(async {
            let prober = if let Some(decoys) = input.decoy_count {
                crate::wg::WgProber::new_with_decoys(
                    input.ip,
                    input.port,
                    input.timeout_ms,
                    input.padding_len,
                    decoys,
                )
            } else {
                crate::wg::WgProber::new(input.ip, input.port, input.timeout_ms, input.padding_len)
            };
            prober.probe().await
        });

        let json_res = match res {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

#[derive(Deserialize)]
struct CaptivePortalInput {
    timeout_ms: u32,
}

/// Wrapper for captive portal detection.
///
/// Input JSON: `{"timeout_ms": 3000}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn detect_captive_portal_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: CaptivePortalInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let rt = match get_runtime() {
            Ok(r) => r,
            Err(e) => return str_to_c_char(&format!("{{\"error\":\"{}\"}}", e)),
        };
        let res = rt.block_on(async { crate::http::detect_captive_portal(input.timeout_ms).await });

        let json_res =
            serde_json::to_string(&res).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
        str_to_c_char(&json_res)
    })
}

#[derive(Deserialize)]
struct PadClientHelloInput {
    raw_hex: String,
    pad_len: usize,
}

#[derive(Serialize)]
struct PadClientHelloResult {
    padded_hex: Option<String>,
    success: bool,
    error: Option<String>,
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    crate::netutil::hex_decode(s)
}

fn hex_encode(bytes: &[u8]) -> String {
    crate::netutil::hex_encode(bytes)
}

/// Wrapper for ClientHello padding.
///
/// Input JSON: `{"raw_hex": "160301...", "pad_len": 500}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn pad_client_hello_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: PadClientHelloInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let raw_bytes = match hex_decode(&input.raw_hex) {
            Ok(b) => b,
            Err(e) => {
                let res = PadClientHelloResult {
                    padded_hex: None,
                    success: false,
                    error: Some(e),
                };
                return str_to_c_char(
                    &serde_json::to_string(&res)
                        .unwrap_or_else(|_| "{\"error\":\"serialization error\"}".to_string()),
                );
            }
        };

        let res = match crate::tls::pad_client_hello(&raw_bytes, input.pad_len) {
            Ok(padded) => PadClientHelloResult {
                padded_hex: Some(hex_encode(&padded)),
                success: true,
                error: None,
            },
            Err(e) => PadClientHelloResult {
                padded_hex: None,
                success: false,
                error: Some(e.to_string()),
            },
        };

        let json_res =
            serde_json::to_string(&res).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
        str_to_c_char(&json_res)
    })
}

#[derive(Deserialize)]
struct FakePacketInput {
    target_ip: String,
    port: u16,
    ttl: u32,
    flags: Option<u8>,
    seq: Option<u32>,
    ack: Option<u32>,
    payload_hex: String,
}

/// Wrapper for raw fake TCP packet injection.
///
/// Input JSON: `{"target_ip": "192.0.2.1", "port": 443, "ttl": 4, "flags": 24, "payload_hex": "160301..."}`
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn inject_fake_packet_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: FakePacketInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let target_ip = match input.target_ip.parse::<std::net::IpAddr>() {
            Ok(ip) => ip,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid IP: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let payload = match hex_decode(&input.payload_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid Hex payload: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let flags = input.flags.unwrap_or(0x18); // Default to PSH|ACK
        let seq = input.seq.unwrap_or_else(rand::random::<u32>);
        let ack = input.ack.unwrap_or(0);

        let res = crate::tcp::send_fake_packet(
            target_ip, input.port, input.ttl, flags, seq, ack, &payload,
        );

        let json_res = match res {
            Ok(_) => "{\"success\":true}".to_string(),
            Err(e) => format!("{{\"success\":false,\"error\":\"{:?}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Initializes the shared memory packet channel.
///
/// Accepts the raw pointer to the mapped memory and its size.
///
/// # Safety
/// `addr` must reference a valid writable shared-memory region of at least `size` bytes.
#[no_mangle]
pub unsafe extern "C" fn init_shm_ffi(addr: *mut std::ffi::c_void, size: usize) -> i32 {
    if addr.is_null() {
        return -1;
    }
    let expected_size = std::mem::size_of::<crate::shm::SharedChannel>();
    if size < expected_size {
        return -2;
    }

    crate::shm::SHM_CHANNEL.store(
        addr as *mut crate::shm::SharedChannel,
        std::sync::atomic::Ordering::SeqCst,
    );
    0
}

/// Helper FFI to push a packet to Go.
///
/// # Safety
/// `data` must reference at least `len` readable bytes for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn push_packet_ffi(data: *const u8, len: u32) -> i32 {
    let channel_ptr = crate::shm::SHM_CHANNEL.load(std::sync::atomic::Ordering::SeqCst);
    if channel_ptr.is_null() {
        return -1;
    }
    if len as usize > crate::shm::SLOT_SIZE {
        return -3;
    }
    if len != 0 && data.is_null() {
        return -3;
    }
    let slice: &[u8] = if len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(data, len as usize)
    };
    match (*channel_ptr).push_rust_to_go(slice) {
        Ok(_) => 0,
        Err(_) => -2,
    }
}

/// Helper FFI to pop a packet from Go.
/// Returns the length of the popped packet, or 0 if empty.
/// Copies the packet into buffer up to max_len.
///
/// # Safety
/// `buf` must reference at least `max_len` writable bytes for the duration of this call.
#[no_mangle]
pub unsafe extern "C" fn pop_packet_ffi(buf: *mut u8, max_len: u32) -> i32 {
    let channel_ptr = crate::shm::SHM_CHANNEL.load(std::sync::atomic::Ordering::SeqCst);
    if channel_ptr.is_null() {
        return -1;
    }
    if max_len == 0 || buf.is_null() {
        return -3;
    }
    match (*channel_ptr).pop_go_to_rust() {
        Some(packet) => {
            let copy_len = std::cmp::min(packet.len(), max_len as usize);
            std::ptr::copy_nonoverlapping(packet.as_ptr(), buf, copy_len);
            copy_len as i32
        }
        None => 0,
    }
}

#[derive(Deserialize)]
struct DisasmInput {
    payload_hex: String,
    arch: String,
}

/// Disassembles custom raw network payload bytes using Capstone.
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn disassemble_shellcode_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: DisasmInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let payload = match hex_decode(&input.payload_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                let err_json = format!("{{\"error\":\"Invalid hex payload: {}\"}}", e);
                return str_to_c_char(&err_json);
            }
        };

        let res = crate::tcp::disassemble_payload(&payload, &input.arch);
        let json_res = match res {
            Ok(disassembly) => {
                let val = serde_json::json!({
                    "success": true,
                    "disassembly": disassembly,
                });
                val.to_string()
            }
            Err(e) => format!("{{\"success\":false,\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

// ─── New Security, DNS & Platform FFI Interfaces ───────────────────

#[derive(Deserialize)]
struct AnomalyCheckInput {
    current: crate::security::anomaly::LoginRecord,
    history: Vec<crate::security::anomaly::LoginRecord>,
    config: Option<crate::security::anomaly::DetectionConfig>,
}

#[derive(Deserialize)]
struct HostsOptimizeInput {
    domains: Vec<String>,
}

#[derive(Deserialize)]
struct MemoryPatchInput {
    pid: u32,
    target_hex: String,
    replacement_hex: String,
}

#[derive(Deserialize)]
struct DecryptCookiesInput {
    target_host: String,
}

#[derive(Deserialize)]
struct StartAdbForwarderInput {
    local_port: u16,
    target_port: u16,
}

/// Run security anomaly analysis on a login attempt.
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn analyze_anomaly_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: AnomalyCheckInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let config = input.config.unwrap_or_default();
        let detector = crate::security::anomaly::AnomalyDetector::new(&config);
        let res = detector.analyze(&input.current, &input.history);

        let json_res =
            serde_json::to_string(&res).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
        str_to_c_char(&json_res)
    })
}

/// Optimize hosts mappings for a set of domains via DoH and test TCP latency.
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn optimize_hosts_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: HostsOptimizeInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let rt = match get_runtime() {
            Ok(r) => r,
            Err(e) => return str_to_c_char(&format!("{{\"error\":\"{}\"}}", e)),
        };

        let res = rt
            .block_on(async { crate::dns::hosts_optimizer::optimize_hosts(&input.domains).await });

        let json_res =
            serde_json::to_string(&res).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e));
        str_to_c_char(&json_res)
    })
}

/// Scan process memory space and replace matching byte sequences.
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn patch_memory_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: MemoryPatchInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let target = match hex_decode(&input.target_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                return str_to_c_char(&format!("{{\"error\":\"Invalid target hex: {}\"}}", e))
            }
        };

        let replacement = match hex_decode(&input.replacement_hex) {
            Ok(bytes) => bytes,
            Err(e) => {
                return str_to_c_char(&format!("{{\"error\":\"Invalid replacement hex: {}\"}}", e))
            }
        };

        let res = crate::security::memory::scan_and_replace(input.pid, &target, &replacement);
        let json_res = match res {
            Ok(count) => format!("{{\"success\":true,\"count\":{}}}", count),
            Err(e) => format!("{{\"success\":false,\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Decrypt session credentials and cookies for a target browser host.
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn decrypt_cookies_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: DecryptCookiesInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let res = crate::security::credentials::extract_chrome_cookies(&input.target_host);
        let json_res = match res {
            Ok(cookies) => serde_json::to_string(&cookies)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Bridge active connections and trace their process ownership details.
///
/// # Safety
/// This C-ABI entry point has no raw-pointer arguments; callers must free the returned string with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn get_active_connections_ffi() -> *mut c_char {
    catch_json_ffi(|| {
        let res = crate::netutil::supervision::get_active_connections();
        let json_res = match res {
            Ok(connections) => serde_json::to_string(&connections)
                .unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e)),
            Err(e) => format!("{{\"error\":\"{}\"}}", e),
        };
        str_to_c_char(&json_res)
    })
}

/// Start async ADB forwarder port multiplexer daemon.
///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn start_adb_forwarder_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: StartAdbForwarderInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        // We run it in a separate thread so it doesn't block the CGO caller.
        // We return success once it binds local port.
        let local_port = input.local_port;
        let target_port = input.target_port;

        std::thread::spawn(move || {
            let (tx, rx) = tokio::sync::oneshot::channel();
            // Drop tx immediately since we keep it running indefinitely or let it live.
            let _ = tx;
            if let Ok(rt) = tokio::runtime::Runtime::new() {
                let _ = rt.block_on(async {
                    crate::platform::android::start_adb_forwarder(local_port, target_port, rx).await
                });
            }
        });

        str_to_c_char("{\"success\":true}")
    })
}

#[derive(Deserialize)]
struct CraftPacketInput {
    packet_type: String, // "tcp_syn", "udp", "icmp_echo"
    src_ip: String,      // e.g. "127.0.0.1"
    dest_ip: String,     // e.g. "127.0.0.1"
    src_port: u16,
    dest_port: u16,
    options_base64: Option<String>,
    payload_base64: String,
}

#[derive(Serialize)]
struct CraftPacketOutput {
    packet_base64: String,
}

///
/// # Safety
/// `input_json` must point to a readable NUL-terminated UTF-8 JSON string for the duration of this call.
/// The returned string is owned by Rust and must be released with `free_string`.
#[no_mangle]
pub unsafe extern "C" fn craft_packet_ffi(input_json: *const c_char) -> *mut c_char {
    catch_json_ffi(|| {
        let input: CraftPacketInput = match unsafe { parse_json_input(input_json) } {
            Ok(input) => input,
            Err(err) => return json_error(err),
        };

        let src_ip_parsed: std::net::Ipv4Addr = match input.src_ip.parse() {
            Ok(ip) => ip,
            Err(_) => return str_to_c_char("{\"error\":\"Invalid source IP\"}"),
        };

        let dest_ip_parsed: std::net::Ipv4Addr = match input.dest_ip.parse() {
            Ok(ip) => ip,
            Err(_) => return str_to_c_char("{\"error\":\"Invalid destination IP\"}"),
        };

        use base64::prelude::*;
        let payload = BASE64_STANDARD
            .decode(&input.payload_base64)
            .unwrap_or_default();

        let crafter = crate::scanner::packet_crafting::PacketCrafting::new();
        let packet_bytes = match input.packet_type.as_str() {
            "tcp_syn" => {
                let options = input
                    .options_base64
                    .as_ref()
                    .and_then(|opt| BASE64_STANDARD.decode(opt).ok())
                    .unwrap_or_default();
                crafter.craft_tcp_syn(
                    src_ip_parsed.octets(),
                    dest_ip_parsed.octets(),
                    input.src_port,
                    input.dest_port,
                    &options,
                    &payload,
                )
            }
            "udp" => crafter.craft_udp(
                src_ip_parsed.octets(),
                dest_ip_parsed.octets(),
                input.src_port,
                input.dest_port,
                &payload,
            ),
            "icmp_echo" => {
                // For icmp, we map src_port to identifier, dest_port to sequence
                crafter.craft_icmp_echo(
                    src_ip_parsed.octets(),
                    dest_ip_parsed.octets(),
                    input.src_port,
                    input.dest_port,
                    &payload,
                )
            }
            _ => return str_to_c_char("{\"error\":\"Unsupported packet type\"}"),
        };

        let encoded = BASE64_STANDARD.encode(&packet_bytes);
        let out_json = serde_json::to_string(&CraftPacketOutput {
            packet_base64: encoded,
        })
        .unwrap();
        str_to_c_char(&out_json)
    })
}
