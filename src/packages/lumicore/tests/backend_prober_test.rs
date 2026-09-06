use lumicore::scanner::backend_prober::{
    analyze_probe_response, build_websocket_handshake_request, TrafficMeter,
};

#[test]
fn test_build_websocket_handshake_request_valid() {
    let url = "https://backend.example.com:8443";
    let (req, target_tried, host_only) =
        build_websocket_handshake_request(url, Some("/custom-ws")).unwrap();

    assert_eq!(target_tried, "https://backend.example.com:8443/custom-ws");
    assert_eq!(host_only, "backend.example.com");
    assert!(req.starts_with("GET /custom-ws HTTP/1.1\r\n"));
    assert!(req.contains("Host: backend.example.com\r\n"));
    assert!(req.contains("Upgrade: websocket\r\n"));
    assert!(req.contains("Connection: Upgrade\r\n"));
    assert!(req.contains("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
    assert!(req.contains("Sec-WebSocket-Version: 13\r\n\r\n"));
}

#[test]
fn test_build_websocket_handshake_request_default_path() {
    let url = "http://198.51.100.1";
    let (req, target_tried, host_only) =
        build_websocket_handshake_request(url, None).unwrap();

    assert_eq!(target_tried, "http://198.51.100.1/novavpn");
    assert_eq!(host_only, "198.51.100.1");
    assert!(req.starts_with("GET /novavpn HTTP/1.1\r\n"));
}

#[test]
fn test_build_websocket_handshake_request_invalid() {
    assert!(build_websocket_handshake_request("", None).is_err());
    assert!(build_websocket_handshake_request("ftp://example.com", None).is_err());
}

#[test]
fn test_analyze_probe_response_success() {
    let (ok, steps, hint) = analyze_probe_response(101, "nginx/1.24", "example.com", 85, true);
    assert!(ok);
    assert!(hint.is_none());
    assert!(steps[0].contains("SUCCESS"));
}

#[test]
fn test_analyze_probe_response_edge_ssrf_raw_ip() {
    let (ok, steps, hint) =
        analyze_probe_response(403, "cloudflare", "203.0.113.195", 42, false);
    assert!(!ok);
    assert!(steps[0].contains("Edge SSRF sandbox blocks bare IP"));
    assert!(hint.is_some());
    assert!(hint.unwrap().contains("DNS-only"));
}

#[test]
fn test_analyze_probe_response_path_mismatch() {
    let (ok, steps, hint) =
        analyze_probe_response(403, "nginx", "proxy.mydomain.com", 250, false);
    assert!(!ok);
    assert!(steps[0].contains("wsSettings.path"));
    assert!(hint.is_some());
}

#[test]
fn test_traffic_meter_accounting() {
    let mut meter = TrafficMeter::new("client_user_01");
    assert_eq!(meter.user_id, "client_user_01");
    assert_eq!(meter.total_bytes(), 0);

    meter.record_up(1024);
    meter.record_down(4096);

    assert_eq!(meter.up_bytes, 1024);
    assert_eq!(meter.down_bytes, 4096);
    assert_eq!(meter.total_bytes(), 5120);
}
