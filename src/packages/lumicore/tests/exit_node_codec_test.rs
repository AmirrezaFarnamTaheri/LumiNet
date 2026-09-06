use lumicore::relay::exit_node_codec::*;
use std::collections::HashMap;

#[test]
fn test_ssrf_safety_validation() {
    // Valid public targets
    assert!(is_safe_url("https://example.com/api"));
    assert!(is_safe_url("http://93.184.216.34:8080/index.html"));
    assert!(is_safe_url("https://dns.google/resolve"));

    // Blocked internal / loopback / private targets
    assert!(!is_safe_url("http://localhost:8080/"));
    assert!(!is_safe_url("https://localhost/"));
    assert!(!is_safe_url("http://server.local/"));
    assert!(!is_safe_url("http://router.lan/"));
    assert!(!is_safe_url("http://127.0.0.1/admin"));
    assert!(!is_safe_url("http://127.0.0.5:9000/"));
    assert!(!is_safe_url("http://0.0.0.0/"));
    assert!(!is_safe_url("http://10.0.0.1/secret"));
    assert!(!is_safe_url("http://172.20.1.1/internal"));
    assert!(!is_safe_url("http://192.168.1.1/router"));
    assert!(!is_safe_url("http://169.254.169.254/latest/meta-data"));
    assert!(!is_safe_url("http://[::1]/debug"));
    assert!(!is_safe_url("ftp://example.com/file"));
}

#[test]
fn test_loop_detection() {
    // 1. Self loop
    let err = detect_relay_loop("https://exit.luminet.internal:8181/proxy", "exit.luminet.internal:8181", false);
    assert!(matches!(err, Err(RelayLoopError::SelfLoop(_))));

    // 2. Hop relay loop (GAS -> Exit -> GAS)
    let hop_err = detect_relay_loop(
        "https://script.google.com/macros/s/AKfycbx123/exec",
        "exit.worker.dev",
        true,
    );
    assert!(matches!(hop_err, Err(RelayLoopError::HopRelayLoop(_))));

    // 3. Normal request (no loop)
    let ok = detect_relay_loop("https://api.github.com/zen", "exit.worker.dev", false);
    assert!(ok.is_ok());
}

#[test]
fn test_relay_error_classification_and_envelope() {
    let quota_err = "Service invoked too many times for one day: urlfetch.";
    let friendly = classify_relay_error(quota_err);
    assert!(friendly.contains("quota exhausted"));

    let auth_err = "Exception: Authorization is required to perform that action.";
    let friendly_auth = classify_relay_error(auth_err);
    assert!(friendly_auth.contains("rejected the request (auth/permission error)"));

    let deploy_err = "Script ID not found or deployment inactive";
    let friendly_deploy = classify_relay_error(deploy_err);
    assert!(friendly_deploy.contains("deployment not found"));

    // Test envelope classification
    let envelope_json = r#"{"e": "Service invoked too many times: urlfetch"}"#;
    let (cat, raw) = classify_relay_envelope(envelope_json.as_bytes());
    assert_eq!(cat, Some(PermanentCategory::Quota));
    assert_eq!(raw, "Service invoked too many times: urlfetch");
}

#[test]
fn test_split_set_cookie_preserves_date_commas() {
    let raw = "session=xyz123; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/, token=abc456; Secure; HttpOnly";
    let cookies = split_set_cookie(raw);
    assert_eq!(cookies.len(), 2);
    assert_eq!(cookies[0], "session=xyz123; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/");
    assert_eq!(cookies[1], "token=abc456; Secure; HttpOnly");
}

#[test]
fn test_parse_hosts_text() {
    let hosts_data = "
# Adblock test list
0.0.0.0 ads.example.com # inline comment
127.0.0.1 tracker.analytics.org
::1 telemetry.badsite.net
malware-direct.biz
# bad entries to skip:
*.wildcard.com
localhost
192.168.1.1
invalid_domain
0.0.0.0 ads.example.com # duplicate
";
    let parsed = parse_hosts_text(hosts_data);
    assert_eq!(parsed.len(), 4);
    assert!(parsed.contains(&"ads.example.com".to_string()));
    assert!(parsed.contains(&"tracker.analytics.org".to_string()));
    assert!(parsed.contains(&"telemetry.badsite.net".to_string()));
    assert!(parsed.contains(&"malware-direct.biz".to_string()));
}

#[test]
fn test_unpack_relay_response_to_http() {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), serde_json::Value::String("text/plain".to_string()));
    headers.insert("x-custom-tag".to_string(), serde_json::Value::String("lumi-relay".to_string()));

    let body_bytes = b"Hello from LumiNet Relay!";
    let b64_body = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, body_bytes);

    let resp = ExitNodeResponse {
        s: 200,
        h: headers,
        b: Some(b64_body),
        e: None,
        gz: None,
    };

    let http_raw = unpack_relay_response_to_http(&resp, 1024 * 1024).expect("Failed to unpack");
    let http_str = String::from_utf8_lossy(&http_raw);

    assert!(http_str.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(http_str.contains("content-type: text/plain\r\n"));
    assert!(http_str.contains("x-custom-tag: lumi-relay\r\n"));
    assert!(http_str.contains(&format!("Content-Length: {}\r\n\r\n", body_bytes.len())));
    assert!(http_str.ends_with("Hello from LumiNet Relay!"));
}
