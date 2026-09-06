//! Unit and integration tests for multi-core tunnel process supervisor and log telemetry engine.

use lumicore::relay::multi_core_supervisor::*;

#[test]
fn test_wsl_noise_detection() {
    assert!(is_wsl_noise("wsl: A localhost proxy is listening on port 1080"));
    assert!(is_wsl_noise("NAT mode does not support port forwarding"));
    assert!(is_wsl_noise("Port not mirrored into WSL"));
    assert!(!is_wsl_noise("Fatal error: connection refused"));
    assert!(!is_wsl_noise("Tunnel established successfully"));
}

#[test]
fn test_binary_info_pattern_detection() {
    assert!(is_binary_info_pattern("CARRIER INFO relay ok: 200 OK"));
    assert!(is_binary_info_pattern("CLIENT INFO dial direct google"));
    assert!(is_binary_info_pattern("SOCKS INFO new session 127.0.0.1:54321"));
    assert!(is_binary_info_pattern("2026/09/04 18:00:00 [FlowDriver] Tunnel up"));
    assert!(is_binary_info_pattern("Zero-Config storage initialized"));
    assert!(!is_binary_info_pattern("Failed to bind socket: address already in use"));
}

#[test]
fn test_oauth_url_extraction() {
    let line1 = "Please open the following link: https://accounts.google.com/o/oauth2/auth?client_id=123&response_type=code in your browser";
    assert_eq!(
        extract_oauth_url(line1),
        Some("https://accounts.google.com/o/oauth2/auth?client_id=123&response_type=code".to_string())
    );

    let line2 = "Ordinary log message without any link";
    assert_eq!(extract_oauth_url(line2), None);
}

#[test]
fn test_log_line_classification() {
    // Normal stdout info
    let (lvl1, url1) = classify_log_line("SOCKS5 server listening on 127.0.0.1:1080", false);
    assert_eq!(lvl1, LogLevel::Info);
    assert_eq!(url1, None);

    // Stderr that is actually Go/WSL info
    let (lvl2, url2) = classify_log_line("wsl: localhost proxy attached", true);
    assert_eq!(lvl2, LogLevel::Info);
    assert_eq!(url2, None);

    let (lvl3, url3) = classify_log_line("CARRIER INFO relay returned 200", true);
    assert_eq!(lvl3, LogLevel::Info);
    assert_eq!(url3, None);

    // Genuine stderr error
    let (lvl4, url4) = classify_log_line("panic: runtime error: invalid memory address", true);
    assert_eq!(lvl4, LogLevel::Error);
    assert_eq!(url4, None);

    // OAuth URL prompt in stderr/stdout
    let (lvl5, url5) = classify_log_line("Visit https://accounts.google.com/o/oauth2/auth?scope=drive to authorize", true);
    assert_eq!(lvl5, LogLevel::OAuth);
    assert!(url5.is_some());
}

#[test]
fn test_log_ring_buffer() {
    let mut ring = CoreLogRingBuffer::new(3);
    assert_eq!(ring.len(), 0);

    ring.push(LogLevel::Info, "log 1".to_string());
    ring.push(LogLevel::Info, "log 2".to_string());
    ring.push(LogLevel::Info, "log 3".to_string());
    assert_eq!(ring.len(), 3);

    // Adding 4th should evict the 1st
    ring.push(LogLevel::Warn, "log 4".to_string());
    assert_eq!(ring.len(), 3);

    let recent = ring.get_recent(10);
    assert_eq!(recent.len(), 3);
    assert_eq!(recent[0].message, "log 2");
    assert_eq!(recent[1].message, "log 3");
    assert_eq!(recent[2].message, "log 4");
}

#[test]
fn test_core_stats_counter() {
    let mut stats = CoreStatsCounter::new();
    assert_eq!(stats.total_requests, 0);
    assert_eq!(stats.today_requests, 0);

    stats.increment(5);
    assert_eq!(stats.total_requests, 5);
    assert_eq!(stats.today_requests, 5);

    stats.increment(10);
    assert_eq!(stats.total_requests, 15);
    assert_eq!(stats.today_requests, 15);

    stats.reset_daily();
    assert_eq!(stats.total_requests, 15);
    assert_eq!(stats.today_requests, 0);
}

#[test]
fn test_apps_script_core_config_synthesis() {
    let cfg = AppsScriptCoreConfig {
        socks_host: "127.0.0.1".to_string(),
        socks_port: 1080,
        google_host: "216.239.38.120".to_string(),
        sni: Some(serde_json::json!(["www.google.com", "mail.google.com"])),
        script_keys: vec!["AKfycbx...".to_string(), "AKfycby...".to_string()],
        tunnel_key: "my-secret-tunnel-key".to_string(),
        socks_user: Some("admin".to_string()),
        socks_pass: Some("password".to_string()),
    };

    let json_str = cfg.to_json_string().expect("serialize should succeed");
    assert!(json_str.contains("\"socks_port\": 1080"));
    assert!(json_str.contains("\"google_host\": \"216.239.38.120\""));
    assert!(json_str.contains("\"script_keys\""));
    assert!(json_str.contains("\"socks_user\": \"admin\""));
}

#[test]
fn test_drive_storage_core_config_synthesis() {
    let cfg = DriveStorageCoreConfig::new_google_drive(
        "127.0.0.1:1080".to_string(),
        Some("folder-id-xyz".to_string()),
        200,
        300,
        "216.239.38.120:443".to_string(),
        "google.com".to_string(),
        "www.googleapis.com".to_string(),
    );

    let json_str = cfg.to_json_string().expect("serialize should succeed");
    assert!(json_str.contains("\"listen_addr\": \"127.0.0.1:1080\""));
    assert!(json_str.contains("\"storage_type\": \"google\""));
    assert!(json_str.contains("\"google_folder_id\": \"folder-id-xyz\""));
    assert!(json_str.contains("\"TargetIP\": \"216.239.38.120:443\""));
    assert!(json_str.contains("\"HostHeader\": \"www.googleapis.com\""));
}
