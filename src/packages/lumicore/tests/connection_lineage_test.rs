use lumicore::platform::{
    drain_terminal_lines, normalize_probe_addr, port_is_live, read_pid,
    reap_orphan_process, strip_ansi, write_pid, ConnectionState, LineageAction, LineageManager,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

#[test]
fn test_lineage_manager_state_transitions() {
    let mut manager = LineageManager::default_policy();
    assert_eq!(*manager.state(), ConnectionState::Idle);

    assert!(manager.on_user_connect().is_ok());
    assert_eq!(*manager.state(), ConnectionState::Launching);

    // Double connect while active fails
    assert!(manager.on_user_connect().is_err());

    manager.on_connecting();
    assert_eq!(*manager.state(), ConnectionState::Connecting);

    manager.on_connected("127.0.0.1:1819".to_string());
    match manager.state() {
        ConnectionState::Connected { socks_addr, connected_at_ms } => {
            assert_eq!(socks_addr, "127.0.0.1:1819");
            assert!(*connected_at_ms > 0);
        }
        _ => panic!("expected Connected state"),
    }

    manager.on_user_disconnect();
    assert_eq!(*manager.state(), ConnectionState::Disconnecting);
    assert!(manager.is_user_stopping());

    manager.on_disconnected();
    assert_eq!(*manager.state(), ConnectionState::Idle);
    assert!(!manager.is_user_stopping());
}

#[test]
fn test_lineage_retry_budget_and_recovery() {
    let mut manager = LineageManager::new(
        2,
        vec![Duration::from_millis(5), Duration::from_millis(10)],
    );

    manager.on_user_connect().unwrap();

    // 1st drop
    let act1 = manager.on_unexpected_drop("network dropped");
    assert_eq!(
        act1,
        LineageAction::Retry {
            attempt: 1,
            backoff: Duration::from_millis(5)
        }
    );
    assert_eq!(
        *manager.state(),
        ConnectionState::Reconnecting {
            attempt: 1,
            max_attempts: 2
        }
    );

    manager.on_retry_launch();
    assert_eq!(*manager.state(), ConnectionState::Launching);

    // 2nd drop
    let act2 = manager.on_unexpected_drop("route scan timeout");
    assert_eq!(
        act2,
        LineageAction::Retry {
            attempt: 2,
            backoff: Duration::from_millis(10)
        }
    );

    manager.on_retry_launch();

    // 3rd drop -> budget exceeded
    let act3 = manager.on_unexpected_drop("server unreachable");
    match act3 {
        LineageAction::Exhausted { message } => {
            assert!(message.contains("exhausted 2 retries"));
        }
        _ => panic!("expected exhausted action"),
    }
    match manager.state() {
        ConnectionState::Error { message, phase } => {
            assert_eq!(phase, "exhausted");
            assert!(message.contains("exhausted 2 retries"));
        }
        _ => panic!("expected Error state"),
    }
}

#[test]
fn test_port_probe_and_normalization() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let real_addr = listener.local_addr().unwrap();

    let probe_any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), real_addr.port());
    let normalized = normalize_probe_addr(&probe_any);
    assert_eq!(normalized.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

    // Spawn accept loop thread
    thread::spawn(move || {
        while let Ok((_stream, _)) = listener.accept() {
            // Keep accepting until test finishes and listener is dropped
        }
    });

    assert!(port_is_live(&real_addr, Duration::from_millis(500)));
    assert!(port_is_live(&probe_any, Duration::from_millis(500)));

    let dead_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 59999);
    assert!(!port_is_live(&dead_addr, Duration::from_millis(50)));
}

#[test]
fn test_terminal_stream_drain_and_ansi() {
    let color_text = "\x1b[31m[ERROR]\x1b[0m Connection to gateway \x1b[32msucceeded\x1b[0m";
    assert_eq!(strip_ansi(color_text), "[ERROR] Connection to gateway succeeded");

    let mut buf = "probe 10%\rprobe 40%\rprobe 100%\r\nconnected ok\n".to_string();
    let lines = drain_terminal_lines(&mut buf);
    assert_eq!(lines, vec!["probe 100%", "connected ok"]);
    assert_eq!(buf, "");
}

#[test]
fn test_process_reaper_pid_lifecycle() {
    let tmp = std::env::temp_dir().join(format!("lumitest_reaper_int_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp);

    let sname = "sidecar_daemon";
    write_pid(&tmp, sname, 44444).unwrap();
    assert_eq!(read_pid(&tmp, sname), Some(44444));

    // Non-existent PID
    let reaped = reap_orphan_process(&tmp, sname);
    assert_eq!(reaped, None); // 44444 was not alive
    assert_eq!(read_pid(&tmp, sname), None); // PID file cleared

    let _ = std::fs::remove_dir_all(&tmp);
}
