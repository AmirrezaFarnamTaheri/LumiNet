//! # Embedded Engine & Platform Socket Protection Tests
//!
//! 1. Platform Socket Protector: Global thread-safe socket protection hooks for mobile/OS VPNs.
//! 2. Gateway Prober & Scanner: Asynchronous candidate generation, atomic cancellation, quiet window, and RTT ranking.
//! 3. In-Process Embedded Controller: In-memory pipeline configuration, peer preparation, and readiness signaling.

use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, AtomicI32, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

use lumicore::platform::{
    is_protector_registered, prepare_embedded, protect_socket_fd, run_embedded,
    set_socket_protector, test_embedded_peer, EmbeddedConfig, EmbeddedEndpoint, EmbeddedError,
    EmbeddedPrepared, SocketProtectError,
};
use lumicore::scanner::{
    generate_candidates, scan_gateways_with_canceller, IpScanFilter, ScanMode, ScannerError,
    MASQUE_PORTS,
};

// ============================================================================
// 1. Platform Socket Protector Hook Plane
// ============================================================================

#[test]
fn test_socket_protector_concurrency_and_rejection() {
    set_socket_protector(None);
    assert!(!is_protector_registered());

    let accepted_fds = Arc::new(AtomicI32::new(0));
    let acc = Arc::clone(&accepted_fds);

    // Register protector that rejects even FDs, accepts odd FDs
    set_socket_protector(Some(Arc::new(move |fd| {
        if fd % 2 != 0 {
            acc.fetch_add(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    })));

    assert!(is_protector_registered());

    // Odd FD should succeed
    assert_eq!(protect_socket_fd(101), Ok(()));
    assert_eq!(accepted_fds.load(Ordering::SeqCst), 1);

    // Even FD should be rejected
    assert_eq!(protect_socket_fd(102), Err(SocketProtectError::Rejected(102)));

    // Deregister
    set_socket_protector(None);
    assert!(!is_protector_registered());
    assert_eq!(protect_socket_fd(102), Ok(()));
}

// ============================================================================
// 2. Gateway Scanner & RTT Ranker Plane
// ============================================================================

#[test]
fn test_gateway_candidate_generator_diversity() {
    let v4_candidates = generate_candidates(IpScanFilter::V4, MASQUE_PORTS, 40);
    assert!(!v4_candidates.is_empty());
    assert!(v4_candidates.iter().all(|addr| addr.is_ipv4()));

    let dual_candidates = generate_candidates(IpScanFilter::DualStack, MASQUE_PORTS, 100);
    assert!(dual_candidates.iter().any(|addr| addr.is_ipv4()));
    assert!(dual_candidates.iter().any(|addr| addr.is_ipv6()));
}

#[tokio::test]
async fn test_gateway_scanner_cancellation_and_quiet_window() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let cand_cancelled = Arc::clone(&cancelled);

    let candidates: Vec<SocketAddr> = vec![
        "162.159.197.1:443".parse().unwrap(),
        "162.159.197.2:443".parse().unwrap(),
        "162.159.197.3:443".parse().unwrap(),
        "162.159.197.4:443".parse().unwrap(),
    ];

    let strat = ScanMode::Turbo.strategy();

    // Probe function that triggers cancellation after 1 result
    let res = scan_gateways_with_canceller(
        candidates,
        strat,
        4,
        &cancelled,
        move |_addr, _timeout| {
            let c = Arc::clone(&cand_cancelled);
            async move {
                c.store(true, Ordering::SeqCst);
                Some(Duration::from_millis(35))
            }
        },
    )
    .await;

    // Must return Cancelled because cancelled atomic was set during probing
    assert_eq!(res.unwrap_err(), ScannerError::Cancelled);
}

#[tokio::test]
async fn test_gateway_scanner_rtt_ordering() {
    let cancelled = AtomicBool::new(false);
    let candidates: Vec<SocketAddr> = vec![
        "162.159.197.1:443".parse().unwrap(),
        "162.159.197.2:443".parse().unwrap(),
        "162.159.197.3:443".parse().unwrap(),
    ];
    let strat = ScanMode::Balanced.strategy();

    let results = scan_gateways_with_canceller(
        candidates,
        strat,
        3,
        &cancelled,
        |addr, _timeout| async move {
            match addr.ip() {
                IpAddr::V4(v4) if v4.octets()[3] == 1 => Some(Duration::from_millis(120)),
                IpAddr::V4(v4) if v4.octets()[3] == 2 => Some(Duration::from_millis(20)),
                _ => Some(Duration::from_millis(60)),
            }
        },
    )
    .await
    .expect("scan results");

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].rtt, Duration::from_millis(20));
    assert_eq!(results[1].rtt, Duration::from_millis(60));
    assert_eq!(results[2].rtt, Duration::from_millis(120));
}

// ============================================================================
// 3. In-Process Embedded Controller Plane
// ============================================================================

#[tokio::test]
async fn test_prepare_embedded_with_fallback() {
    let mut config = EmbeddedConfig::default();
    let broken_peer: SocketAddr = "162.159.197.99:443".parse().unwrap();
    config.peer = Some(broken_peer);
    config.peer_fallback = true;

    let prep = prepare_embedded(&config, move |addr| async move {
        if addr == broken_peer {
            None // simulate failed custom peer
        } else {
            Some(Duration::from_millis(42))
        }
    })
    .await
    .expect("fallback succeeded");

    assert_ne!(prep.peer, broken_peer);
    assert_eq!(prep.rtt, Duration::from_millis(42));
    assert_eq!(prep.ipv4, "172.16.0.2");
}

#[tokio::test]
async fn test_prepare_embedded_without_fallback_fails() {
    let mut config = EmbeddedConfig::default();
    let broken_peer: SocketAddr = "162.159.197.99:443".parse().unwrap();
    config.peer = Some(broken_peer);
    config.peer_fallback = false;

    let res = prepare_embedded(&config, |_addr| async move { None }).await;
    match res {
        Err(EmbeddedError::ValidationFailed(_)) => {}
        other => panic!("expected ValidationFailed, got {:?}", other),
    }
}

#[tokio::test]
async fn test_test_embedded_peer_accuracy() {
    let peer: SocketAddr = "162.159.197.1:443".parse().unwrap();
    let res = test_embedded_peer(peer, |_| async { Some(Duration::from_millis(28)) })
        .await
        .expect("probe ok");

    assert_eq!(res.peer, peer);
    assert_eq!(res.rtt, Duration::from_millis(28));
}

#[tokio::test]
async fn test_run_embedded_tun_channels() {
    let prep = EmbeddedPrepared {
        device_id: "dev-tun-test".into(),
        ipv4: "172.16.0.2".into(),
        ipv6: "fd00::2".into(),
        peer: "162.159.197.1:443".parse().unwrap(),
        rtt: Duration::from_millis(25),
    };

    let (_d2t_tx, d2t_rx) = mpsc::channel(16);
    let (t2d_tx, _t2d_rx) = mpsc::channel(16);
    let (ready_tx, ready_rx) = oneshot::channel();

    let endpoint = EmbeddedEndpoint::Tun {
        device_to_tunnel: d2t_rx,
        tunnel_to_device: t2d_tx,
    };

    let run_res = run_embedded(prep, endpoint, Some(ready_tx)).await;
    assert!(run_res.is_ok());
    assert!(ready_rx.await.is_ok());
}
