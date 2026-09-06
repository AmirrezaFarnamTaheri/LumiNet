use lumicore::speed::batch_speed_matrix::{
    BatchSpeedMatrix, BatchSpeedOptions, SpeedActionType, SpeedCandidate,
};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_tcp_ping_success() {
    // Bind a temporary local TCP listener
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
    let local_port = listener.local_addr().expect("local addr").port();

    let matrix = BatchSpeedMatrix::new(BatchSpeedOptions {
        page_size: 5,
        delay_interval_ms: 10,
        probe_timeout_ms: 1000,
        test_url: "https://www.gstatic.com/generate_204".to_string(),
    });

    let (succ, rtt, err) = matrix.test_tcp_ping("127.0.0.1", local_port).await;
    assert!(succ, "Expected TCP ping success, got error: {:?}", err);
    assert!(rtt.is_some());
    assert!(rtt.unwrap() < 1000);
}

#[tokio::test]
async fn test_tcp_ping_unreachable() {
    let matrix = BatchSpeedMatrix::new(BatchSpeedOptions {
        page_size: 5,
        delay_interval_ms: 0,
        probe_timeout_ms: 200,
        test_url: "https://www.gstatic.com/generate_204".to_string(),
    });

    // Port 1 on localhost is normally closed
    let (succ, rtt, _err) = matrix.test_tcp_ping("127.0.0.1", 1).await;
    assert!(!succ);
    assert!(rtt.is_none());
}

#[tokio::test]
async fn test_cancellation_and_batch() {
    let matrix = BatchSpeedMatrix::new(BatchSpeedOptions {
        page_size: 2,
        delay_interval_ms: 10,
        probe_timeout_ms: 500,
        test_url: "https://www.gstatic.com/generate_204".to_string(),
    });

    let candidates = vec![
        SpeedCandidate {
            tag: "Node1".to_string(),
            address: "127.0.0.1".to_string(),
            port: 80,
            proxy_inbound_port: None,
        },
        SpeedCandidate {
            tag: "Node2".to_string(),
            address: "127.0.0.1".to_string(),
            port: 80,
            proxy_inbound_port: None,
        },
    ];

    // Trigger cancellation immediately
    matrix.cancel();
    assert!(matrix.cancellation_handle().load(std::sync::atomic::Ordering::SeqCst));

    let results = matrix.run_batch(SpeedActionType::TcpPing, &candidates).await;
    // With immediate cancellation before chunk iteration, results should be empty
    assert!(results.is_empty());
}
