//! # Async Job Coordinator & Broadcast Hub Tests (TDD RED Phase)
//!
//! Verifies concurrent job lifecycle execution, multi-subscriber event broadcasting,
//! and cooperative cancellation via CancellationToken.
//!
//! Source: Tokio async broadcast <https://docs.rs/tokio/latest/tokio/sync/broadcast/>
//! Best Practices: /leonardomso-rust-skills (async-broadcast-pubsub, async-cancellation-token, type-enum-states)

use lumicore::jobs::{
    BroadcastHub, JobCoordinator, JobEvent, JobEventType, JobStatus,
};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_job_coordinator_lifecycle() {
    let coordinator = JobCoordinator::new(100);

    let job_id = coordinator
        .submit_job("test-job-1", "echo", |cancel_token| async move {
            if cancel_token.is_cancelled() {
                return Err("cancelled early".into());
            }
            sleep(Duration::from_millis(50)).await;
            Ok("computation complete".to_string())
        })
        .await
        .expect("job should submit");

    // Wait for job to finish
    let result = coordinator.wait_for_completion(&job_id, Duration::from_secs(2)).await;
    assert!(result.is_ok());

    let state = coordinator.get_job_status(&job_id).expect("job should exist");
    assert_eq!(state, JobStatus::Succeeded);
}

#[tokio::test]
async fn test_broadcast_hub_fanout() {
    let hub = BroadcastHub::new(64);
    let mut rx1 = hub.subscribe();
    let mut rx2 = hub.subscribe();

    let event = JobEvent {
        job_id: "stream-job-42".to_string(),
        event_type: JobEventType::Progress { percentage: 75 },
        payload: "scanned 75/100 ports".to_string(),
    };

    hub.publish(event.clone()).expect("publish should succeed");

    let received1 = rx1.recv().await.expect("rx1 should receive event");
    let received2 = rx2.recv().await.expect("rx2 should receive event");

    assert_eq!(received1.job_id, "stream-job-42");
    assert_eq!(received2.job_id, "stream-job-42");
    assert_eq!(received1.payload, "scanned 75/100 ports");
    assert_eq!(received2.payload, "scanned 75/100 ports");
}

#[tokio::test]
async fn test_job_cancellation() {
    let coordinator = JobCoordinator::new(100);

    let job_id = coordinator
        .submit_job("infinite-job", "scanner", |cancel_token| async move {
            loop {
                if cancel_token.is_cancelled() {
                    return Err("aborted by cancellation token".into());
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("job should submit");

    sleep(Duration::from_millis(30)).await;
    let cancelled = coordinator.cancel_job(&job_id).await;
    assert!(cancelled, "cancel_job should return true");

    sleep(Duration::from_millis(50)).await;
    let status = coordinator.get_job_status(&job_id).expect("job status should exist");
    assert_eq!(status, JobStatus::Canceled);
}
