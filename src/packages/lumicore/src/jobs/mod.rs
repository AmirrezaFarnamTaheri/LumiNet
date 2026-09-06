//! # Async Job Coordinator & Broadcast Hub
//!
//! High-performance async task scheduling, lifecycle management, and
//! multi-subscriber event fan-out using Tokio and lock-free concurrency.
//!
//! ## Official References:
//! - Tokio Broadcast: <https://docs.rs/tokio/latest/tokio/sync/broadcast/>
//! - Tokio CancellationToken: <https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html>
//! - DashMap: <https://docs.rs/dashmap/latest/dashmap/>
//!
//! ## Design Patterns:
//! - `leonardomso-rust-skills`: `async-broadcast-pubsub`, `async-cancellation-token`, `type-enum-states`, `err-thiserror-lib`

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::broadcast;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;
pub use tokio_util::sync::CancellationToken;

/// Job orchestration errors.
#[derive(Debug, Error)]
pub enum JobError {
    #[error("job not found: {0}")]
    NotFound(String),
    #[error("job execution failed: {0}")]
    ExecutionFailed(String),
    #[error("job timed out")]
    Timeout,
    #[error("broadcast channel error: {0}")]
    BroadcastError(String),
}

/// Lifecycle status of a scheduled job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Canceled,
}

/// Category of job event dispatched to subscribers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JobEventType {
    Started,
    Progress { percentage: u8 },
    Log,
    Completed,
    Failed,
}

/// Event published over the broadcast bus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobEvent {
    pub job_id: String,
    pub event_type: JobEventType,
    pub payload: String,
}

/// Real-time multi-subscriber event distribution hub.
#[derive(Clone)]
pub struct BroadcastHub {
    sender: broadcast::Sender<JobEvent>,
}

impl BroadcastHub {
    /// Creates a new `BroadcastHub` with capacity buffer.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Subscribes a new receiver to listen to live job events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<JobEvent> {
        self.sender.subscribe()
    }

    /// Publishes a job event to all active subscribers.
    pub fn publish(&self, event: JobEvent) -> Result<usize, JobError> {
        // If there are no receivers, it's not a failure
        match self.sender.send(event) {
            Ok(count) => Ok(count),
            Err(_) => Ok(0),
        }
    }
}

struct JobRecord {
    status: JobStatus,
    output: Option<String>,
    error: Option<String>,
    cancel_token: CancellationToken,
    notify: Arc<Notify>,
    #[allow(dead_code)]
    handle: Option<JoinHandle<()>>,
}

/// Async job coordinator managing background task execution and lifecycle.
#[derive(Clone)]
pub struct JobCoordinator {
    jobs: Arc<DashMap<String, JobRecord>>,
    hub: BroadcastHub,
}

impl JobCoordinator {
    /// Creates a new `JobCoordinator`.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            jobs: Arc::new(DashMap::new()),
            hub: BroadcastHub::new(capacity),
        }
    }

    /// Returns a reference to the shared broadcast hub.
    #[must_use]
    pub fn broadcast_hub(&self) -> &BroadcastHub {
        &self.hub
    }

    /// Submits an asynchronous task to run in the background.
    pub async fn submit_job<F, Fut>(
        &self,
        name: &str,
        _kind: &str,
        task: F,
    ) -> Result<String, JobError>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<String, String>> + Send + 'static,
    {
        let job_id = format!("{}-{}", name, rand::random::<u32>());
        let cancel_token = CancellationToken::new();
        let notify = Arc::new(Notify::new());

        let record = JobRecord {
            status: JobStatus::Pending,
            output: None,
            error: None,
            cancel_token: cancel_token.clone(),
            notify: notify.clone(),
            handle: None,
        };

        self.jobs.insert(job_id.clone(), record);

        let jobs_map = self.jobs.clone();
        let hub = self.hub.clone();
        let id_clone = job_id.clone();
        let token_for_task = cancel_token.clone();

        let handle = tokio::spawn(async move {
            if let Some(mut entry) = jobs_map.get_mut(&id_clone) {
                entry.status = JobStatus::Running;
            }
            let _ = hub.publish(JobEvent {
                job_id: id_clone.clone(),
                event_type: JobEventType::Started,
                payload: "job started".to_string(),
            });

            let outcome = task(token_for_task.clone()).await;

            if let Some(mut entry) = jobs_map.get_mut(&id_clone) {
                if token_for_task.is_cancelled() {
                    entry.status = JobStatus::Canceled;
                    let _ = hub.publish(JobEvent {
                        job_id: id_clone.clone(),
                        event_type: JobEventType::Failed,
                        payload: "job canceled".to_string(),
                    });
                } else {
                    match outcome {
                        Ok(val) => {
                            entry.status = JobStatus::Succeeded;
                            entry.output = Some(val.clone());
                            let _ = hub.publish(JobEvent {
                                job_id: id_clone.clone(),
                                event_type: JobEventType::Completed,
                                payload: val,
                            });
                        }
                        Err(err) => {
                            entry.status = JobStatus::Failed;
                            entry.error = Some(err.clone());
                            let _ = hub.publish(JobEvent {
                                job_id: id_clone.clone(),
                                event_type: JobEventType::Failed,
                                payload: err,
                            });
                        }
                    }
                }
                entry.notify.notify_waiters();
            }
        });

        if let Some(mut entry) = self.jobs.get_mut(&job_id) {
            entry.handle = Some(handle);
        }

        Ok(job_id)
    }

    /// Queries the current status of a job.
    #[must_use]
    pub fn get_job_status(&self, job_id: &str) -> Option<JobStatus> {
        self.jobs.get(job_id).map(|entry| entry.status)
    }

    /// Cancels a running job.
    pub async fn cancel_job(&self, job_id: &str) -> bool {
        if let Some(entry) = self.jobs.get(job_id) {
            entry.cancel_token.cancel();
            true
        } else {
            false
        }
    }

    /// Waits for a job to finish or times out.
    pub async fn wait_for_completion(
        &self,
        job_id: &str,
        wait_timeout: Duration,
    ) -> Result<String, JobError> {
        let notify = {
            let entry = self
                .jobs
                .get(job_id)
                .ok_or_else(|| JobError::NotFound(job_id.to_string()))?;
            if entry.status == JobStatus::Succeeded {
                return Ok(entry.output.clone().unwrap_or_default());
            }
            if entry.status == JobStatus::Failed {
                return Err(JobError::ExecutionFailed(
                    entry.error.clone().unwrap_or_default(),
                ));
            }
            if entry.status == JobStatus::Canceled {
                return Err(JobError::ExecutionFailed("job was canceled".to_string()));
            }
            entry.notify.clone()
        };

        let result = timeout(wait_timeout, notify.notified()).await;
        if result.is_err() {
            return Err(JobError::Timeout);
        }

        let entry = self
            .jobs
            .get(job_id)
            .ok_or_else(|| JobError::NotFound(job_id.to_string()))?;
        match entry.status {
            JobStatus::Succeeded => Ok(entry.output.clone().unwrap_or_default()),
            JobStatus::Failed => Err(JobError::ExecutionFailed(
                entry.error.clone().unwrap_or_default(),
            )),
            JobStatus::Canceled => Err(JobError::ExecutionFailed("job was canceled".to_string())),
            _ => Err(JobError::Timeout),
        }
    }
}
