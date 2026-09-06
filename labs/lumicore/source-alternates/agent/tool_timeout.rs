use std::time::Duration;
use tokio::time::timeout;
use std::future::Future;

pub struct ToolTimeout;

impl ToolTimeout {
    /// Atomic deadline enforcement
    pub async fn enforce_deadline<F, T>(future: F, deadline: Duration) -> Result<T, &'static str>
    where
        F: Future<Output = T>,
    {
        match timeout(deadline, future).await {
            Ok(result) => Ok(result),
            Err(_) => Err("Tool execution timed out. Atomic deadline enforced."),
        }
    }
}
