use tokio::task::JoinSet;
use std::time::Duration;
use rand::Rng;

pub struct ConnectorSync;

impl ConnectorSync {
    /// Tokio JoinSet parallel fetches across all authenticated sources with rate limit queues and Jittered backoff.
    pub async fn fetch_all(sources: Vec<String>) -> Vec<String> {
        let mut join_set = JoinSet::new();
        
        for source in sources {
            join_set.spawn(async move {
                Self::fetch_with_backoff(source).await
            });
        }
        
        let mut results = Vec::new();
        while let Some(res) = join_set.join_next().await {
            if let Ok(data) = res {
                results.push(data);
            }
        }
        results
    }

    async fn fetch_with_backoff(source: String) -> String {
        let mut attempts = 0;
        loop {
            // Simulated rate limit queue check
            if Self::check_rate_limit(&source) {
                return format!("Fetched data from {}", source);
            }
            
            attempts += 1;
            if attempts > 3 {
                return format!("Failed to fetch from {}", source);
            }
            
            let mut rng = rand::thread_rng();
            let jitter: u64 = rng.gen_range(100..500);
            tokio::time::sleep(Duration::from_millis((2u64.pow(attempts) * 100) + jitter)).await;
        }
    }
    
    fn check_rate_limit(_source: &str) -> bool {
        // Dummy implementation of rate limit queue
        true
    }
}
