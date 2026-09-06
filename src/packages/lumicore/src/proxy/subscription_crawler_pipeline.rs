//! # Subscription Crawler Pipeline
//!
//! Multi-source subscription crawling pipeline, scheduled fetch dispatcher,
//! base64/plain payload extractor, and proxy candidate deduplication filter.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlSource {
    pub url: String,
    pub interval_secs: u64,
    pub last_crawl: u64,
    pub total_harvested: usize,
    pub enabled: bool,
}

pub struct SubscriptionCrawlerPipeline {
    sources: HashMap<String, CrawlSource>,
    harvested_proxies: HashSet<String>,
}

impl SubscriptionCrawlerPipeline {
    pub fn new() -> Self {
        Self {
            sources: HashMap::new(),
            harvested_proxies: HashSet::new(),
        }
    }

    pub fn add_source(&mut self, url: &str, interval_secs: u64) {
        self.sources.insert(
            url.to_string(),
            CrawlSource {
                url: url.to_string(),
                interval_secs: interval_secs.max(60),
                last_crawl: 0,
                total_harvested: 0,
                enabled: true,
            },
        );
    }

    pub fn dispatch_pending_sources(&mut self, current_time: u64) -> Vec<String> {
        let mut to_crawl = Vec::new();
        for source in self.sources.values_mut() {
            if source.enabled && (source.last_crawl == 0 || current_time >= source.last_crawl + source.interval_secs) {
                source.last_crawl = current_time;
                to_crawl.push(source.url.clone());
            }
        }
        to_crawl
    }

    pub fn ingest_crawl_content(&mut self, source_url: &str, raw_content: &str) -> usize {
        let mut count = 0;
        let content_trimmed = raw_content.trim();

        // Check if entire payload is base64 encoded
        let decoded_text = if let Ok(decoded_bytes) = BASE64_STANDARD.decode(content_trimmed) {
            String::from_utf8(decoded_bytes).unwrap_or_else(|_| content_trimmed.to_string())
        } else {
            content_trimmed.to_string()
        };

        for line in decoded_text.lines() {
            let line_trimmed = line.trim();
            if line_trimmed.starts_with("ss://")
                || line_trimmed.starts_with("vmess://")
                || line_trimmed.starts_with("vless://")
                || line_trimmed.starts_with("trojan://")
                || line_trimmed.starts_with("hysteria2://")
                || line_trimmed.starts_with("tuic://")
            {
                if self.harvested_proxies.insert(line_trimmed.to_string()) {
                    count += 1;
                }
            }
        }

        if let Some(source) = self.sources.get_mut(source_url) {
            source.total_harvested += count;
        }

        count
    }

    pub fn get_harvested_proxies(&self) -> Vec<String> {
        let mut list: Vec<_> = self.harvested_proxies.iter().cloned().collect();
        list.sort();
        list
    }

    pub fn total_harvested_count(&self) -> usize {
        self.harvested_proxies.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crawler_pipeline() {
        let mut pipeline = SubscriptionCrawlerPipeline::new();
        pipeline.add_source("https://example.com/subs.txt", 3600);

        let pending = pipeline.dispatch_pending_sources(1000);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0], "https://example.com/subs.txt");

        // No new crawls within interval
        let pending_too_soon = pipeline.dispatch_pending_sources(1500);
        assert!(pending_too_soon.is_empty());

        let raw = "vmess://eyJhZGRyIjoiMS4xLjEuMSJ9\ntrojan://pass@2.2.2.2:443\ninvalid_line";
        let ingested = pipeline.ingest_crawl_content("https://example.com/subs.txt", raw);
        assert_eq!(ingested, 2);
        assert_eq!(pipeline.total_harvested_count(), 2);
    }

    #[test]
    fn test_base64_encoded_crawl_content() {
        let mut pipeline = SubscriptionCrawlerPipeline::new();
        pipeline.add_source("https://example.com/b64", 3600);

        let lines = "ss://user:pass@1.2.3.4:8388\nvless://uuid@5.6.7.8:443";
        let encoded = BASE64_STANDARD.encode(lines);

        let ingested = pipeline.ingest_crawl_content("https://example.com/b64", &encoded);
        assert_eq!(ingested, 2);
        assert_eq!(pipeline.total_harvested_count(), 2);
    }
}
