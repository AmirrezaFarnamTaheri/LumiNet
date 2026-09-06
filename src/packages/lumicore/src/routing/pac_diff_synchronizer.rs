//! # PAC Diff Synchronizer
//!
//! Scheduled PAC differential synchronizer, detecting changes between upstream baseline
//! and local rulesets, generating checksummed sync deltas and hot-applying modifications.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacSyncDelta {
    pub added_domains: Vec<String>,
    pub removed_domains: Vec<String>,
    pub previous_checksum: String,
    pub new_checksum: String,
}

pub struct PacDiffSynchronizer {
    active_rules: HashSet<String>,
}

impl PacDiffSynchronizer {
    pub fn new(initial_rules: &[String]) -> Self {
        let mut active_rules = HashSet::new();
        for r in initial_rules {
            let trimmed = r.trim().to_lowercase();
            if !trimmed.is_empty() {
                active_rules.insert(trimmed);
            }
        }

        Self { active_rules }
    }

    pub fn compute_delta(&self, upstream_rules: &[String]) -> PacSyncDelta {
        let mut upstream_set = HashSet::new();
        for r in upstream_rules {
            let trimmed = r.trim().to_lowercase();
            if !trimmed.is_empty() {
                upstream_set.insert(trimmed);
            }
        }

        let mut added: Vec<String> = upstream_set
            .difference(&self.active_rules)
            .cloned()
            .collect();
        added.sort();

        let mut removed: Vec<String> = self
            .active_rules
            .difference(&upstream_set)
            .cloned()
            .collect();
        removed.sort();

        let prev_ck = self.current_checksum();
        let new_ck = Self::compute_checksum_for_set(&upstream_set);

        PacSyncDelta {
            added_domains: added,
            removed_domains: removed,
            previous_checksum: prev_ck,
            new_checksum: new_ck,
        }
    }

    pub fn apply_delta(&mut self, delta: &PacSyncDelta) -> Result<usize, String> {
        let cur_ck = self.current_checksum();
        if cur_ck != delta.previous_checksum {
            return Err("Checksum mismatch: concurrent modification detected".to_string());
        }

        for rem in &delta.removed_domains {
            self.active_rules.remove(rem);
        }

        for add in &delta.added_domains {
            self.active_rules.insert(add.clone());
        }

        let verified_ck = self.current_checksum();
        if verified_ck != delta.new_checksum {
            return Err("Post-apply checksum mismatch".to_string());
        }

        Ok(self.active_rules.len())
    }

    pub fn current_checksum(&self) -> String {
        Self::compute_checksum_for_set(&self.active_rules)
    }

    pub fn contains_rule(&self, domain: &str) -> bool {
        self.active_rules.contains(&domain.trim().to_lowercase())
    }

    pub fn total_rules(&self) -> usize {
        self.active_rules.len()
    }

    fn compute_checksum_for_set(set: &HashSet<String>) -> String {
        let mut sorted: Vec<&String> = set.iter().collect();
        sorted.sort();

        let mut hasher = Sha256::new();
        for item in sorted {
            hasher.update(item.as_bytes());
            hasher.update(b"\n");
        }
        format!("{:x}", hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pac_diff_sync() {
        let initial = vec!["google.com".to_string(), "twitter.com".to_string()];
        let mut sync = PacDiffSynchronizer::new(&initial);

        let upstream = vec![
            "google.com".to_string(),
            "youtube.com".to_string(), // added
            // twitter removed
        ];

        let delta = sync.compute_delta(&upstream);
        assert_eq!(delta.added_domains, vec!["youtube.com".to_string()]);
        assert_eq!(delta.removed_domains, vec!["twitter.com".to_string()]);

        let result = sync.apply_delta(&delta);
        assert!(result.is_ok());
        assert_eq!(sync.total_rules(), 2);
        assert!(sync.contains_rule("youtube.com"));
        assert!(!sync.contains_rule("twitter.com"));
    }
}
