use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum QuotaStatus {
    Normal,
    Warning80Percent,
    Exhausted,
}

#[derive(Debug, Clone)]
pub struct UserQuota {
    pub user_id: String,
    pub max_bytes: u64,
    pub used_bytes: u64,
    pub is_active: bool,
}

#[derive(Debug, Default)]
pub struct BandwidthQuotaEnforcer {
    quotas: HashMap<String, UserQuota>,
}

impl BandwidthQuotaEnforcer {
    pub fn new() -> Self {
        Self {
            quotas: HashMap::new(),
        }
    }

    pub fn register_user(&mut self, user_id: &str, max_bytes: u64) {
        self.quotas.insert(user_id.to_string(), UserQuota {
            user_id: user_id.to_string(),
            max_bytes,
            used_bytes: 0,
            is_active: true,
        });
    }

    pub fn record_traffic(&mut self, user_id: &str, bytes: u64) -> QuotaStatus {
        if let Some(quota) = self.quotas.get_mut(user_id) {
            quota.used_bytes = quota.used_bytes.saturating_add(bytes);
            if quota.used_bytes >= quota.max_bytes {
                quota.is_active = false;
                QuotaStatus::Exhausted
            } else if quota.used_bytes >= (quota.max_bytes * 8) / 10 {
                QuotaStatus::Warning80Percent
            } else {
                QuotaStatus::Normal
            }
        } else {
            QuotaStatus::Exhausted
        }
    }

    pub fn is_user_allowed(&self, user_id: &str) -> bool {
        self.quotas.get(user_id).map(|q| q.is_active).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_quota_exhaustion() {
        let mut enforcer = BandwidthQuotaEnforcer::new();
        enforcer.register_user("client-alice", 1000);

        assert_eq!(enforcer.record_traffic("client-alice", 500), QuotaStatus::Normal);
        assert!(enforcer.is_user_allowed("client-alice"));

        assert_eq!(enforcer.record_traffic("client-alice", 350), QuotaStatus::Warning80Percent);
        assert!(enforcer.is_user_allowed("client-alice"));

        assert_eq!(enforcer.record_traffic("client-alice", 200), QuotaStatus::Exhausted);
        assert!(!enforcer.is_user_allowed("client-alice"));
    }
}
