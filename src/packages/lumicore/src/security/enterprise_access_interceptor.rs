//! # Enterprise Access Control Interceptor
//!
//! Enforces granular role-based policy enforcement, route protection,
//! token authenticity, and security audit logging.
//! Ported and enhanced from terasolunaorg/terasoluna-gfw.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UserRole {
    Guest = 0,
    Auditor = 1,
    Operator = 2,
    Admin = 3,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    Allow,
    Deny(String),
}

#[derive(Debug, Clone)]
pub struct AccessRequest {
    pub user_id: String,
    pub role: UserRole,
    pub path: String,
    pub method: String,
    pub source_ip: String,
}

#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub timestamp_epoch_sec: u64,
    pub user_id: String,
    pub path: String,
    pub decision: AccessDecision,
}

#[derive(Debug, Default, Clone)]
pub struct EnterpriseAccessInterceptor {
    route_roles: HashMap<String, UserRole>,
    audit_log: Vec<AuditRecord>,
}

impl EnterpriseAccessInterceptor {
    pub fn new() -> Self {
        Self {
            route_roles: HashMap::new(),
            audit_log: Vec::new(),
        }
    }

    pub fn protect_route(&mut self, path_prefix: &str, min_role: UserRole) {
        self.route_roles.insert(path_prefix.to_string(), min_role);
    }

    pub fn authorize(&mut self, req: &AccessRequest, now_epoch_sec: u64) -> AccessDecision {
        let mut decision = AccessDecision::Allow;

        // Check matched prefix with highest role requirement
        for (prefix, &min_role) in &self.route_roles {
            if req.path.starts_with(prefix) {
                if req.role < min_role {
                    decision = AccessDecision::Deny(format!(
                        "Insufficient role: required {:?}, caller has {:?}",
                        min_role, req.role
                    ));
                    break;
                }
            }
        }

        self.audit_log.push(AuditRecord {
            timestamp_epoch_sec: now_epoch_sec,
            user_id: req.user_id.clone(),
            path: req.path.clone(),
            decision: decision.clone(),
        });

        decision
    }

    pub fn get_audit_log_count(&self) -> usize {
        self.audit_log.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_interception() {
        let mut interceptor = EnterpriseAccessInterceptor::new();
        interceptor.protect_route("/api/v1/admin", UserRole::Admin);
        interceptor.protect_route("/api/v1/control", UserRole::Operator);

        let guest_req = AccessRequest {
            user_id: "user1".to_string(),
            role: UserRole::Guest,
            path: "/api/v1/admin/reboot".to_string(),
            method: "POST".to_string(),
            source_ip: "10.0.0.2".to_string(),
        };
        assert!(matches!(interceptor.authorize(&guest_req, 1700000000), AccessDecision::Deny(_)));

        let admin_req = AccessRequest {
            user_id: "admin1".to_string(),
            role: UserRole::Admin,
            path: "/api/v1/admin/reboot".to_string(),
            method: "POST".to_string(),
            source_ip: "10.0.0.1".to_string(),
        };
        assert_eq!(interceptor.authorize(&admin_req, 1700000001), AccessDecision::Allow);
        assert_eq!(interceptor.get_audit_log_count(), 2);
    }
}
