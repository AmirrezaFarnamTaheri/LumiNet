use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct IdentitySession {
    pub email: String,
    pub domain: String,
    pub groups: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct RouteAccessPolicy {
    pub path_prefix: String,
    pub allowed_domains: HashSet<String>,
    pub required_groups: HashSet<String>,
}

#[derive(Debug, Default)]
pub struct IdentityPolicyEvaluator {
    policies: Vec<RouteAccessPolicy>,
}

impl IdentityPolicyEvaluator {
    pub fn new() -> Self {
        Self { policies: Vec::new() }
    }

    pub fn add_policy(&mut self, policy: RouteAccessPolicy) {
        self.policies.push(policy);
    }

    pub fn is_authorized(&self, path: &str, session: &IdentitySession) -> bool {
        for policy in &self.policies {
            if path.starts_with(&policy.path_prefix) {
                // Domain match
                if !policy.allowed_domains.is_empty() && !policy.allowed_domains.contains(&session.domain) {
                    return false;
                }
                // Group match
                if !policy.required_groups.is_empty() {
                    let has_group = policy.required_groups.iter().any(|g| session.groups.contains(g));
                    if !has_group {
                        return false;
                    }
                }
                return true;
            }
        }
        // Default deny for unmatched routes
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_policy_evaluation() {
        let mut evaluator = IdentityPolicyEvaluator::new();
        let mut allowed_domains = HashSet::new();
        allowed_domains.insert("luminet.internal".to_string());
        let mut required_groups = HashSet::new();
        required_groups.insert("infra-admin".to_string());

        evaluator.add_policy(RouteAccessPolicy {
            path_prefix: "/admin".to_string(),
            allowed_domains,
            required_groups,
        });

        let mut groups = HashSet::new();
        groups.insert("infra-admin".to_string());

        let admin_session = IdentitySession {
            email: "alice@luminet.internal".to_string(),
            domain: "luminet.internal".to_string(),
            groups: groups.clone(),
        };

        assert!(evaluator.is_authorized("/admin/nodes", &admin_session));

        let guest_session = IdentitySession {
            email: "bob@other.com".to_string(),
            domain: "other.com".to_string(),
            groups: HashSet::new(),
        };

        assert!(!evaluator.is_authorized("/admin/nodes", &guest_session));
    }
}
