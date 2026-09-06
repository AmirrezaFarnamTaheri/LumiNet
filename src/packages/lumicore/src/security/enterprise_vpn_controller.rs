//! # Enterprise VPN Controller
//!
//! Enterprise virtual network controller managing multi-tenant organizations,
//! token-based client authentication, subnet route allocations, and RBAC firewall rules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    Admin,
    Auditor,
    StandardUser,
    Guest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseUser {
    pub user_id: String,
    pub org_id: String,
    pub role: UserRole,
    pub auth_token: String,
    pub assigned_virtual_ip: String,
    pub allowed_routes: Vec<String>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantOrganization {
    pub org_id: String,
    pub name: String,
    pub virtual_subnet: String, // e.g. "10.200.0.0/16"
    pub max_users: u32,
    pub enable_split_tunnel: bool,
}

pub struct EnterpriseVpnController {
    organizations: HashMap<String, TenantOrganization>,
    users: HashMap<String, EnterpriseUser>, // auth_token -> user
    ip_to_token: HashMap<String, String>,
}

impl EnterpriseVpnController {
    pub fn new() -> Self {
        Self {
            organizations: HashMap::new(),
            users: HashMap::new(),
            ip_to_token: HashMap::new(),
        }
    }

    pub fn register_organization(&mut self, org: TenantOrganization) {
        self.organizations.insert(org.org_id.clone(), org);
    }

    pub fn register_user(
        &mut self,
        user_id: &str,
        org_id: &str,
        role: UserRole,
        auth_token: &str,
        virtual_ip: &str,
        allowed_routes: Vec<String>,
    ) -> Result<(), String> {
        if !self.organizations.contains_key(org_id) {
            return Err("Organization does not exist".to_string());
        }

        let user = EnterpriseUser {
            user_id: user_id.to_string(),
            org_id: org_id.to_string(),
            role,
            auth_token: auth_token.to_string(),
            assigned_virtual_ip: virtual_ip.to_string(),
            allowed_routes,
            is_active: true,
        };

        self.ip_to_token.insert(virtual_ip.to_string(), auth_token.to_string());
        self.users.insert(auth_token.to_string(), user);
        Ok(())
    }

    pub fn authenticate_token(&self, token: &str) -> Option<&EnterpriseUser> {
        self.users.get(token).filter(|u| u.is_active)
    }

    pub fn can_access_route(&self, token: &str, destination_ip: &str) -> bool {
        let user = match self.authenticate_token(token) {
            Some(u) => u,
            None => return false,
        };

        if user.role == UserRole::Admin {
            return true;
        }

        // Check if destination matches any allowed route (exact or CIDR match)
        for route in &user.allowed_routes {
            if route == "0.0.0.0/0" {
                return true;
            }
            if let (Ok(dest_ip), Some((net_str, prefix_str))) = (
                destination_ip.parse::<std::net::Ipv4Addr>(),
                route.split_once('/'),
            ) {
                if let (Ok(net_ip), Ok(prefix_len)) = (
                    net_str.parse::<std::net::Ipv4Addr>(),
                    prefix_str.parse::<u32>(),
                ) {
                    let mask = if prefix_len == 0 {
                        0
                    } else if prefix_len >= 32 {
                        !0u32
                    } else {
                        !0u32 << (32 - prefix_len)
                    };
                    if (u32::from(dest_ip) & mask) == (u32::from(net_ip) & mask) {
                        return true;
                    }
                }
            } else if route == destination_ip {
                return true;
            }
        }

        false
    }

    pub fn revoke_user(&mut self, token: &str) -> bool {
        if let Some(user) = self.users.get_mut(token) {
            user.is_active = false;
            self.ip_to_token.remove(&user.assigned_virtual_ip);
            true
        } else {
            false
        }
    }

    pub fn total_active_users(&self) -> usize {
        self.users.values().filter(|u| u.is_active).count()
    }
}

impl Default for EnterpriseVpnController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enterprise_vpn_rbac_and_routes() {
        let mut controller = EnterpriseVpnController::new();

        let org = TenantOrganization {
            org_id: "org-acme".to_string(),
            name: "Acme Corp".to_string(),
            virtual_subnet: "10.200.0.0/16".to_string(),
            max_users: 100,
            enable_split_tunnel: true,
        };
        controller.register_organization(org);

        // Register standard user
        controller
            .register_user(
                "alice",
                "org-acme",
                UserRole::StandardUser,
                "token-alice-123",
                "10.200.1.10",
                vec!["10.200.10.0/24".to_string()],
            )
            .unwrap();

        // Register admin user
        controller
            .register_user(
                "bob",
                "org-acme",
                UserRole::Admin,
                "token-bob-admin",
                "10.200.1.1",
                vec![],
            )
            .unwrap();

        // Test auth
        assert!(controller.authenticate_token("token-alice-123").is_some());
        assert!(controller.authenticate_token("invalid-token").is_none());

        // Test route access
        assert!(controller.can_access_route("token-alice-123", "10.200.10.55"));
        assert!(!controller.can_access_route("token-alice-123", "10.200.99.1"));

        // Admin has universal route access
        assert!(controller.can_access_route("token-bob-admin", "10.200.99.1"));

        // Revoke alice
        assert!(controller.revoke_user("token-alice-123"));
        assert!(controller.authenticate_token("token-alice-123").is_none());
        assert_eq!(controller.total_active_users(), 1);
    }
}
