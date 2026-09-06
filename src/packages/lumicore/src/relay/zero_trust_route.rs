use std::net::{IpAddr, Ipv4Addr};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct ZeroTrustResource {
    pub id: String,
    pub name: String,
    pub network_cidr: String,
    pub mapped_ip: Ipv4Addr,
    pub allowed_permission_mask: u32,
}

#[derive(Debug, Default)]
pub struct ZeroTrustRouteTable {
    resources: HashMap<String, ZeroTrustResource>,
    ip_to_resource: HashMap<Ipv4Addr, String>,
}

impl ZeroTrustRouteTable {
    pub fn new() -> Self {
        Self {
            resources: HashMap::new(),
            ip_to_resource: HashMap::new(),
        }
    }

    pub fn register_resource(&mut self, res: ZeroTrustResource) {
        self.ip_to_resource.insert(res.mapped_ip, res.id.clone());
        self.resources.insert(res.id.clone(), res);
    }

    pub fn lookup_by_ip(&self, ip: &Ipv4Addr) -> Option<&ZeroTrustResource> {
        self.ip_to_resource.get(ip).and_then(|id| self.resources.get(id))
    }

    pub fn evaluate_access(&self, ip: &Ipv4Addr, client_permissions: u32) -> bool {
        if let Some(res) = self.lookup_by_ip(ip) {
            (res.allowed_permission_mask & client_permissions) == res.allowed_permission_mask
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_trust_route_table_lookup() {
        let mut table = ZeroTrustRouteTable::new();
        let res = ZeroTrustResource {
            id: "res-prod-db".to_string(),
            name: "Production Database".to_string(),
            network_cidr: "10.100.0.0/24".to_string(),
            mapped_ip: Ipv4Addr::new(100, 64, 0, 10),
            allowed_permission_mask: 0x00000003,
        };

        table.register_resource(res);

        let found = table.lookup_by_ip(&Ipv4Addr::new(100, 64, 0, 10));
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Production Database");

        // Test permission evaluation
        assert!(table.evaluate_access(&Ipv4Addr::new(100, 64, 0, 10), 0x00000003));
        assert!(table.evaluate_access(&Ipv4Addr::new(100, 64, 0, 10), 0x00000007));
        assert!(!table.evaluate_access(&Ipv4Addr::new(100, 64, 0, 10), 0x00000001));
    }
}
