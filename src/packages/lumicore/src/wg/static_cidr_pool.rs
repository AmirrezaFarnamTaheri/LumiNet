use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq)]
pub struct AllocatedClient {
    pub client_id: String,
    pub ip: Ipv4Addr,
    pub public_key: String,
    pub is_revoked: bool,
}

#[derive(Debug)]
pub struct StaticCidrPool {
    base_prefix: [u8; 3],
    allocated: HashMap<Ipv4Addr, AllocatedClient>,
    revoked_keys: HashSet<String>,
    next_host: u8,
}

impl StaticCidrPool {
    pub fn new(prefix: [u8; 3]) -> Self {
        Self {
            base_prefix: prefix,
            allocated: HashMap::new(),
            revoked_keys: HashSet::new(),
            next_host: 2, // 1 is gateway
        }
    }

    pub fn allocate_client(&mut self, client_id: &str, public_key: &str) -> Option<AllocatedClient> {
        if self.next_host >= 254 {
            return None;
        }
        let ip = Ipv4Addr::new(self.base_prefix[0], self.base_prefix[1], self.base_prefix[2], self.next_host);
        self.next_host += 1;

        let client = AllocatedClient {
            client_id: client_id.to_string(),
            ip,
            public_key: public_key.to_string(),
            is_revoked: false,
        };
        self.allocated.insert(ip, client.clone());
        Some(client)
    }

    pub fn revoke_client(&mut self, ip: &Ipv4Addr) -> bool {
        if let Some(client) = self.allocated.get_mut(ip) {
            client.is_revoked = true;
            self.revoked_keys.insert(client.public_key.clone());
            true
        } else {
            false
        }
    }

    pub fn is_key_revoked(&self, public_key: &str) -> bool {
        self.revoked_keys.contains(public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_cidr_allocation_and_revocation() {
        let mut pool = StaticCidrPool::new([10, 66, 0]);
        let client = pool.allocate_client("user1", "pubkeyA111=").expect("should allocate");

        assert_eq!(client.ip, Ipv4Addr::new(10, 66, 0, 2));
        assert!(!pool.is_key_revoked("pubkeyA111="));

        assert!(pool.revoke_client(&client.ip));
        assert!(pool.is_key_revoked("pubkeyA111="));
    }
}
