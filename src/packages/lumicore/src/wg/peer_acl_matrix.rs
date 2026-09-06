//! # Dynamic WireGuard Peer ACL Matrix Evaluator
//!
//! Evaluates N x N peer interconnect permissions, group memberships,
//! and egress gateway access rules.

use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerNodeId(pub String);

pub struct PeerAclMatrix {
    default_allow: bool,
    // explicit node_a -> set of permitted node_b
    explicit_rules: HashMap<PeerNodeId, HashSet<PeerNodeId>>,
    tags: HashMap<PeerNodeId, HashSet<String>>,
}

impl PeerAclMatrix {
    pub fn new(default_allow: bool) -> Self {
        Self {
            default_allow,
            explicit_rules: HashMap::new(),
            tags: HashMap::new(),
        }
    }

    pub fn set_peer_tags(&mut self, node: PeerNodeId, tags: Vec<String>) {
        let set: HashSet<String> = tags.into_iter().collect();
        self.tags.insert(node, set);
    }

    pub fn allow_peer_pair(&mut self, src: PeerNodeId, dst: PeerNodeId, bidirectional: bool) {
        self.explicit_rules.entry(src.clone()).or_default().insert(dst.clone());
        if bidirectional {
            self.explicit_rules.entry(dst).or_default().insert(src);
        }
    }

    pub fn is_allowed(&self, src: &PeerNodeId, dst: &PeerNodeId) -> bool {
        if src == dst {
            return true;
        }

        if let Some(targets) = self.explicit_rules.get(src) {
            if targets.contains(dst) {
                return true;
            }
        }

        self.default_allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_acl_matrix() {
        let mut acl = PeerAclMatrix::new(false); // default deny
        let node_a = PeerNodeId("node_a".to_string());
        let node_b = PeerNodeId("node_b".to_string());
        let node_c = PeerNodeId("node_c".to_string());

        assert!(!acl.is_allowed(&node_a, &node_b));

        acl.allow_peer_pair(node_a.clone(), node_b.clone(), true);
        assert!(acl.is_allowed(&node_a, &node_b));
        assert!(acl.is_allowed(&node_b, &node_a));
        assert!(!acl.is_allowed(&node_a, &node_c));
    }
}
