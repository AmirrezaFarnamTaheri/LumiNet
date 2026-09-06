//! Radix-2 IP routing trie for O(32)/O(128) longest-prefix match.

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct IpRoutingTrie<T: Clone> {
    root_v4: TrieNode<T>,
    root_v6: TrieNode<T>,
}

#[derive(Debug, Clone)]
struct TrieNode<T: Clone> {
    value: Option<T>,
    children: [Option<Box<TrieNode<T>>>; 2],
}

impl<T: Clone> Default for TrieNode<T> {
    fn default() -> Self {
        Self {
            value: None,
            children: [None, None],
        }
    }
}

impl<T: Clone> IpRoutingTrie<T> {
    pub fn new() -> Self {
        Self {
            root_v4: TrieNode::default(),
            root_v6: TrieNode::default(),
        }
    }

    pub fn insert(&mut self, ip: &IpAddr, prefix_len: u8, value: T) {
        let (root, bits) = match ip {
            IpAddr::V4(v4) => (&mut self.root_v4, v4.octets().to_vec()),
            IpAddr::V6(v6) => (&mut self.root_v6, v6.octets().to_vec()),
        };
        let mut curr = root;
        for bit_idx in 0..prefix_len {
            let byte_pos = (bit_idx / 8) as usize;
            let bit_pos = 7 - (bit_idx % 8);
            let direction = ((bits[byte_pos] >> bit_pos) & 1) as usize;
            if curr.children[direction].is_none() {
                curr.children[direction] = Some(Box::new(TrieNode::default()));
            }
            curr = curr.children[direction].as_mut().unwrap();
        }
        curr.value = Some(value);
    }

    pub fn longest_match(&self, ip: &IpAddr) -> Option<&T> {
        let (root, bits, max_bits) = match ip {
            IpAddr::V4(v4) => (&self.root_v4, v4.octets().to_vec(), 32u8),
            IpAddr::V6(v6) => (&self.root_v6, v6.octets().to_vec(), 128u8),
        };
        let mut curr = root;
        let mut best_val = curr.value.as_ref();
        for bit_idx in 0..max_bits {
            let byte_pos = (bit_idx / 8) as usize;
            let bit_pos = 7 - (bit_idx % 8);
            let direction = ((bits[byte_pos] >> bit_pos) & 1) as usize;
            match &curr.children[direction] {
                Some(next) => {
                    curr = next.as_ref();
                    if curr.value.is_some() {
                        best_val = curr.value.as_ref();
                    }
                }
                None => break,
            }
        }
        best_val
    }
}

impl<T: Clone> Default for IpRoutingTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_ipv4_longest_match() {
        let mut trie = IpRoutingTrie::new();
        let net10: IpAddr = "10.0.0.0".parse().unwrap();
        let net192: IpAddr = "192.168.0.0".parse().unwrap();
        trie.insert(&net10, 8, "rfc1918-10");
        trie.insert(&net192, 16, "rfc1918-192");

        let lookup: IpAddr = "10.5.3.1".parse().unwrap();
        assert_eq!(trie.longest_match(&lookup), Some(&"rfc1918-10"));

        let lookup2: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(trie.longest_match(&lookup2), Some(&"rfc1918-192"));

        let lookup3: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(trie.longest_match(&lookup3), None);
    }
}
