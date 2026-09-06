//! # Lock-Free Flow Trie
//!
//! Bitwise radix trie (Crit-bit tree) for concurrent flow aggregation.
//!
//! Uses atomic pointers for lock-free concurrent writes without mutexes.
//! Supports insert-merge, lookup, and walk operations.

use std::net::IpAddr;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

/// Aggregated flow data for a single IP.
#[derive(Debug, Clone, Default)]
pub struct FlowData {
    pub ip: String,
    pub country: String,
    pub isp: String,
    pub asn: String,
    pub direction: String,
    pub tcp_bytes: u64,
    pub udp_bytes: u64,
    pub icmp_bytes: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub total_bytes: u64,
    pub total_packets: u64,
}

impl FlowData {
    /// Merges another flow data into this one (additive).
    pub fn merge(&mut self, other: &FlowData) {
        self.tcp_bytes += other.tcp_bytes;
        self.udp_bytes += other.udp_bytes;
        self.icmp_bytes += other.icmp_bytes;
        self.tcp_packets += other.tcp_packets;
        self.udp_packets += other.udp_packets;
        self.icmp_packets += other.icmp_packets;
        self.total_bytes += other.total_bytes;
        self.total_packets += other.total_packets;
    }

    /// Returns the total byte count across all protocols.
    pub fn total_bytes(&self) -> u64 {
        self.tcp_bytes + self.udp_bytes + self.icmp_bytes
    }

    /// Returns the total packet count across all protocols.
    pub fn total_packets(&self) -> u64 {
        self.tcp_packets + self.udp_packets + self.icmp_packets
    }
}

/// Node in the radix trie.
struct TrieNode {
    /// The 128-bit key (IP address as u128).
    key: u128,
    /// Data associated with this key.
    data: FlowData,
    /// Left child (bit = 0).
    left: AtomicPtr<TrieNode>,
    /// Right child (bit = 1).
    right: AtomicPtr<TrieNode>,
    /// Critical bit position (0-127).
    crit_bit: u8,
}

/// Lock-free radix trie for IP-based flow aggregation.
pub struct FlowTrie {
    root: AtomicPtr<TrieNode>,
}

unsafe impl Send for FlowTrie {}
unsafe impl Sync for FlowTrie {}

impl Default for FlowTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowTrie {
    /// Creates a new empty trie.
    pub fn new() -> Self {
        Self {
            root: AtomicPtr::new(ptr::null_mut()),
        }
    }

    /// Inserts or merges flow data for an IP address.
    pub fn insert_merge(&self, ip: &IpAddr, data: FlowData) {
        let key = ip_to_u128(ip);

        let new_node = Box::into_raw(Box::new(TrieNode {
            key,
            data: data.clone(),
            left: AtomicPtr::new(ptr::null_mut()),
            right: AtomicPtr::new(ptr::null_mut()),
            crit_bit: 0,
        }));

        loop {
            let root = self.root.load(Ordering::Acquire);
            if root.is_null() {
                if self
                    .root
                    .compare_exchange(
                        ptr::null_mut(),
                        new_node,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return;
                }
                // CAS failed, retry
                continue;
            }

            // Walk the trie to find insertion point
            let mut current = unsafe { &*root };
            loop {
                if current.key == key {
                    // Key exists, merge data
                    unsafe {
                        (*new_node).data.merge(&current.data);
                    }
                    // Update in place
                    unsafe {
                        let node = &mut *root;
                        node.data.merge(&data);
                    }
                    // Free the unused new node
                    unsafe {
                        drop(Box::from_raw(new_node));
                    }
                    return;
                }

                let direction = if key & (1 << (127 - current.crit_bit)) != 0 {
                    1
                } else {
                    0
                };

                let child = if direction == 0 {
                    current.left.load(Ordering::Acquire)
                } else {
                    current.right.load(Ordering::Acquire)
                };

                if child.is_null() {
                    // Insert here
                    let child_ptr = if direction == 0 {
                        &current.left
                    } else {
                        &current.right
                    };

                    if child_ptr
                        .compare_exchange(
                            ptr::null_mut(),
                            new_node,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        return;
                    }
                    // CAS failed, retry from root
                    break;
                }

                current = unsafe { &*child };
            }
        }
    }

    /// Looks up flow data for an IP address.
    pub fn lookup(&self, ip: &IpAddr) -> Option<FlowData> {
        let key = ip_to_u128(ip);
        let mut current = self.root.load(Ordering::Acquire);

        while !current.is_null() {
            let node = unsafe { &*current };
            if node.key == key {
                return Some(node.data.clone());
            }

            let direction = if key & (1 << (127 - node.crit_bit)) != 0 {
                1
            } else {
                0
            };

            current = if direction == 0 {
                node.left.load(Ordering::Acquire)
            } else {
                node.right.load(Ordering::Acquire)
            };
        }

        None
    }

    /// Walks all entries in the trie, calling the visitor function.
    pub fn walk<F: FnMut(&IpAddr, &FlowData)>(&self, mut visitor: F) {
        let root = self.root.load(Ordering::Acquire);
        if !root.is_null() {
            self.walk_node(root, &mut visitor);
        }
    }

    fn walk_node<F: FnMut(&IpAddr, &FlowData)>(&self, node: *const TrieNode, visitor: &mut F) {
        if node.is_null() {
            return;
        }
        let node = unsafe { &*node };
        let ip = u128_to_ip(node.key);
        visitor(&ip, &node.data);

        let left = node.left.load(Ordering::Acquire);
        let right = node.right.load(Ordering::Acquire);
        self.walk_node(left, visitor);
        self.walk_node(right, visitor);
    }

    /// Returns the number of entries in the trie.
    pub fn len(&self) -> usize {
        let mut count = 0;
        self.walk(|_, _| count += 1);
        count
    }

    /// Returns true if the trie is empty.
    pub fn is_empty(&self) -> bool {
        self.root.load(Ordering::Acquire).is_null()
    }

    fn drop_node(&self, node: *mut TrieNode) {
        if node.is_null() {
            return;
        }
        unsafe {
            let n = &*node;
            let left = n.left.load(Ordering::Acquire);
            let right = n.right.load(Ordering::Acquire);
            self.drop_node(left);
            self.drop_node(right);
            drop(Box::from_raw(node));
        }
    }
}

impl Drop for FlowTrie {
    fn drop(&mut self) {
        let root = self.root.load(Ordering::Acquire);
        if !root.is_null() {
            self.drop_node(root);
        }
    }
}

fn ip_to_u128(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            u128::from_be_bytes([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, octets[0], octets[1], octets[2], octets[3],
            ])
        }
        IpAddr::V6(v6) => u128::from_be_bytes(v6.octets()),
    }
}

fn u128_to_ip(key: u128) -> IpAddr {
    let bytes = key.to_be_bytes();
    // Check if it's an IPv4 (first 12 bytes are zero)
    if bytes[..12].iter().all(|&b| b == 0) {
        IpAddr::from([bytes[12], bytes[13], bytes[14], bytes[15]])
    } else {
        IpAddr::from(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_lookup() {
        let trie = FlowTrie::new();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let data = FlowData {
            ip: "192.168.1.1".to_string(),
            tcp_bytes: 100,
            ..Default::default()
        };

        trie.insert_merge(&ip, data);
        let result = trie.lookup(&ip).unwrap();
        assert_eq!(result.tcp_bytes, 100);
    }

    #[test]
    fn test_merge() {
        let trie = FlowTrie::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        trie.insert_merge(
            &ip,
            FlowData {
                tcp_bytes: 100,
                tcp_packets: 10,
                ..Default::default()
            },
        );
        trie.insert_merge(
            &ip,
            FlowData {
                tcp_bytes: 200,
                tcp_packets: 20,
                ..Default::default()
            },
        );

        let result = trie.lookup(&ip).unwrap();
        assert_eq!(result.tcp_bytes, 300);
        assert_eq!(result.tcp_packets, 30);
    }

    #[test]
    fn test_walk() {
        let trie = FlowTrie::new();
        trie.insert_merge(
            &"1.1.1.1".parse().unwrap(),
            FlowData {
                tcp_bytes: 10,
                ..Default::default()
            },
        );
        trie.insert_merge(
            &"2.2.2.2".parse().unwrap(),
            FlowData {
                tcp_bytes: 20,
                ..Default::default()
            },
        );
        trie.insert_merge(
            &"3.3.3.3".parse().unwrap(),
            FlowData {
                tcp_bytes: 30,
                ..Default::default()
            },
        );

        let mut total = 0;
        trie.walk(|_, data| total += data.tcp_bytes);
        assert_eq!(total, 60);
    }

    #[test]
    fn test_ip_conversion() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let key = ip_to_u128(&ip);
        let back = u128_to_ip(key);
        assert_eq!(ip, back);

        let ip6: IpAddr = "2001:db8::1".parse().unwrap();
        let key6 = ip_to_u128(&ip6);
        let back6 = u128_to_ip(key6);
        assert_eq!(ip6, back6);
    }
}
