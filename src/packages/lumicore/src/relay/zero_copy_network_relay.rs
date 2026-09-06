//! High Performance Zero-Copy Network Relay
//!
//! Provides connection forwarding with optional PROXY protocol (v1/v2) injection,
//! endpoint load balancing, health tracking, and session multiplexing.

use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolVersion {
    None,
    V1,
    V2,
}

#[derive(Debug, Clone)]
pub struct RelayEndpoint {
    pub target_addr: SocketAddr,
    pub weight: u32,
    pub is_alive: bool,
    pub active_connections: usize,
    pub total_bytes_forwarded: u64,
}

pub struct ZeroCopyRelaySupervisor {
    pub listen_addr: SocketAddr,
    pub proxy_protocol: ProxyProtocolVersion,
    endpoints: Vec<RelayEndpoint>,
    endpoint_index: usize,
    session_map: HashMap<u64, SocketAddr>,
    next_session_id: u64,
}

impl ZeroCopyRelaySupervisor {
    pub fn new(listen: SocketAddr, proxy_protocol: ProxyProtocolVersion) -> Self {
        Self {
            listen_addr: listen,
            proxy_protocol,
            endpoints: Vec::new(),
            endpoint_index: 0,
            session_map: HashMap::new(),
            next_session_id: 1,
        }
    }

    pub fn add_endpoint(&mut self, addr: SocketAddr, weight: u32) {
        self.endpoints.push(RelayEndpoint {
            target_addr: addr,
            weight: weight.max(1),
            is_alive: true,
            active_connections: 0,
            total_bytes_forwarded: 0,
        });
    }

    pub fn select_forwarding_target(&mut self) -> Option<SocketAddr> {
        let healthy: Vec<usize> = self
            .endpoints
            .iter()
            .enumerate()
            .filter(|(_, ep)| ep.is_alive)
            .map(|(idx, _)| idx)
            .collect();

        if healthy.is_empty() {
            return None;
        }

        let chosen_idx = healthy[self.endpoint_index % healthy.len()];
        self.endpoint_index = self.endpoint_index.wrapping_add(1);
        self.endpoints[chosen_idx].active_connections += 1;
        Some(self.endpoints[chosen_idx].target_addr)
    }

    pub fn open_session(&mut self, client_addr: SocketAddr) -> (u64, Option<SocketAddr>) {
        let sid = self.next_session_id;
        self.next_session_id += 1;

        let target = self.select_forwarding_target();
        if let Some(t) = target {
            self.session_map.insert(sid, t);
        }
        (sid, target)
    }

    pub fn close_session(&mut self, session_id: u64, bytes_relayed: u64) {
        if let Some(target) = self.session_map.remove(&session_id) {
            if let Some(ep) = self.endpoints.iter_mut().find(|ep| ep.target_addr == target) {
                if ep.active_connections > 0 {
                    ep.active_connections -= 1;
                }
                ep.total_bytes_forwarded += bytes_relayed;
            }
        }
    }

    pub fn generate_proxy_header(&self, client_addr: &SocketAddr, server_addr: &SocketAddr) -> Vec<u8> {
        match self.proxy_protocol {
            ProxyProtocolVersion::None => Vec::new(),
            ProxyProtocolVersion::V1 => {
                let proto_str = match (client_addr, server_addr) {
                    (SocketAddr::V4(_), SocketAddr::V4(_)) => "TCP4",
                    (SocketAddr::V6(_), SocketAddr::V6(_)) => "TCP6",
                    _ => "UNKNOWN",
                };
                let header = format!(
                    "PROXY {} {} {} {} {}\r\n",
                    proto_str,
                    client_addr.ip(),
                    server_addr.ip(),
                    client_addr.port(),
                    server_addr.port()
                );
                header.into_bytes()
            }
            ProxyProtocolVersion::V2 => {
                // PROXY protocol v2 binary signature: \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
                let mut v2_bytes = vec![
                    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
                ];
                // Version 2 | Command PROXY (0x21)
                v2_bytes.push(0x21);
                // Family & Protocol: AF_INET + STREAM (0x11) or AF_INET6 + STREAM (0x21)
                match (client_addr, server_addr) {
                    (SocketAddr::V4(c), SocketAddr::V4(s)) => {
                        v2_bytes.push(0x11);
                        v2_bytes.extend_from_slice(&12u16.to_be_bytes()); // length: 4+4+2+2 = 12
                        v2_bytes.extend_from_slice(&c.ip().octets());
                        v2_bytes.extend_from_slice(&s.ip().octets());
                        v2_bytes.extend_from_slice(&c.port().to_be_bytes());
                        v2_bytes.extend_from_slice(&s.port().to_be_bytes());
                    }
                    _ => {
                        // Unsupported address combination for test, write 0 length
                        v2_bytes.push(0x00);
                        v2_bytes.extend_from_slice(&0u16.to_be_bytes());
                    }
                }
                v2_bytes
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_copy_relay_distribution() {
        let listen: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let mut supervisor = ZeroCopyRelaySupervisor::new(listen, ProxyProtocolVersion::V1);

        let t1: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let t2: SocketAddr = "10.0.0.2:443".parse().unwrap();
        supervisor.add_endpoint(t1, 10);
        supervisor.add_endpoint(t2, 10);

        let client: SocketAddr = "192.168.1.50:52411".parse().unwrap();
        let (s1, target1) = supervisor.open_session(client);
        let (_s2, target2) = supervisor.open_session(client);

        assert_eq!(target1, Some(t1));
        assert_eq!(target2, Some(t2));

        let v1_hdr = supervisor.generate_proxy_header(&client, &t1);
        let hdr_str = String::from_utf8(v1_hdr).unwrap();
        assert!(hdr_str.starts_with("PROXY TCP4 192.168.1.50 10.0.0.1 52411 443\r\n"));

        supervisor.close_session(s1, 4096);
        assert_eq!(supervisor.endpoints[0].total_bytes_forwarded, 4096);
        assert_eq!(supervisor.endpoints[0].active_connections, 0);
    }
}
