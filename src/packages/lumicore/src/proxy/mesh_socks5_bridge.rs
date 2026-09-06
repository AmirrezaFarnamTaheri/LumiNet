// Pure Rust implementation: Mesh SOCKS5 Exit Node Bridge

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5AuthMethod {
    NoAuth,
    UsernamePassword(String, String),
}

#[derive(Debug, Clone)]
pub struct MeshExitNodeTarget {
    pub node_id: String,
    pub virtual_ip: Ipv4Addr,
    pub auth_token: Option<String>,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDisposition {
    RouteViaMesh(Ipv4Addr),
    DirectBypass,
    Blocked(String),
}

pub struct MeshSocks5Bridge {
    pub listen_port: u16,
    pub target_exit_node: Option<MeshExitNodeTarget>,
    pub credentials: HashMap<String, String>,
    pub allowed_subnets: Vec<String>,
}

impl MeshSocks5Bridge {
    pub fn new(listen_port: u16) -> Self {
        Self {
            listen_port,
            target_exit_node: None,
            credentials: HashMap::new(),
            allowed_subnets: Vec::new(),
        }
    }

    pub fn set_exit_node(&mut self, target: MeshExitNodeTarget) {
        self.target_exit_node = Some(target);
    }

    pub fn add_user(&mut self, username: impl Into<String>, password: impl Into<String>) {
        self.credentials.insert(username.into(), password.into());
    }

    pub fn authenticate(&self, user: &str, pass: &str) -> bool {
        if self.credentials.is_empty() {
            return true;
        }
        self.credentials.get(user).map(|p| p == pass).unwrap_or(false)
    }

    pub fn evaluate_route(&self, target_host: &str, target_port: u16) -> RouteDisposition {
        if target_port == 0 {
            return RouteDisposition::Blocked("Invalid destination port".to_string());
        }

        // Loopback / RFC1918 bypass checks
        if target_host == "localhost" || target_host == "127.0.0.1" {
            return RouteDisposition::DirectBypass;
        }

        if let Some(ref exit) = self.target_exit_node {
            if exit.active {
                return RouteDisposition::RouteViaMesh(exit.virtual_ip);
            }
        }

        RouteDisposition::DirectBypass
    }

    pub fn parse_socks5_greeting(&self, buffer: &[u8]) -> Result<u8, &'static str> {
        if buffer.len() < 2 {
            return Err("Greeting buffer too short");
        }
        if buffer[0] != 0x05 {
            return Err("Invalid SOCKS version (expected 0x05)");
        }
        let nmethods = buffer[1] as usize;
        if buffer.len() < 2 + nmethods {
            return Err("Incomplete methods list");
        }

        let methods = &buffer[2..2 + nmethods];
        if self.credentials.is_empty() {
            if methods.contains(&0x00) {
                Ok(0x00) // NO AUTHENTICATION REQUIRED
            } else {
                Err("Client does not support NO_AUTH")
            }
        } else {
            if methods.contains(&0x02) {
                Ok(0x02) // USERNAME/PASSWORD
            } else {
                Err("Client does not support USER/PASS AUTH")
            }
        }
    }

    pub fn craft_greeting_response(&self, selected_method: u8) -> [u8; 2] {
        [0x05, selected_method]
    }

    pub fn craft_reply(
        &self,
        rep_code: u8,
        bound_addr: SocketAddr,
    ) -> Vec<u8> {
        let mut reply = vec![0x05, rep_code, 0x00];
        match bound_addr {
            SocketAddr::V4(v4) => {
                reply.push(0x01); // IPv4
                reply.extend_from_slice(&v4.ip().octets());
                reply.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                reply.push(0x04); // IPv6
                reply.extend_from_slice(&v6.ip().octets());
                reply.extend_from_slice(&v6.port().to_be_bytes());
            }
        }
        reply
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socks5_greeting_and_auth() {
        let mut bridge = MeshSocks5Bridge::new(1080);
        
        // No auth configured -> accepts 0x00
        let greeting = [0x05, 0x01, 0x00];
        assert_eq!(bridge.parse_socks5_greeting(&greeting), Ok(0x00));
        assert_eq!(bridge.craft_greeting_response(0x00), [0x05, 0x00]);

        // With user configured -> requires 0x02
        bridge.add_user("alice", "secret123");
        assert_eq!(bridge.parse_socks5_greeting(&greeting), Err("Client does not support USER/PASS AUTH"));
        
        let greeting_with_auth = [0x05, 0x02, 0x00, 0x02];
        assert_eq!(bridge.parse_socks5_greeting(&greeting_with_auth), Ok(0x02));
        assert!(bridge.authenticate("alice", "secret123"));
        assert!(!bridge.authenticate("alice", "wrongpass"));
    }

    #[test]
    fn test_route_evaluation_and_reply_crafting() {
        let mut bridge = MeshSocks5Bridge::new(1080);
        let exit = MeshExitNodeTarget {
            node_id: "exit-de-1".to_string(),
            virtual_ip: Ipv4Addr::new(100, 64, 0, 99),
            auth_token: None,
            active: true,
        };
        bridge.set_exit_node(exit);

        // Localhost bypasses
        assert_eq!(bridge.evaluate_route("127.0.0.1", 80), RouteDisposition::DirectBypass);

        // External goes via mesh exit
        assert_eq!(
            bridge.evaluate_route("1.1.1.1", 443),
            RouteDisposition::RouteViaMesh(Ipv4Addr::new(100, 64, 0, 99))
        );

        // Craft reply packet
        let addr: SocketAddr = "100.64.0.1:1080".parse().unwrap();
        let reply = bridge.craft_reply(0x00, addr);
        assert_eq!(reply[0], 0x05); // SOCKS5
        assert_eq!(reply[1], 0x00); // SUCCESS
        assert_eq!(reply[3], 0x01); // IPv4
    }
}
