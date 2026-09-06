use std::net::{IpAddr, ToSocketAddrs};

pub struct SecureProxyTunneling;

impl SecureProxyTunneling {
    /// Mitigates DNS rebinding vulnerabilities by classifying resolved IPs to block link-locals/private spaces
    pub fn resolve_and_classify(domain: &str) -> Result<Vec<IpAddr>, &'static str> {
        let mut valid_ips = Vec::new();
        
        // Append port 80 for resolution purposes
        let addrs = format!("{}:80", domain).to_socket_addrs().map_err(|_| "DNS resolution failed")?;
        
        for addr in addrs {
            let ip = addr.ip();
            if Self::is_private_or_link_local(&ip) {
                return Err("DNS Rebinding attempt detected: Resolved to private or link-local IP.");
            }
            valid_ips.push(ip);
        }
        
        if valid_ips.is_empty() {
            return Err("No valid public IPs resolved.");
        }
        
        Ok(valid_ips)
    }

    fn is_private_or_link_local(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private() || ipv4.is_link_local() || ipv4.is_loopback() || ipv4.is_broadcast() || ipv4.is_unspecified()
            },
            IpAddr::V6(ipv6) => {
                // Check basic IPv6 private/loopback scopes
                ipv6.is_loopback() || ipv6.is_unspecified() || (ipv6.segments()[0] & 0xfe00) == 0xfc00
            }
        }
    }

    /// Subsequently pinning reqwest's resolver to the exact addresses that passed validation
    pub fn resolve_to_addrs(client_builder: reqwest::ClientBuilder, domain: &str, ips: Vec<IpAddr>) -> reqwest::ClientBuilder {
        let mut socket_addrs = Vec::new();
        for ip in ips {
            socket_addrs.push(std::net::SocketAddr::new(ip, 443));
        }
        // Pinning the resolved IPs to reqwest's custom resolver
        client_builder.resolve_to_addrs(domain, &socket_addrs)
    }
}
