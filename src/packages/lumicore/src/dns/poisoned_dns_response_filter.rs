//! Anti-Poisoning DNS Response Filter
//!
//! Inspects received DNS responses against canonical bogus IP tables injected by network middleboxes,
//! filtering out spurious forged responses while awaiting genuine authoritative responses.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

pub struct PoisonedDnsResponseFilter {
    bogus_ips: HashSet<Ipv4Addr>,
    total_poisoned_dropped: u64,
    total_valid_accepted: u64,
}

impl PoisonedDnsResponseFilter {
    pub fn new() -> Self {
        let mut bogus = HashSet::new();
        // Canonical censorship bogus injection IPs
        let known_bogus = [
            "74.125.127.102", "74.125.155.102", "74.125.39.102", "74.125.39.113",
            "189.163.17.5", "209.85.229.138", "249.129.46.48", "77.4.7.92",
            "128.121.126.139", "159.106.121.75", "169.132.13.103", "192.67.198.6",
            "202.106.1.2", "202.181.7.85", "203.161.230.171", "203.98.7.65",
            "207.12.88.98", "208.56.31.43", "209.145.54.50", "209.220.30.174",
            "209.36.73.33", "211.94.66.147", "213.169.251.35", "216.221.188.182",
            "216.234.179.13", "243.185.187.39", "37.61.54.158", "4.36.66.178",
            "46.82.174.68", "59.24.3.173", "64.33.88.161", "64.33.99.47",
            "64.66.163.251", "65.104.202.252", "65.160.219.113", "66.45.252.237",
            "72.14.205.104", "72.14.205.99", "78.16.49.15", "8.7.198.45", "93.46.8.89",
            "253.157.14.165", "180.168.41.175", "49.2.123.56",
        ];

        for ip_str in known_bogus {
            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                bogus.insert(ip);
            }
        }

        Self {
            bogus_ips: bogus,
            total_poisoned_dropped: 0,
            total_valid_accepted: 0,
        }
    }

    pub fn is_bogus_ip(&self, ip: &Ipv4Addr) -> bool {
        self.bogus_ips.contains(ip)
    }

    pub fn filter_response_ips(&mut self, candidate_ips: &[IpAddr]) -> Vec<IpAddr> {
        let mut clean = Vec::new();
        for ip in candidate_ips {
            match ip {
                IpAddr::V4(v4) => {
                    if self.is_bogus_ip(v4) {
                        self.total_poisoned_dropped += 1;
                    } else {
                        self.total_valid_accepted += 1;
                        clean.push(*ip);
                    }
                }
                IpAddr::V6(_) => {
                    self.total_valid_accepted += 1;
                    clean.push(*ip);
                }
            }
        }
        clean
    }

    pub fn add_bogus_ip(&mut self, ip: Ipv4Addr) {
        self.bogus_ips.insert(ip);
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.total_poisoned_dropped, self.total_valid_accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_poisoning_filter() {
        let mut filter = PoisonedDnsResponseFilter::new();
        let bogus_ip: IpAddr = "74.125.127.102".parse().unwrap();
        let valid_ip: IpAddr = "142.250.190.46".parse().unwrap();

        let filtered = filter.filter_response_ips(&[bogus_ip, valid_ip]);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0], valid_ip);

        let (dropped, accepted) = filter.stats();
        assert_eq!(dropped, 1);
        assert_eq!(accepted, 1);
    }
}
