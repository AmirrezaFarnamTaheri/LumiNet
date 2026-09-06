// Pure Rust implementation: Split Tunneling Routing Rule Synchronizer

use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingAction {
    RouteThroughVpn,
    BypassVpn,
    Drop,
}

#[derive(Debug, Clone)]
pub struct SplitTunnelRule {
    pub id: String,
    pub network: Ipv4Addr,
    pub prefix_len: u8,
    pub action: RoutingAction,
    pub priority: u32,
}

pub struct SplitTunnelRuleSync {
    pub rules: Vec<SplitTunnelRule>,
    pub default_action: RoutingAction,
    pub sync_version: u64,
}

impl SplitTunnelRuleSync {
    pub fn new(default_action: RoutingAction) -> Self {
        Self {
            rules: Vec::new(),
            default_action,
            sync_version: 0,
        }
    }

    pub fn add_rule(
        &mut self,
        id: impl Into<String>,
        cidr: &str,
        action: RoutingAction,
        priority: u32,
    ) -> Result<(), String> {
        let (network, prefix_len) = parse_cidr(cidr)?;
        self.rules.push(SplitTunnelRule {
            id: id.into(),
            network,
            prefix_len,
            action,
            priority,
        });

        // Keep rules sorted descending by priority, then descending by prefix length (longest prefix match)
        self.rules.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| b.prefix_len.cmp(&a.prefix_len))
        });
        self.sync_version += 1;
        Ok(())
    }

    pub fn match_ip(&self, ip: Ipv4Addr) -> RoutingAction {
        let ip_u32 = u32::from(ip);
        for rule in &self.rules {
            let mask = if rule.prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - rule.prefix_len)
            };
            if (ip_u32 & mask) == (u32::from(rule.network) & mask) {
                return rule.action;
            }
        }
        self.default_action
    }

    pub fn sync_from_cidr_feed(&mut self, feed_lines: &str, action: RoutingAction) -> usize {
        let mut count = 0;
        for line in feed_lines.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let rule_id = format!("feed-{}", count + 1);
            if self.add_rule(rule_id, trimmed, action, 100).is_ok() {
                count += 1;
            }
        }
        count
    }
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() == 1 {
        // Single IP as /32
        let ip = parts[0].parse::<Ipv4Addr>().map_err(|e| e.to_string())?;
        return Ok((ip, 32));
    }
    if parts.len() != 2 {
        return Err("Invalid CIDR notation".to_string());
    }
    let ip = parts[0].parse::<Ipv4Addr>().map_err(|e| e.to_string())?;
    let prefix = parts[1].parse::<u8>().map_err(|e| e.to_string())?;
    if prefix > 32 {
        return Err("CIDR prefix cannot exceed 32".to_string());
    }
    Ok((ip, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_tunnel_longest_prefix_match() {
        let mut sync = SplitTunnelRuleSync::new(RoutingAction::BypassVpn);

        // General 10.0.0.0/8 routes via VPN
        sync.add_rule("rule-1", "10.0.0.0/8", RoutingAction::RouteThroughVpn, 10).unwrap();
        // Exception: 10.1.2.0/24 bypasses VPN
        sync.add_rule("rule-2", "10.1.2.0/24", RoutingAction::BypassVpn, 10).unwrap();

        // 10.1.2.5 matches rule-2 (longer prefix /24)
        assert_eq!(sync.match_ip(Ipv4Addr::new(10, 1, 2, 5)), RoutingAction::BypassVpn);
        // 10.2.0.1 matches rule-1 (/8)
        assert_eq!(sync.match_ip(Ipv4Addr::new(10, 2, 0, 1)), RoutingAction::RouteThroughVpn);
        // 192.168.1.1 matches default
        assert_eq!(sync.match_ip(Ipv4Addr::new(192, 168, 1, 1)), RoutingAction::BypassVpn);
    }

    #[test]
    fn test_feed_import() {
        let mut sync = SplitTunnelRuleSync::new(RoutingAction::BypassVpn);
        let feed = "# Blocked prefixes\n185.199.108.0/22\n140.82.112.0/20\n\n";
        let imported = sync.sync_from_cidr_feed(feed, RoutingAction::RouteThroughVpn);
        assert_eq!(imported, 2);
        assert_eq!(sync.match_ip(Ipv4Addr::new(185, 199, 109, 1)), RoutingAction::RouteThroughVpn);
    }
}
