//! # Dynamic Gateway Route Updater
//!
//! Synchronizes platform kernel routing tables, updates interface metrics,
//! and orchestrates seamless gateway failovers.
//! Ported and enhanced from lincank/autoddvpn.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayRoute {
    pub destination_cidr: String,
    pub gateway_ip: String,
    pub metric: u32,
    pub interface_name: String,
}

#[derive(Debug, Clone, Default)]
pub struct DynamicGatewayUpdater {
    routes: HashMap<String, GatewayRoute>,
    default_gateway: Option<String>,
    default_interface: Option<String>,
}

impl DynamicGatewayUpdater {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            default_gateway: None,
            default_interface: None,
        }
    }

    pub fn set_default_gateway(&mut self, gw: &str, iface: &str) {
        self.default_gateway = Some(gw.to_string());
        self.default_interface = Some(iface.to_string());
    }

    pub fn add_route(&mut self, route: GatewayRoute) {
        self.routes.insert(route.destination_cidr.clone(), route);
    }

    pub fn remove_route(&mut self, cidr: &str) -> Option<GatewayRoute> {
        self.routes.remove(cidr)
    }

    /// Compiles OS-native command strings for route manipulation.
    pub fn compile_commands(&self, platform: &str) -> Vec<String> {
        let mut cmds = Vec::new();
        for route in self.routes.values() {
            match platform {
                "linux" => {
                    cmds.push(format!(
                        "ip route add {} via {} dev {} metric {}",
                        route.destination_cidr, route.gateway_ip, route.interface_name, route.metric
                    ));
                }
                "windows" => {
                    cmds.push(format!(
                        "route add {} mask 255.255.255.0 {} metric {}",
                        route.destination_cidr.split('/').next().unwrap_or(""),
                        route.gateway_ip,
                        route.metric
                    ));
                }
                "darwin" => {
                    cmds.push(format!(
                        "route add -net {} {} -interface {}",
                        route.destination_cidr, route.gateway_ip, route.interface_name
                    ));
                }
                _ => {
                    cmds.push(format!(
                        "route add {} gw {}",
                        route.destination_cidr, route.gateway_ip
                    ));
                }
            }
        }
        cmds
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_gateway_updater() {
        let mut updater = DynamicGatewayUpdater::new();
        updater.set_default_gateway("10.8.0.1", "tun0");
        updater.add_route(GatewayRoute {
            destination_cidr: "1.1.1.1/32".to_string(),
            gateway_ip: "10.8.0.1".to_string(),
            metric: 10,
            interface_name: "tun0".to_string(),
        });

        assert_eq!(updater.route_count(), 1);
        let linux_cmds = updater.compile_commands("linux");
        assert_eq!(linux_cmds.len(), 1);
        assert!(linux_cmds[0].contains("ip route add 1.1.1.1/32 via 10.8.0.1 dev tun0 metric 10"));

        updater.remove_route("1.1.1.1/32");
        assert_eq!(updater.route_count(), 0);
    }
}
