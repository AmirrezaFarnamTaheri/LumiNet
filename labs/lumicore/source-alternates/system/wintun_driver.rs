// Ported from: wintun-master
// Target path: core/src/system/wintun_driver.rs

pub struct WintunDriver {
    pub pool_name: String,
}

impl WintunDriver {
    pub fn new(pool_name: &str) -> Self {
        WintunDriver {
            pool_name: pool_name.to_string(),
        }
    }

    pub fn create_adapter(&self, name: &str) {
        println!("wintun_driver: Wrapping official WireGuard Wintun virtual network adapter C driver");
        println!("wintun_driver: Creating adapter '{}' in pool '{}'", name, self.pool_name);
    }
}
