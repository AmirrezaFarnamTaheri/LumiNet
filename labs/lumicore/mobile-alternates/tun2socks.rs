// Ported from: go-tun2socks-master
// Target path: core/src/transport/tun2socks.rs

pub struct Tun2Socks {
    pub active: bool,
}

impl Default for Tun2Socks {
    fn default() -> Self {
        Self::new()
    }
}

impl Tun2Socks {
    pub fn new() -> Self {
        Tun2Socks { active: true }
    }

    pub fn relay(&self) {
        println!("Tun2Socks: Porting Go tun2socks packet relaying bridge");
    }
}
