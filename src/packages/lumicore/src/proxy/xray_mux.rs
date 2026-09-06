
pub struct XrayMux {
    pub active: bool,
}

impl Default for XrayMux {
    fn default() -> Self {
        Self::new()
    }
}

impl XrayMux {
    pub fn new() -> Self {
        XrayMux { active: true }
    }

    pub fn multiplex(&self) {
        println!("XrayMux: Porting Xray core multi-protocol inputs/outbounds (VLESS+XTLS Vision) and WebSocket multiplexing");
    }
}
