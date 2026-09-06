
pub struct ECHPlugin {
    pub active: bool,
}

impl Default for ECHPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ECHPlugin {
    pub fn new() -> Self {
        ECHPlugin { active: true }
    }

    pub fn handle_ech(&self) {
        println!("ECHPlugin: Porting Shadowsocks ECH plugin, HPKE keys exchange, and local nginx fake 404 response builders");
    }
}
