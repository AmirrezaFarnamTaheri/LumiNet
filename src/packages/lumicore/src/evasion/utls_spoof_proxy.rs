
pub struct UTlsSpoofProxy {
    pub active: bool,
}

impl Default for UTlsSpoofProxy {
    fn default() -> Self {
        Self::new()
    }
}

impl UTlsSpoofProxy {
    pub fn new() -> Self {
        UTlsSpoofProxy { active: true }
    }

    pub fn spoof(&self) {
        println!("UTlsSpoofProxy: Porting the Go SOCKS5 proxy, fake ClientHello injection, and uTLS fingerprints");
    }
}
