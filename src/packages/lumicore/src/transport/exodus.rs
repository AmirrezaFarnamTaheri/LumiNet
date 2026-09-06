
pub struct ExodusTransport {
    pub active: bool,
}

impl Default for ExodusTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ExodusTransport {
    pub fn new() -> Self {
        ExodusTransport { active: true }
    }

    pub fn transport(&self) {
        println!("ExodusTransport: Porting Rust UDP tunnel, DHCP IP assignment handshake, and virtual TUN interface adapters");
    }
}
