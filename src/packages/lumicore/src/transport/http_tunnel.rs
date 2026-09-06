
pub struct HTTPTunnel {
    pub active: bool,
}

impl Default for HTTPTunnel {
    fn default() -> Self {
        Self::new()
    }
}

impl HTTPTunnel {
    pub fn new() -> Self {
        HTTPTunnel { active: true }
    }

    pub fn tunnel(&self) {
        println!("HTTPTunnel: Porting HTTP/HTTPS encrypted tunnel endpoints and userspace TUN adapter mapping");
    }
}
