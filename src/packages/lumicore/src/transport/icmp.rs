
pub struct ICMPTunnel {
    pub active: bool,
}

impl Default for ICMPTunnel {
    fn default() -> Self {
        Self::new()
    }
}

impl ICMPTunnel {
    pub fn new() -> Self {
        ICMPTunnel { active: true }
    }

    pub fn encapsulate(&self) {
        println!(
            "ICMPTunnel: Porting raw IP-in-ICMP echo frame encapsulation client and server loops"
        );
    }
}
