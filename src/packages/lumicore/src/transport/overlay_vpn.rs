
pub struct OverlayVPN {
    pub active: bool,
}

impl Default for OverlayVPN {
    fn default() -> Self {
        Self::new()
    }
}

impl OverlayVPN {
    pub fn new() -> Self {
        OverlayVPN { active: true }
    }

    pub fn tunnel(&self) {
        println!("OverlayVPN: Porting C-based overlay VPN, peer epoll loops, rekeying collision rules, and sliding windows");
    }
}
