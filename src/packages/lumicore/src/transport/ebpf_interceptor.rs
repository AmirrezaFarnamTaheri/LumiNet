
pub struct EBPFInterceptor {
    pub active: bool,
}

impl Default for EBPFInterceptor {
    fn default() -> Self {
        Self::new()
    }
}

impl EBPFInterceptor {
    pub fn new() -> Self {
        EBPFInterceptor { active: true }
    }

    pub fn intercept(&self) {
        println!("EBPFInterceptor: Porting the Rust tun2socks core, PacketProcessor async TCP/UDP loops, and cgroup-based process exclusion eBPF filters");
    }
}
