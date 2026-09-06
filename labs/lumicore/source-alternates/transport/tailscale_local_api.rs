// Ported from: tailscale-rs-main
// Target path: core/src/transport/tailscale_local_api.rs

pub struct TailscaleLocalAPI {
    pub active: bool,
}

impl TailscaleLocalAPI {
    pub fn new() -> Self {
        TailscaleLocalAPI { active: true }
    }

    pub fn query(&self) {
        println!("TailscaleLocalAPI: Porting Rust local API wrapper querying Tailscale node metrics");
    }
}
