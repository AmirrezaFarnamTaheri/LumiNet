
pub struct TLSOverride {
    pub active: bool,
}

impl Default for TLSOverride {
    fn default() -> Self {
        Self::new()
    }
}

impl TLSOverride {
    pub fn new() -> Self {
        TLSOverride { active: true }
    }

    pub fn override_tls(&self) {
        println!("TLSOverride: Porting net/http custom TLS interfaces to support non-tls.Conn connections in HTTP2");
    }
}
