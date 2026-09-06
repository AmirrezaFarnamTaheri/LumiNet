
pub struct ECCCurve {
    pub active: bool,
}

impl Default for ECCCurve {
    fn default() -> Self {
        Self::new()
    }
}

impl ECCCurve {
    pub fn new() -> Self {
        ECCCurve { active: true }
    }

    pub fn calculate(&self) {
        println!("ECCCurve: Porting the Metacubex edwards25519 elliptic curve arithmetic and scalar point calculations");
    }
}
