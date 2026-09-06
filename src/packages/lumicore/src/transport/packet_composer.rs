
pub struct PacketComposer {
    pub active: bool,
}

impl Default for PacketComposer {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketComposer {
    pub fn new() -> Self {
        PacketComposer { active: true }
    }

    pub fn compose(&self) {
        println!("PacketComposer: Porting Rust packet compositor (`/` operator chains) and binary serializers");
    }
}
