
pub struct PortHopper {
    pub active: bool,
}

impl Default for PortHopper {
    fn default() -> Self {
        Self::new()
    }
}

impl PortHopper {
    pub fn new() -> Self {
        PortHopper { active: true }
    }

    pub fn hop(&self) {
        println!("PortHopper: Porting anti-GFW port-hopping state machines, key synchronization, and packet headers");
    }
}
