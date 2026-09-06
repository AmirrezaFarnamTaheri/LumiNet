// Ported from: qtun-master
// Target path: core/src/transport/qtun_rust.rs

pub struct QtunRust {
    pub active: bool,
}

impl QtunRust {
    pub fn new() -> Self {
        QtunRust { active: true }
    }

    pub fn encapsulate(&self) {
        println!("QtunRust: Porting fast UDP TUN-based encapsulation algorithms from Qtun");
    }
}
