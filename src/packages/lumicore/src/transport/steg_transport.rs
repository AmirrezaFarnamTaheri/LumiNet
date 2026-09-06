//
// Steganographic transport plugin interface, mirroring the C++ `steg_config_t`
// and `steg_t` two-class API so pluggable steg modules (HTTP, JS, JPEG, ...)
// register against a common surface. `transmit_room(pref, min, max)` is the
// key backpressure hook: returning 0 tells the protocol layer to wait.

use std::io::{self, Read, Write};

/// Cross-connection configuration for a steg module (mirrors `steg_config_t`).
pub trait StegConfig: Send + Sync {
    fn name(&self) -> &'static str;
    fn create_session(&self, is_client: bool) -> Box<dyn StegSession>;
}

/// Per-connection disguise engine (mirrors `steg_t`).
pub trait StegSession: Send {
    /// How many bytes can be transmitted right now?
    ///   0  → backpressure (do not call encode)
    ///   N  → encode/trim plaintext to exactly N bytes (may pad)
    fn transmit_room(&self, preferred: usize, min: usize, max: usize) -> usize;

    /// Encode `plaintext` into cover traffic, write to `sink`.
    fn encode(&mut self, plaintext: &[u8], sink: &mut dyn Write) -> io::Result<()>;

    /// Decode cover traffic from `source`, write plaintext to `dest`.
    /// Returns `Ok(0)` when more data is needed (not an error).
    fn decode(&mut self, source: &mut dyn Read, dest: &mut Vec<u8>) -> io::Result<usize>;

    fn on_successful_recv(&mut self) {}
    fn on_corrupted_recv(&mut self) -> u32 {
        0
    }
}

type StegFactory = Box<dyn Fn() -> Box<dyn StegConfig> + Send + Sync>;

/// Registry of available steg modules.
pub struct StegRegistry {
    factories: Vec<(&'static str, StegFactory)>,
}

impl StegRegistry {
    pub fn new() -> Self {
        Self {
            factories: Vec::new(),
        }
    }

    pub fn register(
        &mut self,
        name: &'static str,
        factory: impl Fn() -> Box<dyn StegConfig> + Send + Sync + 'static,
    ) {
        self.factories.push((name, Box::new(factory)));
    }

    pub fn create(&self, name: &str) -> Option<Box<dyn StegConfig>> {
        self.factories
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, f)| f())
    }

    pub fn available(&self) -> Vec<&'static str> {
        self.factories.iter().map(|(n, _)| *n).collect()
    }
}

impl Default for StegRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Inert StegConfig for tests -----------------------------------

    struct InertConfig;
    impl StegConfig for InertConfig {
        fn name(&self) -> &'static str {
            "inert"
        }
        fn create_session(&self, _is_client: bool) -> Box<dyn StegSession> {
            Box::new(InertSession)
        }
    }

    struct InertSession;
    impl StegSession for InertSession {
        fn transmit_room(&self, preferred: usize, min: usize, max: usize) -> usize {
            // ponytail: inert impl simply permits the preferred count,
            // clamped to `min..=max`. Used to exercise the registry +
            // backpressure contract without a real cover-traffic corpus.
            preferred.min(max).max(min)
        }
        fn encode(&mut self, plaintext: &[u8], sink: &mut dyn Write) -> io::Result<()> {
            sink.write_all(plaintext)
        }
        fn decode(&mut self, source: &mut dyn Read, dest: &mut Vec<u8>) -> io::Result<usize> {
            let mut buf = [0u8; 64];
            let n = source.read(&mut buf)?;
            dest.extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }

    #[test]
    fn registry_create_returns_registered_module() {
        let mut reg = StegRegistry::new();
        reg.register("inert", || Box::new(InertConfig));
        let cfg = reg.create("inert").expect("inert registered");
        assert_eq!(cfg.name(), "inert");
        let sess = cfg.create_session(true);
        assert_eq!(sess.transmit_room(128, 16, 512), 128);
        assert!(reg.create("missing").is_none());
    }

    #[test]
    fn transmit_room_clamps_to_min_max() {
        let mut reg = StegRegistry::new();
        reg.register("inert", || Box::new(InertConfig));
        let cfg = reg.create("inert").unwrap();
        let sess = cfg.create_session(false);
        assert_eq!(sess.transmit_room(0, 16, 512), 16);
        assert_eq!(sess.transmit_room(1000, 16, 512), 512);
    }
}
