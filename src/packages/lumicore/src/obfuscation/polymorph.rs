//! # Polymorphic Transport
//!
//! Traffic shaping and polymorphism for DPI evasion.
//!
//! Core technique: Convert encrypted bytes into shaped byte streams that
//! mimic allowed protocols or look like random noise. Uses Huffman coding
//! to bridge between uniform crypto bytes and shaped protocol bytes.
//! Statistical distributions control packet timing and length.

use std::collections::HashMap;
use std::time::Duration;

/// Probability distribution for packet length/inter-packet timing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Distribution {
    /// Uniform random between min and max.
    Uniform,
    /// Normal/Gaussian distribution.
    Normal,
    /// Exponential distribution.
    Exponential,
    /// Poisson distribution.
    Poisson,
    /// Laplace distribution.
    Laplace,
}

/// Traffic shaping model configuration.
/// Defines how encrypted traffic is transformed to look like a target protocol.
#[derive(Debug, Clone)]
pub struct ShapingModel {
    /// Name of the model (e.g., "http", "random", "dns").
    pub name: String,
    /// Distribution for packet lengths.
    pub length_distribution: Distribution,
    /// Minimum packet length.
    pub min_length: usize,
    /// Maximum packet length.
    pub max_length: usize,
    /// Mean packet length (for Normal/Poisson/Laplace).
    pub mean_length: f64,
    /// Distribution for inter-packet delays.
    pub timing_distribution: Distribution,
    /// Minimum delay between packets.
    pub min_delay: Duration,
    /// Maximum delay between packets.
    pub max_delay: Duration,
    /// Mean delay (for Normal/Poisson/Laplace).
    pub mean_delay: Duration,
    /// Prefix bytes to prepend to each packet.
    pub prefix: Vec<u8>,
    /// Suffix bytes to append to each packet.
    pub suffix: Vec<u8>,
}

impl Default for ShapingModel {
    fn default() -> Self {
        Self {
            name: "random".to_string(),
            length_distribution: Distribution::Uniform,
            min_length: 200,
            max_length: 1400,
            mean_length: 600.0,
            timing_distribution: Distribution::Uniform,
            min_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(100),
            mean_delay: Duration::from_millis(50),
            prefix: Vec::new(),
            suffix: Vec::new(),
        }
    }
}

/// Pre-defined shaping models that mimic common protocols.
pub fn http_model() -> ShapingModel {
    ShapingModel {
        name: "http".to_string(),
        length_distribution: Distribution::Normal,
        min_length: 100,
        max_length: 8000,
        mean_length: 1200.0,
        timing_distribution: Distribution::Exponential,
        min_delay: Duration::from_millis(5),
        max_delay: Duration::from_millis(500),
        mean_delay: Duration::from_millis(50),
        prefix: b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n".to_vec(),
        suffix: b"\r\n".to_vec(),
    }
}

pub fn dns_model() -> ShapingModel {
    ShapingModel {
        name: "dns".to_string(),
        length_distribution: Distribution::Uniform,
        min_length: 40,
        max_length: 512,
        mean_length: 128.0,
        timing_distribution: Distribution::Poisson,
        min_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(100),
        mean_delay: Duration::from_millis(10),
        prefix: Vec::new(),
        suffix: Vec::new(),
    }
}

pub fn random_model() -> ShapingModel {
    ShapingModel::default()
}

/// Samples from a probability distribution.
pub fn sample_distribution(dist: Distribution, min: f64, max: f64, mean: f64) -> f64 {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    match dist {
        Distribution::Uniform => rng.gen_range(min..max),
        Distribution::Normal => {
            // Box-Muller transform
            let u1: f64 = rng.gen_range(0.001..1.0);
            let u2: f64 = rng.gen_range(0.0..1.0);
            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
            let val = mean + z * (max - min) / 6.0;
            val.clamp(min, max)
        }
        Distribution::Exponential => {
            let lambda = 1.0 / mean.max(1.0);
            let u: f64 = rng.gen_range(0.001..1.0);
            let val = -u.ln() / lambda;
            val.clamp(min, max)
        }
        Distribution::Poisson => {
            // Knuth's algorithm
            let l = (-mean).exp();
            let mut k = 0u32;
            let mut p = 1.0f64;
            loop {
                k += 1;
                let u: f64 = rng.gen_range(0.0..1.0);
                p *= u;
                if p < l {
                    break;
                }
            }
            (k as f64).clamp(min, max)
        }
        Distribution::Laplace => {
            let u: f64 = rng.gen_range(-0.999..0.999);
            let b = (max - min) / 4.0;
            let val = mean - b * u.signum() * (1.0 - 2.0 * u.abs()).ln();
            val.clamp(min, max)
        }
    }
}

/// Samples the next packet length from a shaping model.
pub fn next_packet_length(model: &ShapingModel) -> usize {
    let len = sample_distribution(
        model.length_distribution,
        model.min_length as f64,
        model.max_length as f64,
        model.mean_length,
    );
    len as usize
}

/// Samples the next inter-packet delay from a shaping model.
pub fn next_packet_delay(model: &ShapingModel) -> Duration {
    let delay_ms = sample_distribution(
        model.timing_distribution,
        model.min_delay.as_secs_f64() * 1000.0,
        model.max_delay.as_secs_f64() * 1000.0,
        model.mean_delay.as_secs_f64() * 1000.0,
    );
    Duration::from_millis(delay_ms as u64)
}

/// Huffman coding table for byte-to-shaped-byte transformation.
/// Used to bridge between uniform crypto bytes and shaped protocol bytes.
#[derive(Debug, Clone)]
pub struct HuffmanTable {
    /// Encoded representations for each byte value (0-255).
    pub codes: Vec<Vec<bool>>,
    /// Decoding tree: bit pattern → byte value.
    pub decode_tree: HashMap<Vec<bool>, u8>,
}

impl HuffmanTable {
    /// Creates a uniform Huffman table (no shaping, 1:1 mapping).
    pub fn uniform() -> Self {
        let mut codes = Vec::with_capacity(256);
        for i in 0..256 {
            // 8-bit direct encoding
            let mut code = Vec::with_capacity(8);
            for bit in 0..8 {
                code.push((i >> (7 - bit)) & 1 == 1);
            }
            codes.push(code);
        }

        let mut decode_tree = HashMap::new();
        for (byte, code) in codes.iter().enumerate() {
            decode_tree.insert(code.clone(), byte as u8);
        }

        Self { codes, decode_tree }
    }

    /// Encodes a byte using this Huffman table.
    pub fn encode_byte(&self, byte: u8) -> &[bool] {
        &self.codes[byte as usize]
    }

    /// Decodes a bit sequence to a byte.
    pub fn decode_bits(&self, bits: &[bool]) -> Option<u8> {
        self.decode_tree.get(bits).copied()
    }
}

/// Traffic shaper that transforms encrypted data into shaped packets.
pub struct TrafficShaper {
    model: ShapingModel,
    huffman: HuffmanTable,
}

impl TrafficShaper {
    pub fn new(model: ShapingModel) -> Self {
        Self {
            model,
            huffman: HuffmanTable::uniform(),
        }
    }

    /// Shapes encrypted data into a packet that matches the model's profile.
    pub fn shape(&self, data: &[u8]) -> Vec<u8> {
        let target_len = next_packet_length(&self.model);
        let mut shaped =
            Vec::with_capacity(target_len + self.model.prefix.len() + self.model.suffix.len());

        // Add prefix
        shaped.extend_from_slice(&self.model.prefix);

        // Add data (padded to target length if needed)
        shaped.extend_from_slice(data);
        while shaped.len() < target_len {
            shaped.push(0); // Zero-byte padding (chatterbox constraint)
        }

        // Truncate if too long
        shaped.truncate(target_len);

        // Add suffix
        shaped.extend_from_slice(&self.model.suffix);

        shaped
    }

    /// Returns the delay before sending the next packet.
    pub fn next_delay(&self) -> Duration {
        next_packet_delay(&self.model)
    }

    /// Returns the model name.
    pub fn model_name(&self) -> &str {
        &self.model.name
    }

    /// Returns the Huffman table retained for reversible shaped encodings.
    pub fn huffman(&self) -> &HuffmanTable {
        &self.huffman
    }
}

/// Model registry for pluggable shaping models.
/// Models register at init time and are selected by name.
pub struct ModelRegistry {
    models: HashMap<String, ShapingModel>,
}

impl Default for ModelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelRegistry {
    pub fn new() -> Self {
        let mut models = HashMap::new();
        models.insert("http".to_string(), http_model());
        models.insert("dns".to_string(), dns_model());
        models.insert("random".to_string(), random_model());
        Self { models }
    }

    pub fn register(&mut self, model: ShapingModel) {
        self.models.insert(model.name.clone(), model);
    }

    pub fn get(&self, name: &str) -> Option<&ShapingModel> {
        self.models.get(name)
    }

    pub fn list(&self) -> Vec<&str> {
        self.models.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uniform_huffman() {
        let table = HuffmanTable::uniform();
        for byte in 0..=255u8 {
            let encoded = table.encode_byte(byte);
            assert_eq!(encoded.len(), 8);
            let decoded = table.decode_bits(encoded).unwrap();
            assert_eq!(decoded, byte);
        }
    }

    #[test]
    fn test_packet_length_sampling() {
        let model = random_model();
        for _ in 0..100 {
            let len = next_packet_length(&model);
            assert!(len >= model.min_length);
            assert!(len <= model.max_length);
        }
    }

    #[test]
    fn test_packet_delay_sampling() {
        let model = random_model();
        for _ in 0..100 {
            let delay = next_packet_delay(&model);
            assert!(delay >= model.min_delay);
            assert!(delay <= model.max_delay);
        }
    }

    #[test]
    fn test_http_model_prefix() {
        let model = http_model();
        assert!(model.prefix.starts_with(b"HTTP/1.1 200 OK"));
    }

    #[test]
    fn test_model_registry() {
        let registry = ModelRegistry::new();
        assert!(registry.get("http").is_some());
        assert!(registry.get("dns").is_some());
        assert!(registry.get("random").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_traffic_shaper() {
        let shaper = TrafficShaper::new(random_model());
        let data = b"Hello, world!";
        let shaped = shaper.shape(data);
        assert!(shaped.len() >= 200);
        assert!(shaped.len() <= 1400);
    }
}
