//! # Amnezia Obfuscation Parameters
//!
//! Synthesizes, randomizes, and applies AmneziaWG 2.0 / 3.x anti-censorship parameters
//! (Jc junk count, Jmin/Jmax lengths, S1/S2 magic padding, H1-H4 header transforms) for DPI evasion.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AmneziaParams {
    pub jc: u16,
    pub jmin: u16,
    pub jmax: u16,
    pub s1: u16,
    pub s2: u16,
    pub h1: u32,
    pub h2: u32,
    pub h3: u32,
    pub h4: u32,
}

impl Default for AmneziaParams {
    fn default() -> Self {
        Self {
            jc: 4,
            jmin: 40,
            jmax: 70,
            s1: 56,
            s2: 56,
            h1: 0x12345678,
            h2: 0x23456789,
            h3: 0x3456789a,
            h4: 0x456789ab,
        }
    }
}

pub struct AmneziaObfsParameters {
    params: AmneziaParams,
}

impl AmneziaObfsParameters {
    pub fn new(params: AmneziaParams) -> Self {
        Self { params }
    }

    pub fn generate_random(seed: u64) -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);

        let jc = 3 + (rng.gen::<u16>() % 6); // 3..8
        let jmin = 30 + (rng.gen::<u16>() % 30); // 30..59
        let jmax = jmin + 20 + (rng.gen::<u16>() % 40); // jmin+20..jmin+60
        let s1 = 16 + (rng.gen::<u16>() % 64);
        let s2 = 16 + (rng.gen::<u16>() % 64);

        let h1 = rng.gen::<u32>();
        let h2 = rng.gen::<u32>();
        let h3 = rng.gen::<u32>();
        let h4 = rng.gen::<u32>();

        Self {
            params: AmneziaParams {
                jc,
                jmin,
                jmax,
                s1,
                s2,
                h1,
                h2,
                h3,
                h4,
            },
        }
    }

    pub fn transform_header(&self, original_header_type: u8) -> u32 {
        match original_header_type {
            1 => self.params.h1, // Handshake Initiation
            2 => self.params.h2, // Handshake Response
            3 => self.params.h3, // Cookie Reply
            4 => self.params.h4, // Transport Data
            _ => 0,
        }
    }

    pub fn reverse_header(&self, transformed_header: u32) -> Option<u8> {
        if transformed_header == self.params.h1 {
            Some(1)
        } else if transformed_header == self.params.h2 {
            Some(2)
        } else if transformed_header == self.params.h3 {
            Some(3)
        } else if transformed_header == self.params.h4 {
            Some(4)
        } else {
            None
        }
    }

    pub fn export_config_lines(&self) -> String {
        format!(
            "Jc = {}\nJmin = {}\nJmax = {}\nS1 = {}\nS2 = {}\nH1 = {}\nH2 = {}\nH3 = {}\nH4 = {}",
            self.params.jc,
            self.params.jmin,
            self.params.jmax,
            self.params.s1,
            self.params.s2,
            self.params.h1,
            self.params.h2,
            self.params.h3,
            self.params.h4,
        )
    }

    pub fn get_params(&self) -> &AmneziaParams {
        &self.params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amnezia_parameters_generation_and_headers() {
        let obfs = AmneziaObfsParameters::generate_random(42);
        let p = obfs.get_params();

        assert!(p.jc >= 3 && p.jc <= 8);
        assert!(p.jmin < p.jmax);

        // Header transforms
        let t1 = obfs.transform_header(1);
        let t4 = obfs.transform_header(4);
        assert_eq!(obfs.reverse_header(t1), Some(1));
        assert_eq!(obfs.reverse_header(t4), Some(4));
        assert_eq!(obfs.reverse_header(0x99999999), None);

        let cfg = obfs.export_config_lines();
        assert!(cfg.contains("Jc = "));
        assert!(cfg.contains("H1 = "));
    }
}
