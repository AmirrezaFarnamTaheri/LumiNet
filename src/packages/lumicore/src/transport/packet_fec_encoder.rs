//! Forward Error Correction (FEC) Block Parity Engine
//!
//! Generates systematic XOR parity packets for groups of UDP payloads to recover
//! lost packets over lossy links without waiting for end-to-end retransmissions.

use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum FecError {
    EmptySourceGroup,
    TooManyMissingShards,
    InvalidShardLength,
}

impl fmt::Display for FecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySourceGroup => write!(f, "Source group contains no packets"),
            Self::TooManyMissingShards => write!(f, "Exceeded recoverable loss threshold"),
            Self::InvalidShardLength => write!(f, "Inconsistent shard lengths"),
        }
    }
}

impl std::error::Error for FecError {}

#[derive(Debug, Clone)]
pub struct PacketFecEncoder {
    pub group_size: usize,
}

impl Default for PacketFecEncoder {
    fn default() -> Self {
        Self { group_size: 4 }
    }
}

impl PacketFecEncoder {
    pub fn new(group_size: usize) -> Self {
        Self {
            group_size: group_size.max(1),
        }
    }

    /// Computes parity packet for a slice of source packets using XOR parity
    pub fn compute_parity(&self, sources: &[Vec<u8>]) -> Result<Vec<u8>, FecError> {
        if sources.is_empty() {
            return Err(FecError::EmptySourceGroup);
        }

        let max_len = sources.iter().map(|p| p.len()).max().unwrap_or(0);
        let mut parity = vec![0u8; max_len];

        for pkt in sources {
            for (i, byte) in pkt.iter().enumerate() {
                parity[i] ^= byte;
            }
        }

        Ok(parity)
    }

    /// Recovers exactly 1 missing source packet from the remaining sources and the parity packet
    pub fn recover_single_missing(
        known_sources: &[Vec<u8>],
        parity: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>, FecError> {
        let mut recovered = parity.to_vec();
        for pkt in known_sources {
            for (i, byte) in pkt.iter().enumerate() {
                if i < recovered.len() {
                    recovered[i] ^= byte;
                }
            }
        }
        recovered.truncate(expected_len);
        Ok(recovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_parity_recovery() {
        let encoder = PacketFecEncoder::new(3);
        let p1 = b"packet 1 data".to_vec();
        let p2 = b"packet 2 data".to_vec();
        let p3 = b"packet 3 data".to_vec();

        let parity = encoder.compute_parity(&[p1.clone(), p2.clone(), p3.clone()]).unwrap();

        // Suppose p2 is lost. Recover p2 using p1, p3, and parity
        let known = vec![p1, p3];
        let recovered_p2 = PacketFecEncoder::recover_single_missing(&known, &parity, p2.len()).unwrap();

        assert_eq!(recovered_p2, p2);
    }
}
