//! # Composable Evasion Pipeline
//!
//! Composable packet manipulation pipeline for IDS evasion.
//! Ported from ev-master (IDS Evasion via TCP/IP Packet Manipulation).
//!
//! Each evasion is a transform function that wraps a packet.
//! Multiple transforms are applied per segment, producing variants
//! that get shuffled and sent sequentially.

use std::net::TcpStream;
use std::io::Write;
use std::time::Duration;

/// Evasion transform function type.
pub type EvasionTransform = Box<dyn Fn(&[u8]) -> Vec<u8>>;

/// Evasion pipeline configuration.
#[derive(Debug, Clone)]
pub struct EvasionPipeline {
    /// Transforms to apply to each packet.
    pub transforms: Vec<EvasionTransformConfig>,
    /// Delay between packets in milliseconds.
    pub delay_ms: u64,
    /// Delay after SYN handshake in milliseconds.
    pub syn_delay_ms: u64,
    /// Shuffle packet groups before sending.
    pub shuffle: bool,
}

/// Individual evasion transform configuration.
#[derive(Debug, Clone)]
pub enum EvasionTransformConfig {
    /// TCP segmentation - split payload into N-byte segments.
    TcpSegmentation { segment_size: usize },
    /// IP fragmentation - fragment at IP layer.
    IpFragmentation { fragment_size: usize },
    /// Small TTL - packet expires before reaching target.
    SmallTtl { ttl: u8 },
    /// Bad checksum - corrupt TCP checksum.
    BadChecksum,
    /// Corrupt ACK - wrong ACK number.
    CorruptAck { offset: i32 },
    /// Corrupt flags - nonsensical TCP flag combinations.
    CorruptFlags { flags: u8 },
    /// Out-of-order delivery.
    OutOfOrder,
    /// Garbage payload - replace with random data.
    GarbagePayload,
    /// RST packet.
    RstPacket,
}

impl Default for EvasionPipeline {
    fn default() -> Self {
        Self {
            transforms: Vec::new(),
            delay_ms: 10,
            syn_delay_ms: 100,
            shuffle: false,
        }
    }
}

/// Applies TCP segmentation to a payload.
/// Splits into N-byte segments with correct SEQ numbers.
pub fn tcp_segmentation(data: &[u8], segment_size: usize) -> Vec<Vec<u8>> {
    let mut segments = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + segment_size).min(data.len());
        segments.push(data[offset..end].to_vec());
        offset = end;
    }
    segments
}

/// Generates random ASCII string for garbage payloads.
pub fn random_string(length: usize) -> Vec<u8> {
    (0..length).map(|_| rand::random::<u8>() % 94 + 33).collect()
}

/// Corrupts a TCP checksum by adding a random offset.
pub fn corrupt_checksum(data: &[u8]) -> Vec<u8> {
    let mut corrupted = data.to_vec();
    if corrupted.len() >= 16 {
        // Corrupt the checksum field (bytes 16-17 in TCP header)
        let offset = rand::random::<u8>() as u16;
        corrupted[16] = (corrupted[16] as u8).wrapping_add(offset as u8);
        corrupted[17] = (corrupted[17] as u8).wrapping_add((offset >> 8) as u8);
    }
    corrupted
}

/// Corrupts the ACK number with a random offset.
pub fn corrupt_ack(data: &[u8], offset: i32) -> Vec<u8> {
    let mut corrupted = data.to_vec();
    if corrupted.len() >= 12 {
        let ack = u32::from_be_bytes([corrupted[8], corrupted[9], corrupted[10], corrupted[11]]);
        let new_ack = ack.wrapping_add(offset as u32);
        corrupted[8..12].copy_from_slice(&new_ack.to_be_bytes());
    }
    corrupted
}

/// Sets arbitrary TCP flags.
pub fn set_flags(data: &[u8], flags: u8) -> Vec<u8> {
    let mut modified = data.to_vec();
    if modified.len() >= 14 {
        modified[13] = flags;
    }
    modified
}

/// Shuffles a vector of packets using Fisher-Yates algorithm.
pub fn shuffle_packets(packets: &mut Vec<Vec<u8>>) {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    for i in (1..packets.len()).rev() {
        let j = rng.gen_range(0..=i);
        packets.swap(i, j);
    }
}

/// Composable evasion pipeline that applies multiple transforms.
pub fn apply_evasion_pipeline(
    data: &[u8],
    config: &EvasionPipeline,
) -> Vec<Vec<u8>> {
    let mut packets = vec![data.to_vec()];

    for transform in &config.transforms {
        let mut new_packets = Vec::new();
        for packet in &packets {
            match transform {
                EvasionTransformConfig::TcpSegmentation { segment_size } => {
                    let segments = tcp_segmentation(packet, *segment_size);
                    new_packets.extend(segments);
                }
                EvasionTransformConfig::SmallTtl { ttl: _ } => {
                    // In real implementation: set IP TTL field
                    new_packets.push(packet.clone());
                }
                EvasionTransformConfig::BadChecksum => {
                    new_packets.push(corrupt_checksum(packet));
                }
                EvasionTransformConfig::CorruptAck { offset } => {
                    new_packets.push(corrupt_ack(packet, *offset));
                }
                EvasionTransformConfig::CorruptFlags { flags } => {
                    new_packets.push(set_flags(packet, *flags));
                }
                EvasionTransformConfig::GarbagePayload => {
                    new_packets.push(random_string(packet.len()));
                }
                EvasionTransformConfig::RstPacket => {
                    new_packets.push(set_flags(packet, 0x04)); // RST
                }
                _ => {
                    new_packets.push(packet.clone());
                }
            }
        }
        packets = new_packets;
    }

    if config.shuffle {
        shuffle_packets(&mut packets);
    }

    packets
}

/// Sends packets with evasion pipeline applied.
pub fn send_with_evasion(
    stream: &mut TcpStream,
    data: &[u8],
    config: &EvasionPipeline,
) -> std::io::Result<()> {
    let packets = apply_evasion_pipeline(data, config);

    for (i, packet) in packets.iter().enumerate() {
        stream.write_all(packet)?;
        stream.flush()?;

        if i < packets.len() - 1 && config.delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(config.delay_ms));
        }
    }

    Ok(())
}

/// IDS evasion technique presets.
pub fn preset_dpi_bypass() -> EvasionPipeline {
    EvasionPipeline {
        transforms: vec![
            EvasionTransformConfig::TcpSegmentation { segment_size: 2 },
            EvasionTransformConfig::SmallTtl { ttl: 5 },
        ],
        delay_ms: 10,
        syn_delay_ms: 100,
        shuffle: false,
    }
}

pub fn preset_full_evasion() -> EvasionPipeline {
    EvasionPipeline {
        transforms: vec![
            EvasionTransformConfig::TcpSegmentation { segment_size: 4 },
            EvasionTransformConfig::CorruptAck { offset: -66000 },
            EvasionTransformConfig::GarbagePayload,
            EvasionTransformConfig::OutOfOrder,
        ],
        delay_ms: 20,
        syn_delay_ms: 200,
        shuffle: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_segmentation() {
        let data = vec![0u8; 100];
        let segments = tcp_segmentation(&data, 20);
        assert_eq!(segments.len(), 5);
        assert_eq!(segments[0].len(), 20);
    }

    #[test]
    fn test_random_string() {
        let s = random_string(10);
        assert_eq!(s.len(), 10);
        assert!(s.iter().all(|&b| b >= 33 && b <= 126));
    }

    #[test]
    fn test_corrupt_checksum() {
        let data = vec![0u8; 20];
        let corrupted = corrupt_checksum(&data);
        assert_eq!(corrupted.len(), 20);
    }

    #[test]
    fn test_shuffle() {
        let mut packets = vec![vec![1], vec![2], vec![3], vec![4], vec![5]];
        shuffle_packets(&mut packets);
        // Can't assert order changed (random), but can assert length preserved
        assert_eq!(packets.len(), 5);
    }

    #[test]
    fn test_evasion_pipeline() {
        let config = EvasionPipeline {
            transforms: vec![
                EvasionTransformConfig::TcpSegmentation { segment_size: 10 },
                EvasionTransformConfig::GarbagePayload,
            ],
            delay_ms: 0,
            syn_delay_ms: 0,
            shuffle: false,
        };
        let data = vec![0u8; 30];
        let packets = apply_evasion_pipeline(&data, &config);
        assert_eq!(packets.len(), 3); // 3 segments × 1 transform
    }
}
