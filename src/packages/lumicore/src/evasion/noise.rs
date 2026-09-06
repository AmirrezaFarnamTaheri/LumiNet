//! # QUIC Noise Injection
//!
//! Sends random UDP packets before QUIC handshake to confuse DPI.

use std::net::SocketAddr;
use std::time::Duration;

/// Noise packet type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NoiseType {
    Str,
    Base64,
    Hex,
    Rand,
}

/// Noise packet configuration.
#[derive(Debug, Clone)]
pub struct NoisePacket {
    pub packet_type: NoiseType,
    pub payload: String,
    pub sleep_ms: u64,
}

/// Default QUIC noise packets.
pub fn default_quic_noise() -> Vec<NoisePacket> {
    vec![
        NoisePacket {
            packet_type: NoiseType::Rand,
            payload: "100-300".to_string(),
            sleep_ms: 50,
        },
        NoisePacket {
            packet_type: NoiseType::Rand,
            payload: "50-150".to_string(),
            sleep_ms: 30,
        },
        NoisePacket {
            packet_type: NoiseType::Rand,
            payload: "200-500".to_string(),
            sleep_ms: 100,
        },
    ]
}

/// Sends noise packets to confuse DPI before QUIC handshake.
pub async fn send_noise_packets(
    target: SocketAddr,
    packets: &[NoisePacket],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(target).await?;

    for packet in packets {
        let data = match packet.packet_type {
            NoiseType::Str => packet.payload.as_bytes().to_vec(),
            NoiseType::Base64 => {
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &packet.payload)
                    .unwrap_or_default()
            }
            NoiseType::Hex => crate::netutil::hex_decode(&packet.payload).unwrap_or_default(),
            NoiseType::Rand => {
                let size: usize = packet
                    .payload
                    .split('-')
                    .next()
                    .unwrap_or("100")
                    .parse()
                    .unwrap_or(100);
                let mut buf = vec![0u8; size];
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut buf);
                buf
            }
        };
        socket.send(&data).await?;
        if packet.sleep_ms > 0 {
            tokio::time::sleep(Duration::from_millis(packet.sleep_ms)).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_noise() {
        let noise = default_quic_noise();
        assert_eq!(noise.len(), 3);
        assert_eq!(noise[0].packet_type, NoiseType::Rand);
    }
}
