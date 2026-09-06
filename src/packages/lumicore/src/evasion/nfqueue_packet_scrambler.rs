//! NFQUEUE Packet Scrambler and Evasion Filter
//!
//! Provides TCP handshake alteration, TTL hop manipulation, mark-based bypass,
//! and shortcut routing cache for intercepted packets.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrambleAction {
    Accept,
    Drop,
    ScrambleTcpFlags { new_flags: u8 },
    AlterTtl { ttl: u8 },
    MarkPacket { mark: u32 },
}

#[derive(Debug, Clone)]
pub struct ShortcutRoute {
    pub dest_addr: SocketAddr,
    pub created_at: Instant,
    pub ttl: Duration,
    pub packet_count: u64,
}

pub struct NfqueuePacketScrambler {
    pub queue_num: u16,
    pub default_mark: u32,
    shortcut_routes: HashMap<SocketAddr, ShortcutRoute>,
    ttl_hop_limit: u8,
    total_scrambled_packets: u64,
}

impl NfqueuePacketScrambler {
    pub fn new(queue_num: u16, default_mark: u32) -> Self {
        Self {
            queue_num,
            default_mark,
            shortcut_routes: HashMap::new(),
            ttl_hop_limit: 64,
            total_scrambled_packets: 0,
        }
    }

    pub fn set_ttl_hop_limit(&mut self, ttl: u8) {
        self.ttl_hop_limit = ttl;
    }

    pub fn add_shortcut(&mut self, dest: SocketAddr, ttl: Duration) {
        self.shortcut_routes.insert(
            dest,
            ShortcutRoute {
                dest_addr: dest,
                created_at: Instant::now(),
                ttl,
                packet_count: 0,
            },
        );
    }

    pub fn has_active_shortcut(&mut self, dest: &SocketAddr) -> bool {
        if let Some(entry) = self.shortcut_routes.get_mut(dest) {
            if entry.created_at.elapsed() < entry.ttl {
                entry.packet_count += 1;
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn process_ip_packet(&mut self, dest: SocketAddr, raw_packet: &mut [u8]) -> ScrambleAction {
        // Fast shortcut bypass check
        if self.has_active_shortcut(&dest) {
            return ScrambleAction::MarkPacket { mark: self.default_mark };
        }

        self.total_scrambled_packets += 1;

        if raw_packet.len() < 20 {
            return ScrambleAction::Accept;
        }

        // IPv4 Header inspection
        let version = (raw_packet[0] >> 4) & 0x0F;
        if version == 4 {
            let protocol = raw_packet[9];

            // If TCP protocol
            if protocol == 6 && raw_packet.len() >= 40 {
                let ihl = ((raw_packet[0] & 0x0F) * 4) as usize;
                let tcp_flags_offset = ihl + 13;

                if tcp_flags_offset < raw_packet.len() {
                    let flags = raw_packet[tcp_flags_offset];

                    // Check for SYN+ACK (0x12)
                    if (flags & 0x12) == 0x12 {
                        // Scramble TTL to evade middlebox deep inspection
                        raw_packet[8] = self.ttl_hop_limit;
                        return ScrambleAction::AlterTtl { ttl: self.ttl_hop_limit };
                    }
                }
            }
        }

        ScrambleAction::Accept
    }

    pub fn total_scrambled(&self) -> u64 {
        self.total_scrambled_packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nfqueue_scrambler() {
        let mut scrambler = NfqueuePacketScrambler::new(2, 0xCAFE);
        let dest: SocketAddr = "1.2.3.4:443".parse().unwrap();

        // Synthetic IPv4 + TCP packet with SYN+ACK flags
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45; // IPv4, 20-byte header
        packet[8] = 128;  // Original TTL
        packet[9] = 6;    // TCP
        packet[20 + 13] = 0x12; // SYN+ACK

        let action = scrambler.process_ip_packet(dest, &mut packet);
        assert_eq!(action, ScrambleAction::AlterTtl { ttl: 64 });
        assert_eq!(packet[8], 64);

        // Add shortcut route
        scrambler.add_shortcut(dest, Duration::from_secs(60));
        let action2 = scrambler.process_ip_packet(dest, &mut packet);
        assert_eq!(action2, ScrambleAction::MarkPacket { mark: 0xCAFE });
    }
}
