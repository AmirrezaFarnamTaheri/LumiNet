//! # Reverse Tunnel Relay
//!
//! High-performance reverse tunneling relay engine establishing persistent outbound connections
//! from NATed origin edge nodes to public proxy entrypoints, enabling bi-directional multiplexed streams.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelStatus {
    Connecting,
    Active,
    Idle,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseChannel {
    pub channel_id: u32,
    pub origin_node_id: String,
    pub status: ChannelStatus,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_heartbeat: u64,
}

pub struct ReverseTunnelRelay {
    channels: HashMap<u32, ReverseChannel>,
    next_channel_id: u32,
    heartbeat_timeout_secs: u64,
}

impl ReverseTunnelRelay {
    pub fn new(heartbeat_timeout_secs: u64) -> Self {
        Self {
            channels: HashMap::new(),
            next_channel_id: 1,
            heartbeat_timeout_secs: heartbeat_timeout_secs.max(10),
        }
    }

    pub fn open_channel(&mut self, origin_node_id: &str, timestamp: u64) -> u32 {
        let channel_id = self.next_channel_id;
        self.next_channel_id += 1;

        let channel = ReverseChannel {
            channel_id,
            origin_node_id: origin_node_id.to_string(),
            status: ChannelStatus::Active,
            rx_bytes: 0,
            tx_bytes: 0,
            last_heartbeat: timestamp,
        };

        self.channels.insert(channel_id, channel);
        channel_id
    }

    pub fn record_heartbeat(&mut self, channel_id: u32, timestamp: u64) -> bool {
        if let Some(ch) = self.channels.get_mut(&channel_id) {
            ch.last_heartbeat = timestamp;
            if ch.status == ChannelStatus::Idle {
                ch.status = ChannelStatus::Active;
            }
            true
        } else {
            false
        }
    }

    pub fn forward_traffic(&mut self, channel_id: u32, bytes_in: u64, bytes_out: u64) -> Result<(), String> {
        let ch = self.channels.get_mut(&channel_id).ok_or("Channel not found")?;
        if ch.status != ChannelStatus::Active {
            return Err("Channel is not active".to_string());
        }

        ch.rx_bytes += bytes_in;
        ch.tx_bytes += bytes_out;
        Ok(())
    }

    pub fn reap_dead_channels(&mut self, current_time: u64) -> usize {
        let mut reaped = 0;
        for ch in self.channels.values_mut() {
            if ch.status != ChannelStatus::Closed
                && current_time >= ch.last_heartbeat + self.heartbeat_timeout_secs
            {
                ch.status = ChannelStatus::Closed;
                reaped += 1;
            }
        }
        reaped
    }

    pub fn get_channel(&self, channel_id: u32) -> Option<&ReverseChannel> {
        self.channels.get(&channel_id)
    }

    pub fn total_active_channels(&self) -> usize {
        self.channels
            .values()
            .filter(|c| c.status == ChannelStatus::Active)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_tunnel_relay_lifecycle() {
        let mut relay = ReverseTunnelRelay::new(30);

        let ch1 = relay.open_channel("edge-node-01", 1000);
        let ch2 = relay.open_channel("edge-node-02", 1000);
        assert_eq!(relay.total_active_channels(), 2);

        relay.forward_traffic(ch1, 1024, 2048).unwrap();
        let c1 = relay.get_channel(ch1).unwrap();
        assert_eq!(c1.rx_bytes, 1024);
        assert_eq!(c1.tx_bytes, 2048);

        // Keep ch1 alive at t=1025
        relay.record_heartbeat(ch1, 1025);

        // At t=1035 (35s since 1000), ch2 exceeds 30s timeout and should be reaped
        let reaped = relay.reap_dead_channels(1035);
        assert_eq!(reaped, 1);
        assert_eq!(relay.get_channel(ch2).unwrap().status, ChannelStatus::Closed);
        assert_eq!(relay.get_channel(ch1).unwrap().status, ChannelStatus::Active);
    }
}
