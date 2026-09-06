//! # sFlow v5 Parser
//!
//! Parses sFlow v5 packets from network switches/routers for traffic monitoring.
//!
//! sFlow is a sampling technology that provides visibility into network traffic
//! by sampling packets at network devices and sending flow records to collectors.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// sFlow v5 packet header.
#[derive(Debug, Clone)]
pub struct SflowHeader {
    pub version: u32,
    pub ip_version: u32,
    pub agent_ip: IpAddr,
    pub sub_agent_id: u32,
    pub seq_number: u32,
    pub uptime: u32,
    pub num_samples: u32,
}

/// sFlow flow sample.
#[derive(Debug, Clone)]
pub struct FlowSample {
    pub seq_number: u32,
    pub source_id: u32,
    pub sampling_rate: u32,
    pub sample_pool: u32,
    pub drops: u32,
    pub records: Vec<FlowRecord>,
}

/// sFlow flow record.
#[derive(Debug, Clone)]
pub enum FlowRecord {
    RawPacket {
        protocol: u32,
        length: u32,
        stripped: u32,
        header_length: u32,
    },
    Ethernet {
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        ethertype: u16,
    },
    IPv4 {
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: u8,
        tos: u8,
        ttl: u8,
        src_port: u16,
        dst_port: u16,
        length: u16,
    },
    IPv6 {
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: u8,
        traffic_class: u8,
        flow_label: u32,
        src_port: u16,
        dst_port: u16,
        length: u16,
    },
}

/// Parsed sFlow datagram.
#[derive(Debug, Clone)]
pub struct SflowDatagram {
    pub header: SflowHeader,
    pub samples: Vec<FlowSample>,
}

/// Parses an sFlow v5 datagram from raw bytes.
pub fn parse_sflow(data: &[u8]) -> Option<SflowDatagram> {
    if data.len() < 28 {
        return None;
    }

    let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if version != 5 {
        return None;
    }

    let ip_version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

    let agent_ip = if ip_version == 1 {
        // IPv4
        IpAddr::from([data[8], data[9], data[10], data[11]])
    } else {
        // IPv6
        IpAddr::from([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
            data[17], data[18], data[19], data[20], data[21], data[22], data[23],
        ])
    };

    let sub_agent_id = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
    let seq_number = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);
    let uptime = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);
    let num_samples = u32::from_be_bytes([data[36], data[37], data[38], data[39]]);

    let header = SflowHeader {
        version,
        ip_version,
        agent_ip,
        sub_agent_id,
        seq_number,
        uptime,
        num_samples,
    };

    // Parse samples (simplified - full parsing would be much more complex)
    let samples = Vec::new();

    Some(SflowDatagram { header, samples })
}

/// Exponential Weighted Moving Average (EWMA) for traffic rate smoothing.
#[derive(Debug, Clone)]
pub struct Ewma {
    /// Current smoothed value.
    value: f64,
    /// Smoothing factor (tau).
    tau: Duration,
    /// Last update time.
    last_update: Instant,
}

impl Ewma {
    /// Creates a new EWMA with the given smoothing factor.
    pub fn new(tau: Duration) -> Self {
        Self {
            value: 0.0,
            tau,
            last_update: Instant::now(),
        }
    }

    /// Updates the EWMA with a new instantaneous value.
    pub fn update(&mut self, instantaneous: f64) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_update).as_secs_f64();
        let tau = self.tau.as_secs_f64();

        if tau > 0.0 && dt > 0.0 {
            let decay = (-dt / tau).exp();
            self.value = instantaneous + decay * (self.value - instantaneous);
        } else {
            self.value = instantaneous;
        }

        self.last_update = now;
    }

    /// Returns the current smoothed value.
    pub fn value(&self) -> f64 {
        self.value
    }

    /// Resets the EWMA to zero.
    pub fn reset(&mut self) {
        self.value = 0.0;
        self.last_update = Instant::now();
    }
}

/// Traffic rate tracker with bps and pps.
#[derive(Debug, Clone)]
pub struct TrafficRate {
    pub bps: Ewma,
    pub pps: Ewma,
    pub bytes_total: u64,
    pub packets_total: u64,
}

impl TrafficRate {
    pub fn new(tau: Duration) -> Self {
        Self {
            bps: Ewma::new(tau),
            pps: Ewma::new(tau),
            bytes_total: 0,
            packets_total: 0,
        }
    }

    /// Records a packet.
    pub fn record_packet(&mut self, bytes: u64) {
        self.bytes_total += bytes;
        self.packets_total += 1;
        self.bps.update(bytes as f64 * 8.0); // Convert to bits
        self.pps.update(1.0);
    }

    /// Returns current bps.
    pub fn bps(&self) -> f64 {
        self.bps.value()
    }

    /// Returns current pps.
    pub fn pps(&self) -> f64 {
        self.pps.value()
    }
}

/// Per-host traffic statistics.
#[derive(Debug, Clone)]
pub struct HostTraffic {
    pub ip: IpAddr,
    pub inbound: TrafficRate,
    pub outbound: TrafficRate,
}

impl HostTraffic {
    pub fn new(ip: IpAddr, tau: Duration) -> Self {
        Self {
            ip,
            inbound: TrafficRate::new(tau),
            outbound: TrafficRate::new(tau),
        }
    }
}

/// Traffic monitor that tracks per-host rates.
pub struct TrafficMonitor {
    hosts: HashMap<IpAddr, HostTraffic>,
    tau: Duration,
}

impl TrafficMonitor {
    pub fn new(tau: Duration) -> Self {
        Self {
            hosts: HashMap::new(),
            tau,
        }
    }

    /// Records a flow sample.
    pub fn record_flow(&mut self, src: IpAddr, dst: IpAddr, bytes: u64) {
        // Update source (outbound)
        let src_entry = self
            .hosts
            .entry(src)
            .or_insert_with(|| HostTraffic::new(src, self.tau));
        src_entry.outbound.record_packet(bytes);

        // Update destination (inbound)
        let dst_entry = self
            .hosts
            .entry(dst)
            .or_insert_with(|| HostTraffic::new(dst, self.tau));
        dst_entry.inbound.record_packet(bytes);
    }

    /// Returns traffic stats for a specific host.
    pub fn get_host(&self, ip: &IpAddr) -> Option<&HostTraffic> {
        self.hosts.get(ip)
    }

    /// Returns all hosts sorted by total traffic.
    pub fn top_hosts(&self, limit: usize) -> Vec<&HostTraffic> {
        let mut hosts: Vec<_> = self.hosts.values().collect();
        hosts.sort_by(|a, b| {
            let a_total = a.inbound.bps() + a.outbound.bps();
            let b_total = b.inbound.bps() + b.outbound.bps();
            b_total
                .partial_cmp(&a_total)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        hosts.into_iter().take(limit).collect()
    }

    /// Returns total number of tracked hosts.
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }
}

/// DDoS mitigation trigger.
#[derive(Debug, Clone)]
pub struct DdosTrigger {
    pub name: String,
    pub bps_threshold: f64,
    pub pps_threshold: f64,
    pub burst_duration: Duration,
    pub active: bool,
}

impl DdosTrigger {
    pub fn new(
        name: &str,
        bps_threshold: f64,
        pps_threshold: f64,
        burst_duration: Duration,
    ) -> Self {
        Self {
            name: name.to_string(),
            bps_threshold,
            pps_threshold,
            burst_duration,
            active: false,
        }
    }

    /// Checks if the trigger should fire.
    pub fn should_fire(&self, rate: &TrafficRate) -> bool {
        rate.bps() > self.bps_threshold || rate.pps() > self.pps_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_ewma() {
        let mut ewma = Ewma::new(Duration::from_secs(10));
        ewma.update(100.0);
        assert!(ewma.value() > 0.0);
        assert!(ewma.value() <= 100.0);
    }

    #[test]
    fn test_traffic_rate() {
        let mut rate = TrafficRate::new(Duration::from_secs(5));
        rate.record_packet(1500);
        rate.record_packet(1500);
        assert_eq!(rate.packets_total, 2);
        assert_eq!(rate.bytes_total, 3000);
    }

    #[test]
    fn test_traffic_monitor() {
        let mut monitor = TrafficMonitor::new(Duration::from_secs(5));
        let src: IpAddr = "192.168.1.1".parse().unwrap();
        let dst: IpAddr = "10.0.0.1".parse().unwrap();
        monitor.record_flow(src, dst, 1500);
        assert_eq!(monitor.host_count(), 2);
    }

    #[test]
    fn test_ddos_trigger() {
        let trigger = DdosTrigger::new("test", 1000000.0, 1000.0, Duration::from_secs(60));
        let mut rate = TrafficRate::new(Duration::from_secs(5));
        rate.record_packet(1500);
        // Should not trigger for low traffic
        assert!(!trigger.should_fire(&rate));
    }
}
