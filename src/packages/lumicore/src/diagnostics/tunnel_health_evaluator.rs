//! Tunnel Health Evaluator, FEC Profile Tiers & Dynamic Diagnostics
//!
//! Originates from VpnDad-main (Shared/VPNProfile.swift & VpnDadApp/HealthDiagnostics.swift)
//! and absorbed into the LumiNet diagnostics and resilience plane.

use serde::{Deserialize, Serialize};

/// High-level operational verdict on tunnel health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TunnelHealthVerdict {
    /// VPN/Tunnel interface is not connected.
    Disconnected,
    /// VPN is currently negotiating or establishing handshake.
    Starting,
    /// Traffic is actively flowing with healthy RTT and acceptable loss.
    Working,
    /// Uplink/downlink degraded due to elevated packet loss or high latency.
    Degraded,
    /// Connection stalled or stalled without packets, requiring tunnel renegotiation.
    ReconnectNeeded,
    /// Total transmission failure or fatal error.
    Broken,
    /// Tunnel connected but zero packets received yet.
    WaitingForTraffic,
}

impl TunnelHealthVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::Starting => "starting",
            Self::Working => "working",
            Self::Degraded => "degraded",
            Self::ReconnectNeeded => "reconnect_needed",
            Self::Broken => "broken",
            Self::WaitingForTraffic => "waiting_for_traffic",
        }
    }
}

/// Real-time metrics collected from the tunnel network extension or daemon.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelMetrics {
    pub uptime_seconds: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub rtt_ms: Option<u32>,
    pub packet_loss_percent: f32,
    pub last_packet_age_ms: u64,
}

impl Default for TunnelMetrics {
    fn default() -> Self {
        Self {
            uptime_seconds: 0,
            bytes_in: 0,
            bytes_out: 0,
            packets_in: 0,
            packets_out: 0,
            rtt_ms: None,
            packet_loss_percent: 0.0,
            last_packet_age_ms: 0,
        }
    }
}

/// Comprehensive health assessment report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TunnelHealthReport {
    pub verdict: TunnelHealthVerdict,
    pub summary: String,
    pub evidence: Vec<String>,
}

/// Forward Error Correction (FEC) Profile settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FecProfile {
    pub level: String,
    pub enabled: bool,
    pub group_size: usize,
    pub overhead_percent: u32,
    pub symbol_size: usize,
    pub flush_timeout_ms: u32,
    pub direction: String,
}

/// Standard predefined FEC profile tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FecProfileTier {
    None,
    Conservative,
    Balanced,
    Aggressive,
}

impl FecProfileTier {
    pub fn to_profile(&self) -> FecProfile {
        match self {
            Self::None => FecProfile {
                level: "none".to_string(),
                enabled: false,
                group_size: 8,
                overhead_percent: 15,
                symbol_size: 0,
                flush_timeout_ms: 25,
                direction: "download".to_string(),
            },
            Self::Conservative => FecProfile {
                level: "conservative".to_string(),
                enabled: true,
                group_size: 8,
                overhead_percent: 15,
                symbol_size: 0,
                flush_timeout_ms: 25,
                direction: "download".to_string(),
            },
            Self::Balanced => FecProfile {
                level: "balanced".to_string(),
                enabled: true,
                group_size: 12,
                overhead_percent: 25,
                symbol_size: 0,
                flush_timeout_ms: 20,
                direction: "download".to_string(),
            },
            Self::Aggressive => FecProfile {
                level: "aggressive".to_string(),
                enabled: true,
                group_size: 16,
                overhead_percent: 40,
                symbol_size: 0,
                flush_timeout_ms: 15,
                direction: "download".to_string(),
            },
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        let normalized = s.trim().to_lowercase().replace('_', "-");
        match normalized.as_str() {
            "off" | "disabled" | "disable" | "none" => Some(Self::None),
            "safe" | "low" | "conservative" => Some(Self::Conservative),
            "medium" | "balanced" => Some(Self::Balanced),
            "high" | "aggressive" => Some(Self::Aggressive),
            _ => None,
        }
    }
}

/// Cryptographic encryption tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EncryptionLevel {
    Standard, // AES-128-GCM (method 3)
    Strong,   // AES-192-GCM (method 4)
    Maximum,  // AES-256-GCM (method 5)
}

impl EncryptionLevel {
    pub fn method_id(&self) -> u32 {
        match self {
            Self::Standard => 3,
            Self::Strong => 4,
            Self::Maximum => 5,
        }
    }

    pub fn cipher_name(&self) -> &'static str {
        match self {
            Self::Standard => "aes-128-gcm",
            Self::Strong => "aes-192-gcm",
            Self::Maximum => "aes-256-gcm",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        let normalized = s.trim().to_lowercase().replace(['_', ' '], "-");
        match normalized.as_str() {
            "standard" | "aes-128" | "aes-128-gcm" | "aes128" | "128" => Some(Self::Standard),
            "strong" | "aes-192" | "aes-192-gcm" | "aes192" | "192" => Some(Self::Strong),
            "maximum" | "max" | "strongest" | "aes-256" | "aes-256-gcm" | "aes256" | "256" => {
                Some(Self::Maximum)
            }
            _ => None,
        }
    }
}

/// Evaluates tunnel health status from metrics and connection state.
pub fn evaluate_tunnel_health(
    metrics: Option<&TunnelMetrics>,
    connection_state: &str,
    probe_loss_rate: f32,
    idle_timeout_ms: u64,
) -> TunnelHealthReport {
    let mut evidence = Vec::new();

    let state = connection_state.trim().to_lowercase();
    if state == "disconnected" || state == "invalid" {
        return TunnelHealthReport {
            verdict: TunnelHealthVerdict::Disconnected,
            summary: "Tunnel interface is disconnected.".to_string(),
            evidence: vec![format!("Connection state is {}", connection_state)],
        };
    }

    if state == "connecting" || state == "reasserting" || state == "starting" {
        return TunnelHealthReport {
            verdict: TunnelHealthVerdict::Starting,
            summary: "Tunnel is negotiating handshake.".to_string(),
            evidence: vec![format!("Current state: {}", connection_state)],
        };
    }

    let m = match metrics {
        Some(m) => m,
        None => {
            return TunnelHealthReport {
                verdict: TunnelHealthVerdict::WaitingForTraffic,
                summary: "Connected, awaiting first tunnel telemetry packet.".to_string(),
                evidence: vec!["Zero metrics recorded.".to_string()],
            };
        }
    };

    if m.packets_in == 0 && m.packets_out > 0 {
        if m.last_packet_age_ms > idle_timeout_ms {
            evidence.push(format!(
                "Outbound {} pkts, but 0 inbound pkts received (idle {}ms > {}ms threshold).",
                m.packets_out, m.last_packet_age_ms, idle_timeout_ms
            ));
            return TunnelHealthReport {
                verdict: TunnelHealthVerdict::Broken,
                summary: "Uplink active but zero downlink packets returned from tunnel.".to_string(),
                evidence,
            };
        }
        return TunnelHealthReport {
            verdict: TunnelHealthVerdict::WaitingForTraffic,
            summary: "Waiting for downlink packets from tunnel endpoint.".to_string(),
            evidence: vec![format!("Sent {} packets, waiting for reply.", m.packets_out)],
        };
    }

    if m.last_packet_age_ms > idle_timeout_ms * 2 {
        evidence.push(format!(
            "Last packet observed {}ms ago (stale timeout {}ms).",
            m.last_packet_age_ms,
            idle_timeout_ms * 2
        ));
        return TunnelHealthReport {
            verdict: TunnelHealthVerdict::ReconnectNeeded,
            summary: "Tunnel connection has stalled with no packets received.".to_string(),
            evidence,
        };
    }

    let total_loss = m.packet_loss_percent.max(probe_loss_rate * 100.0);
    if total_loss > 35.0 || m.rtt_ms.map_or(false, |r| r > 1200) {
        evidence.push(format!("Packet loss: {:.1}%", total_loss));
        if let Some(rtt) = m.rtt_ms {
            evidence.push(format!("Round-trip latency: {}ms", rtt));
        }
        return TunnelHealthReport {
            verdict: TunnelHealthVerdict::Degraded,
            summary: "Tunnel operational but experiencing severe packet loss or latency.".to_string(),
            evidence,
        };
    }

    evidence.push(format!(
        "In: {}B ({} pkts), Out: {}B ({} pkts)",
        m.bytes_in, m.packets_in, m.bytes_out, m.packets_out
    ));
    if let Some(rtt) = m.rtt_ms {
        evidence.push(format!("RTT: {}ms", rtt));
    }
    evidence.push(format!("Loss: {:.1}%", total_loss));

    TunnelHealthReport {
        verdict: TunnelHealthVerdict::Working,
        summary: "Tunnel is healthy and actively routing traffic.".to_string(),
        evidence,
    }
}
