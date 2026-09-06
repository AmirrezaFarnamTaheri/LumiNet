//! Protocol Escalation Ladder and Hostile Network Anti-DPI Fingerprinter.
//!
//! Provides progressive failover and fingerprint-guided connection staging:
//! 1. Direct 2-pass strategy: Executes standard configured parameters for a bounded initial
//!    window (e.g. 35s), escalating seamlessly to an anti-DPI hardened profile without changing
//!    the user-selected protocol.
//! 2. Smart Auto escalation ladder: Probes high-resilience MASQUE -> MASQUE Hardened ->
//!    GOOL (TCP/TLS tunnel) -> WireGuard (IPv6 preferred).
//! 3. Hostile network fingerprinting: Automatically detects filtered/censored networks where direct
//!    TCP egress on port 80 is suppressed; leads with the hardened anti-DPI profile immediately to avoid
//!    wasting the first-pass timeout window.
//! 4. Anti-DPI hardening transform: Enables noise camouflage, HTTP/2 stream multiplexing, TCP/TLS
//!    record fragmentation, and Encrypted Client Hello (ECH).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    Masque,
    Gool,
    Wireguard,
    Smart,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiDpiSettings {
    pub noise_camouflage: bool,
    pub http2_transport: bool,
    pub packet_fragmentation: bool,
    pub encrypted_client_hello: bool,
}

impl Default for AntiDpiSettings {
    fn default() -> Self {
        Self {
            noise_camouflage: false,
            http2_transport: false,
            packet_fragmentation: false,
            encrypted_client_hello: false,
        }
    }
}

impl AntiDpiSettings {
    pub fn hardened() -> Self {
        Self {
            noise_camouflage: true,
            http2_transport: true,
            packet_fragmentation: true,
            encrypted_client_hello: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationCandidate {
    pub protocol: ProtocolKind,
    pub timeout_ms: u64,
    pub anti_dpi: AntiDpiSettings,
    pub label: String,
}

pub const FIRST_PASS_MAX_MS: u64 = 35_000;
pub const HARDENED_MAX_MS: u64 = 120_000;

pub const SMART_AUTO_PREFERENCE: [ProtocolKind; 3] = [
    ProtocolKind::Masque,
    ProtocolKind::Gool,
    ProtocolKind::Wireguard,
];

/// Returns the successor protocol in the Smart Auto preference sequence.
pub fn next_candidate_protocol(failed: ProtocolKind) -> Option<ProtocolKind> {
    let idx = SMART_AUTO_PREFERENCE.iter().position(|p| *p == failed)?;
    SMART_AUTO_PREFERENCE.get(idx + 1).copied()
}

/// Constructs the two-pass direct plan for an explicitly chosen protocol.
pub fn build_direct_plan(
    protocol: ProtocolKind,
    full_timeout_ms: u64,
    hostile_network: bool,
) -> Vec<EscalationCandidate> {
    let name = format!("{protocol:?}").to_uppercase();

    let as_configured = EscalationCandidate {
        protocol,
        timeout_ms: full_timeout_ms.min(FIRST_PASS_MAX_MS),
        anti_dpi: AntiDpiSettings::default(),
        label: format!("{name} · as configured"),
    };

    let anti_dpi = EscalationCandidate {
        protocol,
        timeout_ms: full_timeout_ms,
        anti_dpi: AntiDpiSettings::hardened(),
        label: format!("{name} · hardened anti-DPI"),
    };

    if hostile_network {
        // When the network is identified as hostile/filtered, lead with the hardened candidate
        vec![anti_dpi, as_configured]
    } else {
        vec![as_configured, anti_dpi]
    }
}

/// Constructs the multi-stage Smart Auto escalation ladder.
pub fn build_auto_plan(
    ipv6_only: bool,
    full_timeout_ms: u64,
    hostile_network: bool,
) -> Vec<EscalationCandidate> {
    let mut plan = Vec::new();

    let order: Vec<ProtocolKind> = if ipv6_only {
        vec![ProtocolKind::Wireguard, ProtocolKind::Masque, ProtocolKind::Gool]
    } else {
        SMART_AUTO_PREFERENCE.to_vec()
    };

    for (i, proto) in order.iter().enumerate() {
        let name = format!("{proto:?}").to_uppercase();
        if i == 0 {
            let as_configured = EscalationCandidate {
                protocol: *proto,
                timeout_ms: full_timeout_ms.min(FIRST_PASS_MAX_MS),
                anti_dpi: AntiDpiSettings::default(),
                label: format!("{name} · as configured"),
            };
            let anti_dpi = EscalationCandidate {
                protocol: *proto,
                timeout_ms: full_timeout_ms.min(HARDENED_MAX_MS),
                anti_dpi: AntiDpiSettings::hardened(),
                label: format!("{name} · hardened anti-DPI"),
            };

            if hostile_network {
                plan.push(anti_dpi);
                plan.push(as_configured);
            } else {
                plan.push(as_configured);
                plan.push(anti_dpi);
            }
        } else {
            plan.push(EscalationCandidate {
                protocol: *proto,
                timeout_ms: if i + 1 == order.len() {
                    full_timeout_ms
                } else {
                    full_timeout_ms.min(HARDENED_MAX_MS)
                },
                anti_dpi: AntiDpiSettings::hardened(),
                label: format!("{name} · hardened anti-DPI"),
            });
        }
    }

    plan
}

/// Top-level plan generator dispatching between direct and Smart Auto ladder.
pub fn build_escalation_plan(
    protocol: ProtocolKind,
    ipv6_only: bool,
    full_timeout_ms: u64,
    hostile_network: bool,
) -> Vec<EscalationCandidate> {
    if protocol == ProtocolKind::Smart {
        build_auto_plan(ipv6_only, full_timeout_ms, hostile_network)
    } else {
        build_direct_plan(protocol, full_timeout_ms, hostile_network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smart_auto_never_emits_smart_as_candidate_protocol() {
        let plan = build_escalation_plan(ProtocolKind::Smart, false, 60_000, false);
        assert!(!plan.is_empty());
        for c in plan {
            assert_ne!(c.protocol, ProtocolKind::Smart);
        }
    }

    #[test]
    fn direct_plan_preserves_user_protocol() {
        let plan = build_escalation_plan(ProtocolKind::Gool, false, 50_000, false);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0].protocol, ProtocolKind::Gool);
        assert_eq!(plan[1].protocol, ProtocolKind::Gool);
        assert!(!plan[0].anti_dpi.noise_camouflage);
        assert!(plan[1].anti_dpi.noise_camouflage);
    }

    #[test]
    fn hostile_network_inverts_priority_to_hardened() {
        let plan = build_escalation_plan(ProtocolKind::Masque, false, 50_000, true);
        assert_eq!(plan.len(), 2);
        // Hardened candidate leads
        assert!(plan[0].anti_dpi.noise_camouflage);
        assert_eq!(plan[0].label, "MASQUE · hardened anti-DPI");
        // Plain candidate is fallback
        assert!(!plan[1].anti_dpi.noise_camouflage);
        assert_eq!(plan[1].label, "MASQUE · as configured");
    }

    #[test]
    fn ipv6_prioritizes_wireguard_in_smart_auto() {
        let plan = build_escalation_plan(ProtocolKind::Smart, true, 60_000, false);
        assert_eq!(plan[0].protocol, ProtocolKind::Wireguard);
    }

    #[test]
    fn fallback_sequence() {
        assert_eq!(next_candidate_protocol(ProtocolKind::Masque), Some(ProtocolKind::Gool));
        assert_eq!(next_candidate_protocol(ProtocolKind::Gool), Some(ProtocolKind::Wireguard));
        assert_eq!(next_candidate_protocol(ProtocolKind::Wireguard), None);
    }
}
