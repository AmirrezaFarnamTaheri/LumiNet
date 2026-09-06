//! # eBPF-Inspired DNS Pollution Packet Dropper
//!
//! Replicates kernel-level eBPF packet filter logic to identify and drop
//! poisoned DNS responses injected by middleboxes before reaching the application.
//! Ported directly from ihciah/clean-dns-bpf.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsDropDecision {
    Pass,
    DropPoisoned(&'static str),
}

#[derive(Debug, Clone, Default)]
pub struct EbpfDnsDropFilter {
    pub dropped_count: usize,
    pub passed_count: usize,
}

impl EbpfDnsDropFilter {
    pub fn new() -> Self {
        Self {
            dropped_count: 0,
            passed_count: 0,
        }
    }

    /// Inspects raw IPv4/UDP and DNS payload attributes:
    /// 1. `ip_id == 0`: Characteristic of middlebox forged IP packets
    /// 2. `frag_off == 0x0040`: DF flag anomaly in injected packets
    /// 3. Answer RR == 1 and Authority RR == 0
    /// 4. DNS Flag Authoritative Answer (AA, bit 2 of byte 2) set on recursive resolvers
    pub fn inspect_packet(
        &mut self,
        ip_id: u16,
        frag_off: u16,
        src_port: u16,
        dns_payload: &[u8],
    ) -> DnsDropDecision {
        if src_port != 53 {
            self.passed_count += 1;
            return DnsDropDecision::Pass;
        }

        // Anomaly 1: IP identification field is exactly 0
        if ip_id == 0 {
            self.dropped_count += 1;
            return DnsDropDecision::DropPoisoned("Forged packet with IP ID = 0");
        }

        // Anomaly 2: Fragment offset / flags matches DF bit 0x0040
        if frag_off == 0x0040 {
            self.dropped_count += 1;
            return DnsDropDecision::DropPoisoned("Forged packet with frag_off = 0x0040");
        }

        // DNS header must be at least 12 bytes
        if dns_payload.len() < 12 {
            self.passed_count += 1;
            return DnsDropDecision::Pass;
        }

        let answer_rrs = u16::from_be_bytes([dns_payload[6], dns_payload[7]]);
        let auth_rrs = u16::from_be_bytes([dns_payload[8], dns_payload[9]]);

        // Anomaly 3 & 4: Injected response has exactly 1 answer RR, 0 authority RRs,
        // and has the Authoritative Answer (AA) flag bit set on a recursive resolver response.
        let flags_byte1 = dns_payload[2];
        let aa_bit_set = (flags_byte1 & 0b0000_0100) != 0;

        if answer_rrs == 1 && auth_rrs == 0 && aa_bit_set {
            self.dropped_count += 1;
            return DnsDropDecision::DropPoisoned("Forged packet with AA flag on single-answer recursive query");
        }

        self.passed_count += 1;
        DnsDropDecision::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drop_ip_id_zero() {
        let mut filter = EbpfDnsDropFilter::new();
        let payload = vec![0u8; 12];
        let dec = filter.inspect_packet(0, 0, 53, &payload);
        assert!(matches!(dec, DnsDropDecision::DropPoisoned(_)));
        assert_eq!(filter.dropped_count, 1);
    }

    #[test]
    fn test_drop_frag_off() {
        let mut filter = EbpfDnsDropFilter::new();
        let payload = vec![0u8; 12];
        let dec = filter.inspect_packet(1234, 0x0040, 53, &payload);
        assert!(matches!(dec, DnsDropDecision::DropPoisoned(_)));
    }

    #[test]
    fn test_drop_authoritative_anomaly() {
        let mut filter = EbpfDnsDropFilter::new();
        let mut payload = vec![0u8; 12];
        payload[2] = 0b0000_0100; // AA bit set
        payload[6] = 0x00;
        payload[7] = 0x01; // Answer RRs = 1
        payload[8] = 0x00;
        payload[9] = 0x00; // Authority RRs = 0

        let dec = filter.inspect_packet(5555, 0, 53, &payload);
        assert!(matches!(dec, DnsDropDecision::DropPoisoned(_)));
    }

    #[test]
    fn test_pass_legitimate_packet() {
        let mut filter = EbpfDnsDropFilter::new();
        let mut payload = vec![0u8; 12];
        payload[2] = 0b0000_0000; // AA bit not set
        payload[6] = 0x00;
        payload[7] = 0x02; // 2 answers
        let dec = filter.inspect_packet(5555, 0, 53, &payload);
        assert_eq!(dec, DnsDropDecision::Pass);
        assert_eq!(filter.passed_count, 1);
    }
}
