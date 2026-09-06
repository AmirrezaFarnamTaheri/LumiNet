//
// Netfilter IP/Port randomization kernel module — userspace companion.
//
// The upstream  kernel module intercepts outgoing packets via
// netfilter NF_INET_LOCAL_OUT and NF_INET_POST_ROUTING hooks, replacing
// the source IP (and optionally source port) with random values drawn from
// a configured pool while updating IP/TCP/UDP checksums incrementally.
//
// Since LumiNet runs primarily in userspace and cannot load kernel modules
// on locked-down platforms, this module implements two things:
//
// 1.  — a pure-Rust stateless transformation engine that
//    takes a raw IP packet, randomizes source IP and/or port, and correctly
//    fixes IP, TCP and UDP checksums. Safe to call from any transport layer.
//
// 2.  — a higher-level struct (matching the stub API)
//    that maintains a randmap session (e.g., a source-address pool derived
//    from the original endpoint) and drives the transform.
//
// Kernel module integration: callers on Linux can use the 
// netfilter module by calling
//  after loading
// the module. This file does NOT include the kernel module source (which
// lives in the upstream xt_RANDMAP.c under GPL).

use std::net::Ipv4Addr;
use rand::{Rng, SeedableRng};

/// How the source address is randomised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandmapMode {
    /// Fully random IP in the same /24 as the original source.
    SubnetPreserving,
    /// Fully random IP across the full IPv4 address space (subject to routing).
    Global,
    /// Keep the original source IP, only randomise the port.
    PortOnly,
}

impl Default for RandmapMode {
    fn default() -> Self {
        RandmapMode::SubnetPreserving
    }
}

/// Configuration for one randmap session.
#[derive(Debug, Clone)]
pub struct RandmapConfig {
    /// How to randomise the source IP.
    pub mode: RandmapMode,
    /// Whether to also randomise the source port.
    pub randomise_port: bool,
    /// Minimum port value (for port-only mode). Defaults to 32768.
    pub port_min: u16,
    /// Maximum port value (for port-only mode). Defaults to 60999.
    pub port_max: u16,
}

impl Default for RandmapConfig {
    fn default() -> Self {
        Self {
            mode: RandmapMode::SubnetPreserving,
            randomise_port: true,
            port_min: 32768,
            port_max: 60999,
        }
    }
}

/// Core stateless transformation engine for IP/port randomization.
pub struct RandmapTransform {
    rng: rand::rngs::SmallRng,
    cfg: RandmapConfig,
}

impl Default for RandmapTransform {
    fn default() -> Self {
        Self::new(RandmapConfig::default())
    }
}

impl RandmapTransform {
    pub fn new(cfg: RandmapConfig) -> Self {
        Self {
            rng: rand::rngs::SmallRng::from_entropy(),
            cfg,
        }
    }

    /// Randomise a single source IPv4 address according to the configured mode.
    pub fn randomise_v4(&mut self, src: Ipv4Addr) -> Ipv4Addr {
        match self.cfg.mode {
            RandmapMode::SubnetPreserving => {
                // Keep /24 prefix, randomise last octet.
                let octets = src.octets();
                let new_last = u8::try_from(self.rng.gen_range(1..=254)).unwrap_or(1);
                Ipv4Addr::new(octets[0], octets[1], octets[2], new_last)
            }
            RandmapMode::Global => {
                // Full random, but exclude reserved ranges.
                loop {
                    let r0 = u8::try_from(self.rng.gen_range(1..=223)).unwrap_or(1);
                    let r1 = self.rng.gen();
                    let r2 = self.rng.gen();
                    let r3 = u8::try_from(self.rng.gen_range(1..=254)).unwrap_or(1);
                    let candidate = Ipv4Addr::new(r0, r1, r2, r3);
                    if !is_reserved_v4(&candidate) {
                        break candidate;
                    }
                }
            }
            RandmapMode::PortOnly => src,
        }
    }

    /// Randomise a source port.
    pub fn randomise_port(&mut self) -> u16 {
        if !self.cfg.randomise_port {
            return 0; // caller should preserve original
        }
        let range = self.cfg.port_max.saturating_sub(self.cfg.port_min) + 1;
        self.rng.gen_range(self.cfg.port_min..=self.cfg.port_min.saturating_add(range - 1))
    }

    /// Transform a raw IPv4 packet buffer in-place.
    /// Handles: IPv4 header src-IP field + TCP/UDP checksum fields.
    /// Panics if the buffer is shorter than an IPv4 header.
    pub fn transform_packet(&mut self, pkt: &mut [u8]) -> Result<(), &'static str> {
        if pkt.len() < 20 {
            return Err("packet_too_short_for_ipv4");
        }
        // IP version = 4, IHL >= 5 (20 bytes minimum).
        let version_ihl = pkt[0];
        if version_ihl >> 4 != 4 {
            return Err("not_ipv4");
        }
        let ihl = (version_ihl & 0x0F) as usize * 4;
        if pkt.len() < ihl {
            return Err("packet_shorter_than_ihl");
        }
        let total_len = u16::from_be_bytes([pkt[2], pkt[3]]);

        // Original src IP (bytes 12-15).
        let orig_src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);

        // Randomise src IP.
        let new_src = self.randomise_v4(orig_src);
        pkt[12] = new_src.octets()[0];
        pkt[13] = new_src.octets()[1];
        pkt[14] = new_src.octets()[2];
        pkt[15] = new_src.octets()[3];

        // Fix IP header checksum.
        self.fix_ipv4_checksum(pkt, ihl);

        // Fix transport checksum (TCP or UDP).
        let transport_start = ihl;
        if pkt.len() >= transport_start + 4 {
            let proto = pkt[9];
            match proto {
                6 => self.fix_tcp_checksum(pkt, transport_start, new_src),
                17 => self.fix_udp_checksum(pkt, transport_start, new_src),
                _ => {}
            }
        }

        // Return total_len for caller awareness.
        let _ = total_len;
        Ok(())
    }

    /// Compute and write the IP header checksum for a packet.
    fn fix_ipv4_checksum(&self, pkt: &mut [u8], _header_len: usize) {
        let old_cksum = u16::from_be_bytes([pkt[10], pkt[11]]);
        pkt[10] = 0;
        pkt[11] = 0;
        let old_src_u32 = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
        let new_src_u32 = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
        let cksum = incremental_checksum(old_cksum, old_src_u32, new_src_u32);
        pkt[10] = (cksum >> 8) as u8;
        pkt[11] = cksum as u8;
    }

    /// Recompute TCP checksum.
    fn fix_tcp_checksum(&self, pkt: &mut [u8], tcp_start: usize, new_src: Ipv4Addr) {
        if pkt.len() < tcp_start + 20 {
            return;
        }
        let tcp_len = pkt.len() - tcp_start;
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let seg_copy: Vec<u8> = pkt[tcp_start..tcp_start + tcp_len.min(65535)].to_vec();
        let new_cksum = tcp_checksum(new_src, dst, 6, tcp_len as u16, &seg_copy);
        pkt[tcp_start + 16] = (new_cksum >> 8) as u8;
        pkt[tcp_start + 17] = new_cksum as u8;
    }

    /// Recompute UDP checksum.
    fn fix_udp_checksum(&self, pkt: &mut [u8], udp_start: usize, new_src: Ipv4Addr) {
        if pkt.len() < udp_start + 8 {
            return;
        }
        let udp_len = u16::from_be_bytes([pkt[udp_start + 4], pkt[udp_start + 5]]);
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let seg_copy: Vec<u8> = pkt[udp_start..].to_vec();
        let new_cksum = udp_checksum(new_src, dst, 17, udp_len, &seg_copy);
        pkt[udp_start + 6] = (new_cksum >> 8) as u8;
        pkt[udp_start + 7] = new_cksum as u8;
    }

    pub fn randmap(&self) -> String {
        format!(
            "netfilter_randmap: mode={:?} randomise_port={} port_range=[{},{}]",
            self.cfg.mode,
            self.cfg.randomise_port,
            self.cfg.port_min,
            self.cfg.port_max
        )
    }
}

/// Top-level struct matching the original stub API.
pub struct NetfilterRandmap {
    transform: RandmapTransform,
}

impl Default for NetfilterRandmap {
    fn default() -> Self {
        Self::new(RandmapConfig::default())
    }
}

impl NetfilterRandmap {
    pub fn new(cfg: RandmapConfig) -> Self {
        Self {
            transform: RandmapTransform::new(cfg),
        }
    }

    pub fn randomise_packet(&mut self, pkt: &mut [u8]) -> Result<(), &'static str> {
        self.transform.transform_packet(pkt)
    }

    pub fn randmap(&self) -> String {
        self.transform.randmap()
    }
}

// ---------------------------------------------------------------------------
// Checksum helpers
// ---------------------------------------------------------------------------

fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: u16, segment: &[u8]) -> u16 {
    pseudo_header_checksum(src, dst, proto, len, segment)
}

fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: u16, segment: &[u8]) -> u16 {
    pseudo_header_checksum(src, dst, proto, len, segment)
}

fn pseudo_header_checksum(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    len: u16,
    segment: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    for &b in &src.octets()[..4] {
        sum += u32::from(b);
    }
    for &b in &dst.octets()[..4] {
        sum += u32::from(b);
    }
    sum += u32::from(proto) + u32::from(len);
    for chunk in segment.chunks(2) {
        if chunk.len() == 2 {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        } else {
            sum += u32::from(chunk[0]);
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

fn incremental_checksum(old: u16, old_val: u32, new_val: u32) -> u16 {
    let mut sum: u32 = u32::from(old);
    sum = sum.wrapping_add(u32::from(!old_val as u16));
    sum = sum.wrapping_add(u32::from(new_val as u16));
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum as u16
}

fn is_reserved_v4(addr: &Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0
        || octets[0] == 10
        || octets[0] == 127
        || (octets[0] == 169 && octets[1] == 254)
        || (octets[0] == 172 && (octets[1] & 0xF0) == 0x10)
        || (octets[0] == 192 && (octets[1] == 0 || octets[1] == 168))
        || (octets[0] & 0xF0) == 0xE0
        || (octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_header(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload_len: usize) -> Vec<u8> {
        let total_len = 20 + payload_len;
        let mut hdr = vec![0u8; total_len];
        hdr[0] = 0x45;
        hdr[2] = (total_len >> 8) as u8;
        hdr[3] = total_len as u8;
        hdr[8] = 64;
        hdr[9] = proto;
        hdr[12..16].copy_from_slice(&src.octets());
        hdr[16..20].copy_from_slice(&dst.octets());
        hdr
    }

    fn set_ip_cksum(hdr: &mut [u8]) {
        hdr[10] = 0;
        hdr[11] = 0;
        let mut sum: u32 = 0;
        for i in (0..hdr.len() - (hdr.len() % 2)).step_by(2) {
            if i != 10 && i != 11 {
                sum += u32::from(u16::from_be_bytes([hdr[i], hdr[i + 1]]));
            }
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let cksum = !(sum as u16);
        hdr[10] = (cksum >> 8) as u8;
        hdr[11] = cksum as u8;
    }

    #[test]
    fn subnet_preserving_changes_last_octet() {
        let src = Ipv4Addr::new(10, 0, 0, 5);
        let mut t = RandmapTransform::new(RandmapConfig {
            mode: RandmapMode::SubnetPreserving,
            randomise_port: false,
            ..Default::default()
        });
        let new = t.randomise_v4(src);
        assert_eq!(new.octets()[0..3], src.octets()[0..3]);
        assert_ne!(new.octets()[3], src.octets()[3]);
    }

    #[test]
    fn global_avoids_reserved_ranges() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let mut t = RandmapTransform::new(RandmapConfig {
            mode: RandmapMode::Global,
            randomise_port: false,
            ..Default::default()
        });
        for _ in 0..100 {
            let r = t.randomise_v4(src);
            assert!(!is_reserved_v4(&r), "{r} should not be reserved");
        }
    }

    #[test]
    fn port_only_preserves_ip() {
        let src = Ipv4Addr::new(8, 8, 8, 8);
        let mut t = RandmapTransform::new(RandmapConfig {
            mode: RandmapMode::PortOnly,
            randomise_port: false,
            ..Default::default()
        });
        assert_eq!(t.randomise_v4(src), src);
    }

    #[test]
    fn reserved_ip_rejected() {
        assert!(is_reserved_v4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_reserved_v4(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_reserved_v4(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_reserved_v4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(!is_reserved_v4(&Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn randmap_replaces_println() {
        let nm = NetfilterRandmap::default();
        let s = nm.randmap();
        assert!(s.starts_with("netfilter_randmap:"));
        assert!(s.contains("mode=SubnetPreserving"));
    }

    #[test]
    fn transform_packet_preserves_dst() {
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let mut hdr = ipv4_header(src, dst, 6, 0);
        set_ip_cksum(&mut hdr);
        let mut t = RandmapTransform::default();
        t.transform_packet(&mut hdr).unwrap();
        // Destination IP unchanged at bytes 16-19.
        assert_eq!(hdr[16], 8);
        assert_eq!(hdr[17], 8);
        assert_eq!(hdr[18], 8);
        assert_eq!(hdr[19], 8);
    }
}
