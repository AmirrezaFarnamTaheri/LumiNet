//! # SNI Spoof Engine & DPI Desync Coordinator
//!
//! High-performance packet-level SNI spoofing and DPI desynchronization engine.
//!
//! Provides:
//! - 4-Tuple connection state tracking for raw TCP injection
//! - Out-of-window sequence number calculation: `(syn_seq + 1 - fake_len) & 0xFFFFFFFF`
//! - Byte-accurate TLS 1.3 ClientHello template builder with dynamic SNI and RFC 7685 padding balancing
//! - Bitwise Cloudflare CIDR scanner for 15 canonical network ranges
//! - Port conflict and kill-switch orchestration logic

use std::net::Ipv4Addr;

/// 4-Tuple key identifying a TCP connection in network byte order or host u32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Conn4TupleKey {
    pub src_ip: u32,
    pub src_port: u16,
    pub dst_ip: u32,
    pub dst_port: u16,
}

impl Conn4TupleKey {
    pub fn new(src_ip: Ipv4Addr, src_port: u16, dst_ip: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src_ip: u32::from(src_ip),
            src_port,
            dst_ip: u32::from(dst_ip),
            dst_port,
        }
    }

    /// Returns the reverse key for tracking the inbound reply direction.
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
        }
    }
}

/// Profile configuration for the SNI spoof engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniSpoofEngineProfile {
    pub connect_ip: String,
    pub connect_port: u16,
    pub listen_host: String,
    pub listen_port: u16,
    pub fake_sni: String,
    pub fast_mode: bool,
}

impl Default for SniSpoofEngineProfile {
    fn default() -> Self {
        Self {
            connect_ip: "127.0.0.1".to_string(),
            connect_port: 443,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 10808,
            fake_sni: "speedtest.net".to_string(),
            fast_mode: true,
        }
    }
}

/// TCP flag constants.
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;

/// IPv4 / TCP packet dissection and mutation helpers.
pub struct IpTcpPacket;

impl IpTcpPacket {
    #[inline]
    pub fn is_ipv4_tcp(buf: &[u8]) -> bool {
        if buf.len() < 20 {
            return false;
        }
        let version = buf[0] >> 4;
        let protocol = buf[9];
        version == 4 && protocol == 6
    }

    #[inline]
    pub fn ip_header_len(buf: &[u8]) -> usize {
        (buf[0] & 0x0F) as usize * 4
    }

    #[inline]
    pub fn tcp_header_len(buf: &[u8], ip_hl: usize) -> usize {
        if buf.len() < ip_hl + 13 {
            return 20;
        }
        ((buf[ip_hl + 12] >> 4) as usize) * 4
    }

    #[inline]
    pub fn total_len(buf: &[u8]) -> u16 {
        if buf.len() < 4 {
            return 0;
        }
        u16::from_be_bytes([buf[2], buf[3]])
    }

    #[inline]
    pub fn src_ip(buf: &[u8]) -> u32 {
        if buf.len() < 16 {
            return 0;
        }
        u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]])
    }

    #[inline]
    pub fn dst_ip(buf: &[u8]) -> u32 {
        if buf.len() < 20 {
            return 0;
        }
        u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]])
    }

    #[inline]
    pub fn src_port(buf: &[u8], ip_hl: usize) -> u16 {
        if buf.len() < ip_hl + 2 {
            return 0;
        }
        u16::from_be_bytes([buf[ip_hl], buf[ip_hl + 1]])
    }

    #[inline]
    pub fn dst_port(buf: &[u8], ip_hl: usize) -> u16 {
        if buf.len() < ip_hl + 4 {
            return 0;
        }
        u16::from_be_bytes([buf[ip_hl + 2], buf[ip_hl + 3]])
    }

    #[inline]
    pub fn seq_num(buf: &[u8], ip_hl: usize) -> u32 {
        if buf.len() < ip_hl + 8 {
            return 0;
        }
        u32::from_be_bytes([buf[ip_hl + 4], buf[ip_hl + 5], buf[ip_hl + 6], buf[ip_hl + 7]])
    }

    #[inline]
    pub fn ack_num(buf: &[u8], ip_hl: usize) -> u32 {
        if buf.len() < ip_hl + 12 {
            return 0;
        }
        u32::from_be_bytes([buf[ip_hl + 8], buf[ip_hl + 9], buf[ip_hl + 10], buf[ip_hl + 11]])
    }

    #[inline]
    pub fn flags(buf: &[u8], ip_hl: usize) -> u8 {
        if buf.len() < ip_hl + 14 {
            return 0;
        }
        buf[ip_hl + 13]
    }

    #[inline]
    pub fn payload_len(buf: &[u8]) -> usize {
        let ip_hl = Self::ip_header_len(buf);
        let tcp_hl = Self::tcp_header_len(buf, ip_hl);
        let tot = Self::total_len(buf) as usize;
        if tot >= ip_hl + tcp_hl {
            tot - ip_hl - tcp_hl
        } else {
            0
        }
    }

    /// Constructs an out-of-window decoy packet from a captured 3-way ACK packet snapshot.
    ///
    /// The fake packet replaces the TCP payload with `fake_payload`, advances IP total length,
    /// increments the IPv4 identification field, sets the TCP PSH flag, and updates the sequence
    /// number to `fake_seq`.
    pub fn build_fake_payload_packet(
        source_packet: &[u8],
        fake_payload: &[u8],
        fake_seq: u32,
    ) -> Result<Vec<u8>, String> {
        if !Self::is_ipv4_tcp(source_packet) {
            return Err("source packet is not a valid IPv4 TCP packet".to_string());
        }

        let ip_hl = Self::ip_header_len(source_packet);
        let tcp_hl = Self::tcp_header_len(source_packet, ip_hl);
        let header_len = ip_hl + tcp_hl;

        if source_packet.len() < header_len {
            return Err("source packet truncated before headers complete".to_string());
        }

        let total_size = header_len + fake_payload.len();
        if total_size > 65535 {
            return Err("resulting packet exceeds maximum IPv4 MTU (65535)".to_string());
        }

        let mut packet = vec![0u8; total_size];
        packet[..header_len].copy_from_slice(&source_packet[..header_len]);
        packet[header_len..].copy_from_slice(fake_payload);

        // Update IPv4 Total Length (bytes 2..4)
        let total_len_be = (total_size as u16).to_be_bytes();
        packet[2] = total_len_be[0];
        packet[3] = total_len_be[1];

        // Increment IPv4 Identification (bytes 4..6)
        let ident = u16::from_be_bytes([packet[4], packet[5]]);
        let new_ident = ident.wrapping_add(1).to_be_bytes();
        packet[4] = new_ident[0];
        packet[5] = new_ident[1];

        // Set TCP PSH flag (byte ip_hl + 13)
        packet[ip_hl + 13] |= TCP_FLAG_PSH;

        // Overwrite TCP Sequence Number (bytes ip_hl + 4 .. ip_hl + 8)
        let seq_be = fake_seq.to_be_bytes();
        packet[ip_hl + 4..ip_hl + 8].copy_from_slice(&seq_be);

        // Compute internet checksum for IPv4 header
        Self::compute_ip_checksum(&mut packet[..ip_hl]);

        // Compute TCP checksum including pseudo-header
        Self::compute_tcp_checksum(&mut packet, ip_hl, tcp_hl);

        Ok(packet)
    }

    /// Computes and writes the standard RFC 791 IPv4 header checksum.
    pub fn compute_ip_checksum(ip_header: &mut [u8]) {
        ip_header[10] = 0;
        ip_header[11] = 0;
        let mut sum: u32 = 0;
        for chunk in ip_header.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let checksum = !(sum as u16);
        let cs_bytes = checksum.to_be_bytes();
        ip_header[10] = cs_bytes[0];
        ip_header[11] = cs_bytes[1];
    }

    /// Computes and writes the RFC 793 TCP checksum over pseudo-header and segment.
    pub fn compute_tcp_checksum(packet: &mut [u8], ip_hl: usize, tcp_hl: usize) {
        if packet.len() < ip_hl + tcp_hl {
            return;
        }
        // Zero existing checksum field in TCP header (offset 16..18 in TCP header)
        packet[ip_hl + 16] = 0;
        packet[ip_hl + 17] = 0;

        let src_ip = [packet[12], packet[13], packet[14], packet[15]];
        let dst_ip = [packet[16], packet[17], packet[18], packet[19]];
        let tcp_len = (packet.len() - ip_hl) as u16;

        let mut sum: u32 = 0;
        // Pseudo-header: Src IP
        sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
        sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
        // Pseudo-header: Dst IP
        sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
        // Pseudo-header: Protocol (6) + TCP length
        sum += 6u32;
        sum += tcp_len as u32;

        // TCP segment
        let tcp_segment = &packet[ip_hl..];
        for chunk in tcp_segment.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        if tcp_segment.len() % 2 != 0 {
            sum += (tcp_segment[tcp_segment.len() - 1] as u32) << 8;
        }

        while (sum >> 16) > 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let checksum = !(sum as u16);
        let cs_bytes = checksum.to_be_bytes();
        packet[ip_hl + 16] = cs_bytes[0];
        packet[ip_hl + 17] = cs_bytes[1];
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    if value.len() % 2 != 0 {
        return Vec::new();
    }
    (0..value.len())
        .step_by(2)
        .filter_map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

/// Dynamic TLS 1.3 ClientHello template builder with RFC 7685 padding balancing.
///
/// Ensures the overall ClientHello length remains strictly 517 bytes regardless of
/// the SNI hostname length (`pad_len = 219 - fake_sni.len()`).
pub struct TlsClientHelloTemplate;

impl TlsClientHelloTemplate {
    pub const TEMPLATE_HEX: &'static str =
        "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    const TEMPLATE_SNI_LEN: usize = 6;

    /// Builds a canonical ClientHello with the requested fake SNI and deterministic entropy.
    pub fn build(fake_sni: &str, random: [u8; 32], session_id: [u8; 32], key_share: [u8; 32]) -> Vec<u8> {
        let template_bytes = decode_hex(Self::TEMPLATE_HEX);
        let sni_bytes = fake_sni.as_bytes();

        let static1 = &template_bytes[..11];
        let static2 = &[0x20u8];
        let static3 = &template_bytes[76..120];
        let static4 = &template_bytes[(127 + Self::TEMPLATE_SNI_LEN)..(262 + Self::TEMPLATE_SNI_LEN)];
        let static5 = &[0x00u8, 0x15u8];

        // SNI Extension: [Type=0x00,0x00][ExtLen: 2B][ListLen: 2B][NameType=0x00][NameLen: 2B][NameBytes]
        let mut sni_ext = Vec::with_capacity(7 + sni_bytes.len());
        sni_ext.extend_from_slice(&((sni_bytes.len() + 5) as u16).to_be_bytes());
        sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
        sni_ext.push(0x00); // HostName type
        sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(sni_bytes);

        // Padding Extension (RFC 7685, Type 0x0015): pad_len = 219 - sni_bytes.len()
        let pad_len = if sni_bytes.len() <= 219 {
            219 - sni_bytes.len()
        } else {
            0
        };
        let mut pad_ext = Vec::with_capacity(2 + pad_len);
        pad_ext.extend_from_slice(&(pad_len as u16).to_be_bytes());
        pad_ext.resize(2 + pad_len, 0x00);

        let mut out = Vec::with_capacity(517);
        out.extend_from_slice(static1);
        out.extend_from_slice(&random);
        out.extend_from_slice(static2);
        out.extend_from_slice(&session_id);
        out.extend_from_slice(static3);
        out.extend_from_slice(&sni_ext);
        out.extend_from_slice(static4);
        out.extend_from_slice(&key_share);
        out.extend_from_slice(static5);
        out.extend_from_slice(&pad_ext);

        out
    }
}

/// Bitwise matcher for the 15 canonical Cloudflare IPv4 CIDR ranges.
pub struct CloudflareCidrMatcher;

impl CloudflareCidrMatcher {
    pub const CIDRS: [&'static str; 15] = [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    ];

    /// Checks whether an IPv4 address belongs to any Cloudflare edge CIDR range.
    pub fn is_cloudflare_ip(ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        for cidr in &Self::CIDRS {
            if let Some((net, mask)) = Self::parse_cidr(cidr) {
                if (ip_u32 & mask) == net {
                    return true;
                }
            }
        }
        false
    }

    fn parse_cidr(cidr: &str) -> Option<(u32, u32)> {
        let mut parts = cidr.split('/');
        let ip_str = parts.next()?;
        let prefix_len: u32 = parts.next()?.parse().ok()?;
        let ip: Ipv4Addr = ip_str.parse().ok()?;
        let ip_u32 = u32::from(ip);
        let mask = if prefix_len == 0 {
            0
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        };
        Some((ip_u32 & mask, mask))
    }
}

/// Domain sanitization and extraction utility for SNI scanner.
pub struct SniDomainCleaner;

impl SniDomainCleaner {
    /// Sanitizes and strips protocols, trailing slashes, comments, and port numbers from raw SNI inputs.
    pub fn clean_domain(raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return None;
        }

        let mut domain = trimmed;
        // Strip URL schemes (e.g., https://, http://)
        if let Some(pos) = domain.find("://") {
            domain = &domain[pos + 3..];
        }

        // Strip path / query
        if let Some(pos) = domain.find('/') {
            domain = &domain[..pos];
        }

        // Strip port numbers
        if let Some(pos) = domain.find(':') {
            domain = &domain[..pos];
        }

        let cleaned = domain.trim().to_lowercase();
        if cleaned.is_empty() || cleaned.contains(' ') || !cleaned.contains('.') {
            return None;
        }

        Some(cleaned)
    }
}

/// Action produced by the emergency kill-switch coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillSwitchAction {
    NoChange,
    BlockOutbound,
    UnblockOutbound,
}

/// Coordinates system firewall kill-switch arming and state transitions.
#[derive(Debug, Clone)]
pub struct KillSwitchCoordinator {
    pub armed_sni: bool,
    pub armed_v2ray: bool,
    pub is_blocked: bool,
    pub kill_switch_enabled: bool,
}

impl KillSwitchCoordinator {
    pub fn new(kill_switch_enabled: bool) -> Self {
        Self {
            armed_sni: false,
            armed_v2ray: false,
            is_blocked: false,
            kill_switch_enabled,
        }
    }

    pub fn arm_sni(&mut self) {
        self.armed_sni = true;
    }

    pub fn arm_v2ray(&mut self) {
        self.armed_v2ray = true;
    }

    pub fn disarm_sni(&mut self) -> KillSwitchAction {
        self.armed_sni = false;
        self.evaluate_unblock()
    }

    pub fn disarm_v2ray(&mut self) -> KillSwitchAction {
        self.armed_v2ray = false;
        self.evaluate_unblock()
    }

    /// Evaluates periodic heartbeat tick against active core state.
    pub fn on_tick(&mut self, sni_running: bool, v2ray_running: bool) -> KillSwitchAction {
        if !self.kill_switch_enabled {
            return self.evaluate_unblock();
        }

        if !self.armed_sni && !self.armed_v2ray {
            return KillSwitchAction::NoChange;
        }

        let dropped = (self.armed_sni && !sni_running) || (self.armed_v2ray && !v2ray_running);

        if dropped && !self.is_blocked {
            self.is_blocked = true;
            KillSwitchAction::BlockOutbound
        } else {
            KillSwitchAction::NoChange
        }
    }

    fn evaluate_unblock(&mut self) -> KillSwitchAction {
        if (!self.armed_sni && !self.armed_v2ray) || !self.kill_switch_enabled {
            if self.is_blocked {
                self.is_blocked = false;
                return KillSwitchAction::UnblockOutbound;
            }
        }
        KillSwitchAction::NoChange
    }

    /// Returns the Windows netsh command to block all outbound traffic.
    pub fn netsh_block_rule(rule_name: &str) -> Vec<String> {
        vec![
            "advfirewall".into(),
            "firewall".into(),
            "add".into(),
            "rule".into(),
            format!("name={}", rule_name),
            "dir=out".into(),
            "action=block".into(),
            "profile=any".into(),
            "enable=yes".into(),
        ]
    }

    /// Returns the Windows netsh command to remove the outbound block rule.
    pub fn netsh_unblock_rule(rule_name: &str) -> Vec<String> {
        vec![
            "advfirewall".into(),
            "firewall".into(),
            "delete".into(),
            "rule".into(),
            format!("name={}", rule_name),
        ]
    }
}
