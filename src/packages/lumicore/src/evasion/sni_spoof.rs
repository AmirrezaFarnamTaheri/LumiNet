//! # SNI Spoofing
//!
//! Fake TLS ClientHello injection with wrong TCP sequence number.

use std::net::IpAddr;
use std::sync::LazyLock;

pub const FAKE_CLIENTHELLO_SIZE: usize = 517;
pub const MAX_SNI_LENGTH: usize = 219;

const TEMPLATE_HEX: &str = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5";
const TEMPLATE_SNI: &[u8] = b"mci.ir";

static TEMPLATE_BYTES: LazyLock<Vec<u8>> =
    LazyLock::new(|| decode_hex(TEMPLATE_HEX).expect("invalid built-in SNI spoof template"));

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}

/// Returns whether a decoy hostname is safe to encode as a bounded TLS SNI.
pub fn is_valid_sni_hostname(sni: &str) -> bool {
    if sni.is_empty()
        || sni.len() > MAX_SNI_LENGTH
        || !sni.is_ascii()
        || sni.starts_with('.')
        || sni.ends_with('.')
    {
        return false;
    }
    sni.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

/// Builds the canonical 517-byte fake TLS ClientHello used for out-of-window
/// SNI decoys. The structure is based on a real ClientHello template with a
/// complete extension set and an explicit padding extension, while entropy,
/// key-share bytes, and the SNI value are regenerated per call.
pub fn build_fake_clienthello(
    fake_sni: &str,
    _fingerprint: super::fingerprint::BrowserFingerprint,
) -> Vec<u8> {
    assert!(is_valid_sni_hostname(fake_sni), "invalid fake SNI");

    let template = TEMPLATE_BYTES.as_slice();
    let sni_bytes = fake_sni.as_bytes();
    let template_sni_len = TEMPLATE_SNI.len();

    let static1 = &template[..11];
    let static3 = &template[76..120];
    let static4 = &template[127 + template_sni_len..262 + template_sni_len];

    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    let mut session_id = [0u8; 32];
    let mut key_share = [0u8; 32];
    rng.fill_bytes(&mut random);
    rng.fill_bytes(&mut session_id);
    rng.fill_bytes(&mut key_share);

    let padding_len = MAX_SNI_LENGTH - sni_bytes.len();
    let mut out = Vec::with_capacity(FAKE_CLIENTHELLO_SIZE);
    out.extend_from_slice(static1);
    out.extend_from_slice(&random);
    out.push(0x20);
    out.extend_from_slice(&session_id);
    out.extend_from_slice(static3);

    let sni_ext_len = (sni_bytes.len() + 5) as u16;
    let sni_list_len = (sni_bytes.len() + 3) as u16;
    let sni_len = sni_bytes.len() as u16;
    out.extend_from_slice(&sni_ext_len.to_be_bytes());
    out.extend_from_slice(&sni_list_len.to_be_bytes());
    out.push(0x00);
    out.extend_from_slice(&sni_len.to_be_bytes());
    out.extend_from_slice(sni_bytes);

    out.extend_from_slice(static4);
    out.extend_from_slice(&key_share);
    out.extend_from_slice(&[0x00, 0x15]);
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.resize(out.len() + padding_len, 0);

    assert_eq!(out.len(), FAKE_CLIENTHELLO_SIZE, "ClientHello size mismatch");
    out
}

/// Computes fake TCP sequence number.
pub fn compute_fake_seq(isn: u32, payload_len: usize) -> u32 {
    isn.wrapping_add(1).wrapping_sub(payload_len as u32)
}

/// Computes an out-of-window decoy sequence when the caller already knows the
/// first real payload sequence (`ISN + 1`).
pub fn compute_fake_seq_from_next(next_real_seq: u32, payload_len: usize) -> u32 {
    next_real_seq.wrapping_sub(payload_len as u32)
}

/// Parses SNI from raw TLS ClientHello.
pub fn parse_sni_from_clienthello(data: &[u8]) -> Option<String> {
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }
    let mut pos = 5;
    if pos + 4 > data.len() {
        return None;
    }
    pos += 4;
    pos += 34;
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos >= data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > data.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    while pos + 4 <= ext_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0x0000 {
            if pos + 2 > data.len() {
                return None;
            }
            let sni_start = pos + 2;
            if sni_start + 3 > data.len() {
                return None;
            }
            let sni_type = data[sni_start];
            let sni_len = u16::from_be_bytes([data[sni_start + 1], data[sni_start + 2]]) as usize;
            let sni_value_start = sni_start + 3;
            if sni_type == 0x00 && sni_value_start + sni_len <= data.len() {
                return String::from_utf8(
                    data[sni_value_start..sni_value_start + sni_len].to_vec(),
                )
                .ok();
            }
        }
        pos += ext_len;
    }
    None
}

/// SNI spoofing configuration.
#[derive(Debug, Clone)]
pub struct SniSpoofConfig {
    pub fake_sni: String,
    pub real_sni: String,
    pub fragment_real: bool,
    pub fragment_size: usize,
    pub fragment_delay_ms: u64,
}

impl Default for SniSpoofConfig {
    fn default() -> Self {
        Self {
            fake_sni: "www.speedtest.net".to_string(),
            real_sni: String::new(),
            fragment_real: false,
            fragment_size: 20,
            fragment_delay_ms: 10,
        }
    }
}

/// Connection state tracker for TCP handshake monitoring.
#[derive(Debug, Clone)]
pub struct ConnectionTracker {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub syn_seq: u32,
    pub syn_ack_seq: u32,
    pub ack_seq: u32,
    pub is_monitoring: bool,
    pub handshake_complete: bool,
}

impl ConnectionTracker {
    pub fn new(src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            syn_seq: 0,
            syn_ack_seq: 0,
            ack_seq: 0,
            is_monitoring: false,
            handshake_complete: false,
        }
    }

    pub fn update(&mut self, seq: u32, ack: u32, flags: u8) {
        const SYN: u8 = 0x02;
        const ACK: u8 = 0x10;
        if flags & SYN != 0 && flags & ACK == 0 {
            self.syn_seq = seq;
            self.is_monitoring = true;
        } else if flags & SYN != 0 && flags & ACK != 0 {
            self.syn_ack_seq = seq;
        } else if flags & ACK != 0 && self.is_monitoring {
            self.ack_seq = ack;
            self.handshake_complete = true;
        }
    }

    pub fn should_inject(&self) -> bool {
        self.handshake_complete && self.is_monitoring
    }
}

/// Default decoy SNIs.
pub fn default_decoy_snis() -> Vec<&'static str> {
    vec![
        "www.speedtest.net",
        "www.google.com",
        "www.microsoft.com",
        "www.apple.com",
        "www.cloudflare.com",
        "www.github.com",
        "www.youtube.com",
        "www.facebook.com",
    ]
}

// ---------------------------------------------------------------------------
// SniSpoof — raw-packet out-of-window decoy injector
// Merged from sni_spoof_pro (now removed) into the canonical sni_spoof module.
// ---------------------------------------------------------------------------

/// Wraps a prebuilt decoy ClientHello and provides raw TCP packet injection helpers.
///
/// The injector embeds the decoy payload into an IPv4+TCP frame whose sequence number
/// is deliberately set to `syn_seq + 1 - decoy_len` (out-of-window) so:
///   - DPI middleboxes parse the decoy SNI and log/pass the "connection".
///   - The real server receives an out-of-order segment and silently drops it.
pub struct SniSpoof {
    decoy_payload: Vec<u8>,
}

impl SniSpoof {
    /// Build a new `SniSpoof` using a dynamically constructed decoy ClientHello.
    pub fn new(decoy_domain: &str) -> Self {
        let decoy_payload = Self::build_decoy_hello(decoy_domain);
        SniSpoof { decoy_payload }
    }

    /// Builds the canonical fixed-size padded ClientHello for `decoy_domain`.
    /// Keeping one builder avoids fingerprint drift between the diagnostic and injection paths.
    pub fn build_decoy_hello(decoy_domain: &str) -> Vec<u8> {
        build_fake_clienthello(decoy_domain, super::fingerprint::BrowserFingerprint::Chrome120)
    }

    /// Wraps the decoy payload in a raw IPv4+TCP frame with an out-of-window sequence number.
    ///
    /// `syn_seq` is the sequence number from the observed SYN packet.
    /// Returns the complete raw packet bytes (IP + TCP + payload) ready for injection
    /// via a raw socket or WinDivert/NFQUEUE.
    pub fn inject_out_of_window_decoy(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        syn_seq: u32,
    ) -> Vec<u8> {
        let decoy_len = self.decoy_payload.len() as u32;
        // seq = syn_seq + 1 - decoy_len  →  falls before the receiver's window
        let decoy_seq = syn_seq.wrapping_add(1).wrapping_sub(decoy_len);
        let total_len = (20 + 20 + self.decoy_payload.len()) as u16;

        let mut pkt = Vec::with_capacity(total_len as usize);

        // IPv4 header (20 bytes)
        pkt.push(0x45); // version=4, IHL=5
        pkt.push(0x00); // DSCP/ECN
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x12, 0x34]); // identification
        pkt.extend_from_slice(&[0x40, 0x00]); // flags: DF, frag offset 0
        pkt.push(0x40); // TTL=64
        pkt.push(0x06); // protocol: TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum (computed below)

        match (src_ip, dst_ip) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                pkt.extend_from_slice(&s.octets());
                pkt.extend_from_slice(&d.octets());
            }
            _ => return Vec::new(), // IPv6 not supported by this raw injector
        }

        // TCP header (20 bytes)
        pkt.extend_from_slice(&src_port.to_be_bytes());
        pkt.extend_from_slice(&dst_port.to_be_bytes());
        pkt.extend_from_slice(&decoy_seq.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack=0 (decoy; server drops)
        pkt.push(0x50); // data offset=5 (20 bytes)
        pkt.push(0x18); // flags: PSH|ACK
        pkt.extend_from_slice(&[0xf0, 0x00]); // window size
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum (computed below)
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent pointer

        pkt.extend_from_slice(&self.decoy_payload);

        Self::fill_checksums(&mut pkt);
        pkt
    }

    fn fill_checksums(pkt: &mut [u8]) {
        // IP header checksum (one's complement of the one's complement sum of header words)
        let mut sum = 0u32;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let csum = !(sum as u16);
        pkt[10] = (csum >> 8) as u8;
        pkt[11] = (csum & 0xff) as u8;

        // TCP checksum over pseudo-header + TCP segment
        let total = pkt.len();
        let tcp_len = (total - 20) as u32;
        let mut sum = 0u32;
        for i in (12..20).step_by(2) {
            // src+dst IP from IP header
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        sum += 6u32; // protocol = TCP
        sum += tcp_len;
        let mut i = 20;
        while i + 1 < total {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
            i += 2;
        }
        if !total.is_multiple_of(2) {
            sum += (pkt[total - 1] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let csum = !(sum as u16);
        pkt[36] = (csum >> 8) as u8;
        pkt[37] = (csum & 0xff) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evasion::BrowserFingerprint;

    #[test]
    fn test_build_fake_clienthello() {
        let hello = build_fake_clienthello("www.speedtest.net", BrowserFingerprint::Chrome120);
        assert_eq!(hello.len(), FAKE_CLIENTHELLO_SIZE);
    }

    #[test]
    fn test_compute_fake_seq() {
        assert_eq!(compute_fake_seq(1000, 517), 1001 - 517);
    }

    #[test]
    fn test_compute_fake_seq_from_next() {
        assert_eq!(compute_fake_seq_from_next(1001, 517), 1001 - 517);
    }

    #[test]
    fn test_fake_clienthello_is_fixed_size_and_round_trips_sni() {
        let sni = "security.vercel.com";
        let hello = build_fake_clienthello(sni, BrowserFingerprint::Chrome120);
        assert_eq!(hello.len(), FAKE_CLIENTHELLO_SIZE);
        assert_eq!(u16::from_be_bytes([hello[3], hello[4]]) as usize, hello.len() - 5);
        assert_eq!(parse_sni_from_clienthello(&hello).as_deref(), Some(sni));
    }

    #[test]
    fn test_sni_validation_rejects_malformed_names() {
        for sni in ["", "bad name", "-bad.example", "bad-.example", ".bad.example"] {
            assert!(!is_valid_sni_hostname(sni), "unexpected valid SNI: {sni}");
        }
    }

    #[test]
    fn test_connection_tracker() {
        let mut tracker = ConnectionTracker::new(
            "192.168.1.1".parse().unwrap(),
            12345,
            "10.0.0.1".parse().unwrap(),
            443,
        );
        tracker.update(1000, 0, 0x02);
        assert!(tracker.is_monitoring);
        tracker.update(5000, 1001, 0x12);
        tracker.update(1001, 5001, 0x10);
        assert!(tracker.should_inject());
    }

    #[test]
    fn test_sni_spoof_decoy_hello() {
        let spoof = SniSpoof::new("www.example.com");
        let payload = &spoof.decoy_payload;
        // TLS record header byte 0 must be 0x16 (handshake)
        assert_eq!(payload[0], 0x16);
        // ClientHello type byte at position 5 must be 0x01
        assert_eq!(payload[5], 0x01);
    }

    #[test]
    fn test_sni_spoof_inject_packet_length() {
        let spoof = SniSpoof::new("www.cloudflare.com");
        let src: IpAddr = "192.168.1.1".parse().unwrap();
        let dst: IpAddr = "1.1.1.1".parse().unwrap();
        let pkt = spoof.inject_out_of_window_decoy(src, dst, 12345, 443, 1000);
        // Packet must be at least IP(20) + TCP(20) + payload
        assert!(pkt.len() >= 40 + spoof.decoy_payload.len());
        // Protocol byte in IP header = 6 (TCP)
        assert_eq!(pkt[9], 0x06);
    }
}
