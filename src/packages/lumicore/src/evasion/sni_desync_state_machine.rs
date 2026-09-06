//! # SNI Desync State Machine & TLS Handshake Synthesizer
//!
//! Complete bi-directional TCP three-way handshake tracking state machine and
//! byte-for-byte TLS 1.3 ClientHello / ServerHello template synthesizer with round-trip
//! component extraction for out-of-window SNI spoofing DPI bypass.
//!

use std::net::{IpAddr, SocketAddr};

/// TLS constants used in template synthesis.
pub const TLS_CHANGE_CIPHER_SPEC: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
pub const TLS_APP_DATA_HEADER: [u8; 3] = [0x17, 0x03, 0x03];

/// Parsed components extracted from a 517-byte canonical ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedClientHello {
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub sni: String,
    pub key_share: [u8; 32],
}

/// Parsed components extracted from a ServerHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedServerHello {
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub key_share: [u8; 32],
    pub app_data: Vec<u8>,
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).map_err(|error| error.to_string())
        })
        .collect()
}

/// Static ServerHello template hex string.
pub const SH_TEMPLATE_HEX: &str = "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1dae291c5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbde406130200002e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5b0e4eb188ebd30193271e8171152eb4e";

/// Synthesizes a TLS 1.3 ServerHello packet with ChangeCipherSpec and ApplicationData envelope.
pub fn build_serverhello_with(
    random: &[u8; 32],
    session_id: &[u8; 32],
    key_share: &[u8; 32],
    app_data: &[u8],
) -> Vec<u8> {
    let raw_sh = decode_hex(SH_TEMPLATE_HEX).unwrap_or_default();
    let static1 = &raw_sh[..11];
    let static3 = &raw_sh[76..95];

    let mut result = Vec::with_capacity(256 + app_data.len());
    result.extend_from_slice(static1);
    result.extend_from_slice(random);
    result.push(0x20);
    result.extend_from_slice(session_id);
    result.extend_from_slice(static3);
    result.extend_from_slice(key_share);
    result.extend_from_slice(&TLS_CHANGE_CIPHER_SPEC);
    result.extend_from_slice(&TLS_APP_DATA_HEADER);
    result.extend_from_slice(&(app_data.len() as u16).to_be_bytes());
    result.extend_from_slice(app_data);

    result
}

/// Builds a TLS client response packet (ChangeCipherSpec + ApplicationData header + length + app_data).
pub fn build_client_response_with(app_data: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(11 + app_data.len());
    result.extend_from_slice(&TLS_CHANGE_CIPHER_SPEC);
    result.extend_from_slice(&TLS_APP_DATA_HEADER);
    result.extend_from_slice(&(app_data.len() as u16).to_be_bytes());
    result.extend_from_slice(app_data);
    result
}

/// Parses a TLS client response packet and returns the underlying application data.
pub fn parse_client_response(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 11 {
        return Err("Client response packet too short (expected at least 11 bytes)".to_string());
    }
    if &data[..6] != TLS_CHANGE_CIPHER_SPEC.as_slice() {
        return Err("Missing or invalid ChangeCipherSpec header".to_string());
    }
    if &data[6..9] != TLS_APP_DATA_HEADER.as_slice() {
        return Err("Missing or invalid ApplicationData header".to_string());
    }
    let len = u16::from_be_bytes([data[9], data[10]]) as usize;
    if data.len() < 11 + len {
        return Err("Application data truncated in client response".to_string());
    }
    Ok(data[11..11 + len].to_vec())
}

/// Parses a synthesized ServerHello and extracts its constituent cryptographic segments.
pub fn parse_serverhello(data: &[u8]) -> Result<ParsedServerHello, String> {
    if data.len() < 159 {
        return Err(format!("Expected >= 159 bytes for ServerHello, got {}", data.len()));
    }

    let mut random = [0u8; 32];
    random.copy_from_slice(&data[11..43]);

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&data[44..76]);

    let mut key_share = [0u8; 32];
    key_share.copy_from_slice(&data[95..127]);

    let app_data = if data.len() > 138 {
        data[138..].to_vec()
    } else {
        Vec::new()
    };

    Ok(ParsedServerHello {
        random,
        session_id,
        key_share,
        app_data,
    })
}

/// Parses a canonical 517-byte ClientHello packet back into its component parts.
pub fn parse_clienthello(data: &[u8]) -> Result<ParsedClientHello, String> {
    if data.len() != 517 {
        return Err(format!("Expected 517 bytes for canonical ClientHello, got {}", data.len()));
    }

    let mut random = [0u8; 32];
    random.copy_from_slice(&data[11..43]);

    let mut session_id = [0u8; 32];
    session_id.copy_from_slice(&data[44..76]);

    let sni_len = u16::from_be_bytes([data[125], data[126]]) as usize;
    if 127 + sni_len > data.len() {
        return Err("SNI length exceeds packet length".to_string());
    }

    let sni = String::from_utf8(data[127..127 + sni_len].to_vec())
        .map_err(|e| format!("Invalid SNI UTF-8: {}", e))?;

    let ks_idx = 262 + sni_len;
    if ks_idx + 32 > data.len() {
        return Err("Key share offset out of bounds".to_string());
    }

    let mut key_share = [0u8; 32];
    key_share.copy_from_slice(&data[ks_idx..ks_idx + 32]);

    Ok(ParsedClientHello {
        random,
        session_id,
        sni,
        key_share,
    })
}

/// TCP flag masks.
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;

/// State of a TCP connection being monitored for out-of-window desync injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    Initial,
    SynSent,
    SynAckReceived,
    HandshakeComplete,
    DecoyInjected,
    DecoyAcknowledged,
    Terminated,
}

/// Action produced by processing an outbound packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundHandshakeAction {
    Pass,
    ScheduleDecoyInjection {
        decoy_seq: u32,
        new_ident: u16,
    },
    UnexpectedPacket(String),
}

/// Action produced by processing an inbound packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundHandshakeAction {
    Pass,
    DecoyAckReceived,
    UnexpectedPacket(String),
}

/// State machine tracking TCP handshake state to synchronize out-of-window SNI injection.
#[derive(Debug, Clone)]
pub struct TcpHandshakeDesyncTracker {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub syn_seq: Option<u32>,
    pub syn_ack_seq: Option<u32>,
    pub phase: HandshakePhase,
    pub fake_sent: bool,
    pub bypass_method: String,
}

impl TcpHandshakeDesyncTracker {
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            remote_addr,
            syn_seq: None,
            syn_ack_seq: None,
            phase: HandshakePhase::Initial,
            fake_sent: false,
            bypass_method: "wrong_seq".to_string(),
        }
    }

    /// Processes an outbound packet originating from the local client.
    pub fn handle_outbound(
        &mut self,
        seq_num: u32,
        ack_num: u32,
        flags: u8,
        payload_len: usize,
        curr_ident: u16,
        decoy_len: usize,
    ) -> OutboundHandshakeAction {
        if self.phase == HandshakePhase::DecoyInjected || self.phase == HandshakePhase::DecoyAcknowledged {
            return OutboundHandshakeAction::Pass;
        }

        // 1. SYN packet: SYN=1, ACK=0, RST=0, FIN=0, payload=0
        let is_syn = (flags & TCP_FLAG_SYN != 0)
            && (flags & TCP_FLAG_ACK == 0)
            && (flags & TCP_FLAG_RST == 0)
            && (flags & TCP_FLAG_FIN == 0)
            && payload_len == 0;

        if is_syn {
            if ack_num != 0 {
                self.phase = HandshakePhase::Terminated;
                return OutboundHandshakeAction::UnexpectedPacket("Outbound SYN ack_num != 0".to_string());
            }
            if let Some(existing_syn) = self.syn_seq {
                if existing_syn != seq_num {
                    self.phase = HandshakePhase::Terminated;
                    return OutboundHandshakeAction::UnexpectedPacket(format!(
                        "SYN seq mismatch: new {} != existing {}",
                        seq_num, existing_syn
                    ));
                }
            }
            self.syn_seq = Some(seq_num);
            self.phase = HandshakePhase::SynSent;
            return OutboundHandshakeAction::Pass;
        }

        // 2. ACK packet completing 3-way handshake: SYN=0, ACK=1, RST=0, FIN=0, payload=0
        let is_ack = (flags & TCP_FLAG_ACK != 0)
            && (flags & TCP_FLAG_SYN == 0)
            && (flags & TCP_FLAG_RST == 0)
            && (flags & TCP_FLAG_FIN == 0)
            && payload_len == 0;

        if is_ack && self.phase == HandshakePhase::SynAckReceived {
            let syn_seq = match self.syn_seq {
                Some(s) => s,
                None => {
                    self.phase = HandshakePhase::Terminated;
                    return OutboundHandshakeAction::UnexpectedPacket("No SYN sequence recorded".to_string());
                }
            };
            let syn_ack_seq = match self.syn_ack_seq {
                Some(s) => s,
                None => {
                    self.phase = HandshakePhase::Terminated;
                    return OutboundHandshakeAction::UnexpectedPacket("No SYN-ACK sequence recorded".to_string());
                }
            };

            let expected_seq = syn_seq.wrapping_add(1);
            if seq_num != expected_seq {
                self.phase = HandshakePhase::Terminated;
                return OutboundHandshakeAction::UnexpectedPacket(format!(
                    "Outbound ACK seq mismatch: {} != expected {}",
                    seq_num, expected_seq
                ));
            }

            let expected_ack = syn_ack_seq.wrapping_add(1);
            if ack_num != expected_ack {
                self.phase = HandshakePhase::Terminated;
                return OutboundHandshakeAction::UnexpectedPacket(format!(
                    "Outbound ACK ack mismatch: {} != expected {}",
                    ack_num, expected_ack
                ));
            }

            // Handshake is complete! Calculate out-of-window decoy sequence
            self.phase = HandshakePhase::HandshakeComplete;
            let decoy_seq = syn_seq.wrapping_add(1).wrapping_sub(decoy_len as u32);
            let new_ident = curr_ident.wrapping_add(1);
            self.fake_sent = true;
            self.phase = HandshakePhase::DecoyInjected;

            return OutboundHandshakeAction::ScheduleDecoyInjection {
                decoy_seq,
                new_ident,
            };
        }

        OutboundHandshakeAction::UnexpectedPacket("Unexpected outbound packet during handshake".to_string())
    }

    /// Processes an inbound packet arriving from the remote destination server.
    pub fn handle_inbound(
        &mut self,
        seq_num: u32,
        ack_num: u32,
        flags: u8,
        payload_len: usize,
    ) -> InboundHandshakeAction {
        let syn_seq = match self.syn_seq {
            Some(s) => s,
            None => {
                self.phase = HandshakePhase::Terminated;
                return InboundHandshakeAction::UnexpectedPacket("Inbound packet before outbound SYN".to_string());
            }
        };

        // 1. SYN-ACK packet: SYN=1, ACK=1, RST=0, FIN=0, payload=0
        let is_syn_ack = (flags & TCP_FLAG_SYN != 0)
            && (flags & TCP_FLAG_ACK != 0)
            && (flags & TCP_FLAG_RST == 0)
            && (flags & TCP_FLAG_FIN == 0)
            && payload_len == 0;

        if is_syn_ack {
            let expected_ack = syn_seq.wrapping_add(1);
            if ack_num != expected_ack {
                self.phase = HandshakePhase::Terminated;
                return InboundHandshakeAction::UnexpectedPacket(format!(
                    "SYN-ACK ack mismatch: {} != expected {}",
                    ack_num, expected_ack
                ));
            }
            if let Some(existing_syn_ack) = self.syn_ack_seq {
                if existing_syn_ack != seq_num {
                    self.phase = HandshakePhase::Terminated;
                    return InboundHandshakeAction::UnexpectedPacket(format!(
                        "SYN-ACK seq changed: {} != {}",
                        seq_num, existing_syn_ack
                    ));
                }
            }
            self.syn_ack_seq = Some(seq_num);
            self.phase = HandshakePhase::SynAckReceived;
            return InboundHandshakeAction::Pass;
        }

        // 2. Decoy ACK packet: remote server acknowledged the handshake or decoy: ACK=1, SYN=0, payload=0
        let is_ack = (flags & TCP_FLAG_ACK != 0)
            && (flags & TCP_FLAG_SYN == 0)
            && (flags & TCP_FLAG_RST == 0)
            && (flags & TCP_FLAG_FIN == 0)
            && payload_len == 0;

        if is_ack && (self.phase == HandshakePhase::DecoyInjected || self.fake_sent) {
            let syn_ack_seq = match self.syn_ack_seq {
                Some(s) => s,
                None => {
                    self.phase = HandshakePhase::Terminated;
                    return InboundHandshakeAction::UnexpectedPacket("Missing SYN-ACK sequence".to_string());
                }
            };

            let expected_seq = syn_ack_seq.wrapping_add(1);
            if seq_num != expected_seq {
                self.phase = HandshakePhase::Terminated;
                return InboundHandshakeAction::UnexpectedPacket(format!(
                    "Inbound ACK seq mismatch: {} != expected {}",
                    seq_num, expected_seq
                ));
            }

            let expected_ack = syn_seq.wrapping_add(1);
            if ack_num != expected_ack {
                self.phase = HandshakePhase::Terminated;
                return InboundHandshakeAction::UnexpectedPacket(format!(
                    "Inbound ACK ack mismatch: {} != expected {}",
                    ack_num, expected_ack
                ));
            }

            self.phase = HandshakePhase::DecoyAcknowledged;
            return InboundHandshakeAction::DecoyAckReceived;
        }

        InboundHandshakeAction::UnexpectedPacket("Unexpected inbound packet".to_string())
    }
}
