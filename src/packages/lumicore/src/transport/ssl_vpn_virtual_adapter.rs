//! SSL VPN Virtual Adapter Stack and Frame Encapsulator
//!
//! Encapsulates raw IP datagrams into structured SSL VPN tunnel transport frames,
//! supporting control messages, keepalive pings, and data transport multiplexing.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslVpnMessageType {
    Data = 0x01,
    Keepalive = 0x02,
    AuthChallenge = 0x03,
    Disconnect = 0x04,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SslVpnFrame {
    pub msg_type: SslVpnMessageType,
    pub session_id: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct SslVpnVirtualAdapter;

impl SslVpnVirtualAdapter {
    /// Formats a frame: [Magic: 2B (0x53, 0x56)] [MsgType: 1B] [Reserved: 1B] [SessionID: 4B] [Len: 2B] [Payload: NB]
    pub fn encode_frame(frame: &SslVpnFrame) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + frame.payload.len());
        out.extend_from_slice(&[0x53, 0x56]); // "SV"
        out.push(frame.msg_type as u8);
        out.push(0x00); // Reserved
        out.extend_from_slice(&frame.session_id.to_be_bytes());
        out.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&frame.payload);
        out
    }

    /// Decodes a frame from raw bytes, returning the parsed frame and consumed bytes
    pub fn decode_frame(buf: &[u8]) -> Option<(SslVpnFrame, usize)> {
        if buf.len() < 10 {
            return None;
        }

        if buf[0] != 0x53 || buf[1] != 0x56 {
            return None;
        }

        let msg_type = match buf[2] {
            0x01 => SslVpnMessageType::Data,
            0x02 => SslVpnMessageType::Keepalive,
            0x03 => SslVpnMessageType::AuthChallenge,
            0x04 => SslVpnMessageType::Disconnect,
            _ => return None,
        };

        let session_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let payload_len = u16::from_be_bytes([buf[8], buf[9]]) as usize;

        let total_size = 10 + payload_len;
        if buf.len() < total_size {
            return None;
        }

        let payload = buf[10..total_size].to_vec();
        Some((
            SslVpnFrame {
                msg_type,
                session_id,
                payload,
            },
            total_size,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssl_vpn_virtual_adapter_roundtrip() {
        let frame = SslVpnFrame {
            msg_type: SslVpnMessageType::Data,
            session_id: 9999,
            payload: b"raw ip packet payload".to_vec(),
        };

        let encoded = SslVpnVirtualAdapter::encode_frame(&frame);
        let (decoded, consumed) = SslVpnVirtualAdapter::decode_frame(&encoded).unwrap();

        assert_eq!(decoded, frame);
        assert_eq!(consumed, encoded.len());
    }
}
