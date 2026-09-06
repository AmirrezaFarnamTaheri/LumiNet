#[derive(Debug, Clone, PartialEq)]
pub struct DnsTunnelFrame {
    pub session_id: u16,
    pub sequence: u16,
    pub is_final: bool,
    pub payload: Vec<u8>,
}

pub struct DnsTunnelCodec;

impl DnsTunnelCodec {
    pub fn encode_to_dns_query_label(frame: &DnsTunnelFrame, domain_suffix: &str) -> String {
        let mut raw = Vec::with_capacity(5 + frame.payload.len());
        raw.extend_from_slice(&frame.session_id.to_be_bytes());
        raw.extend_from_slice(&frame.sequence.to_be_bytes());
        raw.push(if frame.is_final { 1 } else { 0 });
        raw.extend_from_slice(&frame.payload);

        let hex_str = raw.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        format!("{}.{}", hex_str, domain_suffix)
    }

    pub fn decode_from_dns_query_label(query: &str, domain_suffix: &str) -> Option<DnsTunnelFrame> {
        let trimmed = query.strip_suffix(domain_suffix)?.trim_end_matches('.');
        let label = trimmed.split('.').next()?;
        if label.len() < 10 || label.len() % 2 != 0 {
            return None;
        }

        let mut raw = Vec::new();
        for i in (0..label.len()).step_by(2) {
            let byte = u8::from_str_radix(&label[i..i+2], 16).ok()?;
            raw.push(byte);
        }

        let session_id = u16::from_be_bytes([raw[0], raw[1]]);
        let sequence = u16::from_be_bytes([raw[2], raw[3]]);
        let is_final = raw[4] == 1;
        let payload = raw[5..].to_vec();

        Some(DnsTunnelFrame {
            session_id,
            sequence,
            is_final,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_tunnel_frame_roundtrip() {
        let frame = DnsTunnelFrame {
            session_id: 0x1234,
            sequence: 42,
            is_final: true,
            payload: b"tunnel-data".to_vec(),
        };

        let query = DnsTunnelCodec::encode_to_dns_query_label(&frame, "tunnel.example.com");
        assert!(query.ends_with(".tunnel.example.com"));

        let decoded = DnsTunnelCodec::decode_from_dns_query_label(&query, "tunnel.example.com").expect("decode failed");
        assert_eq!(decoded, frame);
    }
}
