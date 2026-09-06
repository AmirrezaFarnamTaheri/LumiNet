//! # SLIP (Serial Line Internet Protocol) Framing Codec
//!
//! Implements RFC 1055 packet framing for encapsulating IP packets over
//! streams and datagram channels. Ported and elevated from `SlipNet-main` and `Skirk-main`.

pub const SLIP_END: u8 = 0xC0;
pub const SLIP_ESC: u8 = 0xDB;
pub const SLIP_ESC_END: u8 = 0xDC;
pub const SLIP_ESC_ESC: u8 = 0xDD;

/// Encodes a raw packet buffer into a SLIP-framed byte vector.
pub fn slip_encode(packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(packet.len() + 8);
    out.push(SLIP_END);
    for &b in packet {
        match b {
            SLIP_END => {
                out.push(SLIP_ESC);
                out.push(SLIP_ESC_END);
            }
            SLIP_ESC => {
                out.push(SLIP_ESC);
                out.push(SLIP_ESC_ESC);
            }
            _ => out.push(b),
        }
    }
    out.push(SLIP_END);
    out
}

/// Streaming SLIP decoder that accumulates input chunks and yields decoded packets.
#[derive(Debug, Default)]
pub struct SlipDecoder {
    buffer: Vec<u8>,
    in_escape: bool,
}

impl SlipDecoder {
    /// Creates a new, empty SLIP decoder.
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(1500),
            in_escape: false,
        }
    }

    /// Feeds raw input bytes into the decoder and returns all fully reassembled packets.
    pub fn decode_chunk(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();

        for &b in chunk {
            if self.in_escape {
                match b {
                    SLIP_ESC_END => self.buffer.push(SLIP_END),
                    SLIP_ESC_ESC => self.buffer.push(SLIP_ESC),
                    other => {
                        // Protocol violation: push literal byte
                        self.buffer.push(other);
                    }
                }
                self.in_escape = false;
            } else if b == SLIP_ESC {
                self.in_escape = true;
            } else if b == SLIP_END {
                if !self.buffer.is_empty() {
                    packets.push(std::mem::take(&mut self.buffer));
                    self.buffer.reserve(1500);
                }
            } else {
                self.buffer.push(b);
            }
        }

        packets
    }

    /// Resets decoder state, clearing any uncompleted packet fragments.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.in_escape = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slip_roundtrip() {
        let original = vec![0x45, 0x00, 0xC0, 0xDB, 0x01, 0x02, 0xC0];
        let encoded = slip_encode(&original);

        // First and last bytes must be SLIP_END
        assert_eq!(*encoded.first().unwrap(), SLIP_END);
        assert_eq!(*encoded.last().unwrap(), SLIP_END);

        let mut decoder = SlipDecoder::new();
        let decoded = decoder.decode_chunk(&encoded);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], original);
    }

    #[test]
    fn test_slip_chunked_streaming() {
        let p1 = vec![1, 2, 3, 4, 5];
        let p2 = vec![10, 20, 30, SLIP_END, 40, SLIP_ESC, 50];

        let mut stream = slip_encode(&p1);
        stream.extend(slip_encode(&p2));

        let mut decoder = SlipDecoder::new();
        // Split stream into tiny 3-byte chunks to test streaming reassembly
        let mut packets = Vec::new();
        for chunk in stream.chunks(3) {
            packets.extend(decoder.decode_chunk(chunk));
        }

        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0], p1);
        assert_eq!(packets[1], p2);
    }
}
