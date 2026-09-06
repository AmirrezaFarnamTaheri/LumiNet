use std::io::{self, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct TLSFragmentation {
    pub active: bool,
    pub chunk_size: usize,
    pub delay_ms: u64,
}

impl TLSFragmentation {
    pub fn new(chunk_size: usize, delay_ms: u64) -> Self {
        TLSFragmentation {
            active: true,
            chunk_size,
            delay_ms,
        }
    }

    /// Finds the SNI offset in a TLS ClientHello
    fn find_sni_offset(data: &[u8]) -> Option<usize> {
        if data.len() < 43 || data[0] != 0x16 || data[5] != 0x01 {
            return None;
        }
        let session_id_len = data[43] as usize;
        let mut pos = 44 + session_id_len;
        if pos + 2 > data.len() {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;
        if pos + 1 > data.len() {
            return None;
        }
        let comp_methods_len = data[pos] as usize;
        pos += 1 + comp_methods_len;
        if pos + 2 > data.len() {
            return None;
        }
        let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos + ext_len;
        while pos + 4 <= ext_end && pos + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_size = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;
            if ext_type == 0 {
                return Some(pos);
            }
            pos += ext_size;
        }
        None
    }

    /// Splits the ClientHello at the SNI boundary
    pub fn fragment_and_send(&self, stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
        if !self.active || payload.is_empty() {
            stream.write_all(payload)?;
            return stream.flush();
        }

        let mut split_point = payload.len() / 2;
        if let Some(sni_offset) = Self::find_sni_offset(payload) {
            split_point = sni_offset;
        }

        if split_point > 0 && split_point < payload.len() {
            stream.write_all(&payload[..split_point])?;
            stream.flush()?;
            if self.delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(self.delay_ms));
            }
            stream.write_all(&payload[split_point..])?;
            stream.flush()?;
        } else {
            let mut offset = 0;
            while offset < payload.len() {
                let end = std::cmp::min(offset + self.chunk_size, payload.len());
                stream.write_all(&payload[offset..end])?;
                stream.flush()?;
                if self.delay_ms > 0 && end < payload.len() {
                    std::thread::sleep(Duration::from_millis(self.delay_ms));
                }
                offset = end;
            }
        }
        Ok(())
    }
}
