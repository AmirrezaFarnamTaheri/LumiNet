use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Parses raw ClientHello bytes and returns the SNI host name if present.
pub fn read_sni_host_name_from_client_hello(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    // Record type 22 (Handshake)
    if data[0] != 0x16 {
        return None;
    }
    let record_len = ((data[3] as usize) << 8) | (data[4] as usize);
    if data.len() < 5 + record_len {
        return None;
    }

    let handshake = &data[5..5 + record_len];
    if handshake.is_empty() || handshake[0] != 0x01 {
        // Not ClientHello
        return None;
    }

    let mut pos = 38; // Skip type (1), len (3), version (2), random (32)
    if handshake.len() < pos + 1 {
        return None;
    }

    // Session ID
    let session_id_len = handshake[pos] as usize;
    pos += 1 + session_id_len;

    if handshake.len() < pos + 2 {
        return None;
    }

    // Cipher Suites
    let cipher_suites_len = ((handshake[pos] as usize) << 8) | (handshake[pos + 1] as usize);
    pos += 2 + cipher_suites_len;

    if handshake.len() < pos + 1 {
        return None;
    }

    // Compression Methods
    let comp_methods_len = handshake[pos] as usize;
    pos += 1 + comp_methods_len;

    if handshake.len() < pos + 2 {
        return None;
    }

    // Extensions
    let extensions_len = ((handshake[pos] as usize) << 8) | (handshake[pos + 1] as usize);
    pos += 2;
    let extensions_end = pos + extensions_len;

    if handshake.len() < extensions_end {
        return None;
    }

    while pos + 4 <= extensions_end {
        let ext_type = ((handshake[pos] as u16) << 8) | (handshake[pos + 1] as u16);
        let ext_len = ((handshake[pos + 2] as usize) << 8) | (handshake[pos + 3] as usize);
        pos += 4;

        if pos + ext_len > extensions_end {
            break;
        }

        if ext_type == 0 {
            // SNI Extension
            let mut sni_pos = pos;
            if sni_pos + 2 > pos + ext_len {
                break;
            }
            let list_len = ((handshake[sni_pos] as usize) << 8) | (handshake[sni_pos + 1] as usize);
            sni_pos += 2;

            if sni_pos + list_len > pos + ext_len {
                break;
            }

            while sni_pos + 3 <= pos + ext_len {
                let name_type = handshake[sni_pos];
                let name_len =
                    ((handshake[sni_pos + 1] as usize) << 8) | (handshake[sni_pos + 2] as usize);
                sni_pos += 3;

                if sni_pos + name_len > pos + ext_len {
                    break;
                }

                if name_type == 0 {
                    // Host Name
                    let host_bytes = &handshake[sni_pos..sni_pos + name_len];
                    return String::from_utf8(host_bytes.to_vec()).ok();
                }
                sni_pos += name_len;
            }
        }
        pos += ext_len;
    }

    None
}

/// A reader wrapper that records all read bytes into an internal buffer.
pub struct RecordingBufReader<R> {
    inner: R,
    buffer: Vec<u8>,
    recording: bool,
}

impl<R> RecordingBufReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            recording: true,
        }
    }

    pub fn recorded_bytes(&self) -> &[u8] {
        &self.buffer
    }

    pub fn stop_recording(&mut self) {
        self.recording = false;
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for RecordingBufReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before_len = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            let after_len = buf.filled().len();
            if after_len > before_len && self.recording {
                let added = &buf.filled()[before_len..after_len];
                self.buffer.extend_from_slice(added);
            }
        }
        res
    }
}

/// A stream wrapper that prepends prefix bytes before delegating to the underlying stream.
pub struct PrefixedReaderWriter<S> {
    inner: S,
    prefix: Vec<u8>,
    prefix_pos: usize,
}

impl<S> PrefixedReaderWriter<S> {
    pub fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            prefix_pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedReaderWriter<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix_pos < self.prefix.len() {
            let rem = &self.prefix[self.prefix_pos..];
            let to_write = std::cmp::min(rem.len(), buf.remaining());
            buf.put_slice(&rem[..to_write]);
            self.prefix_pos += to_write;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedReaderWriter<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn test_sni_parsing_mock_client_hello() {
        // Minimal ClientHello containing SNI extension for "example.com"
        let mock_client_hello: &[u8] = &[
            0x16, // Handshake
            0x03, 0x03, // Version
            0x00, 0x3d, // Length
            // Handshake Protocol: Client Hello
            0x01, 0x00, 0x00, 0x39, // Handshake Length
            0x03, 0x03, // TLS 1.2
            // Random (32 bytes)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0x00, // Session ID Length
            0x00, 0x02, 0x00, 0x2f, // Cipher Suites Length and Suite
            0x01, 0x00, // Compression Methods Length and Method
            // Extensions Length
            0x00, 0x0e, // Extension: Server Name
            0x00, 0x00, // Type
            0x00, 0x0a, // Length
            0x00, 0x08, // Server Name List Length
            0x00, // Server Name Type (Host Name)
            0x00, 0x05, // Host Name Length
            b'e', b'x', b'a', b'm', b'p',
        ];

        let host = read_sni_host_name_from_client_hello(mock_client_hello);
        assert_eq!(host, Some("examp".to_string()));
    }

    #[tokio::test]
    async fn test_recording_buf_reader() {
        let input = b"recorded-payload";
        let mut reader = RecordingBufReader::new(&input[..]);
        let mut out = vec![0u8; 8];
        reader.read_exact(&mut out).await.unwrap();
        assert_eq!(reader.recorded_bytes(), b"recorded");

        // Stop recording
        reader.stop_recording();
        let mut out2 = vec![0u8; 8];
        reader.read_exact(&mut out2).await.unwrap();
        // recorded bytes should remain unchanged
        assert_eq!(reader.recorded_bytes(), b"recorded");
    }

    #[tokio::test]
    async fn test_prefixed_reader_writer() {
        let underlying = b"-suffix";
        let prefix = b"prefix-".to_vec();
        let mut reader = PrefixedReaderWriter::new(&underlying[..], prefix);

        let mut out = String::new();
        reader.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "prefix--suffix");
    }
}
