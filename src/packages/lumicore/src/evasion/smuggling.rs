//! # HTTP Request Smuggling
//!
//! HTTP smuggling techniques for DPI bypass.

/// HTTP smuggling technique.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HttpSmuggling {
    ContentLength,
    TransferEncoding,
    ClTe,
    TeCl,
    DoubleContentLength,
    TransferEncodingWhitespace,
    TransferEncodingCase,
    NegativeContentLength,
    LeadingZerosContentLength,
    TransferEncodingChunkExtension,
}

/// Applies HTTP smuggling technique to a request.
pub fn apply_smuggling(method: &str, path: &str, host: &str, technique: HttpSmuggling) -> String {
    match technique {
        HttpSmuggling::ContentLength => {
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n")
        }
        HttpSmuggling::TransferEncoding => {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
        }
        HttpSmuggling::ClTe => {
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n")
        }
        HttpSmuggling::TeCl => {
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n")
        }
        HttpSmuggling::DoubleContentLength => {
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n")
        }
        HttpSmuggling::TransferEncodingWhitespace => {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding : chunked\r\n\r\n"
            )
        }
        HttpSmuggling::TransferEncodingCase => {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {host}\r\ntransfer-encoding: chunked\r\n\r\n"
            )
        }
        HttpSmuggling::NegativeContentLength => {
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: -1\r\n\r\n")
        }
        HttpSmuggling::LeadingZerosContentLength => {
            format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 00000\r\n\r\n")
        }
        HttpSmuggling::TransferEncodingChunkExtension => {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smuggling_techniques() {
        let techniques = vec![
            HttpSmuggling::ContentLength,
            HttpSmuggling::TransferEncoding,
            HttpSmuggling::ClTe,
            HttpSmuggling::TeCl,
        ];
        for t in techniques {
            let result = apply_smuggling("GET", "/", "example.com", t);
            assert!(result.contains("HTTP/1.1"));
            assert!(result.contains("Host: example.com"));
        }
    }
}
