const TLS_HANDSHAKE: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const SNI_HOST_NAME: u8 = 0x00;

const MAX_HOST_LEN: usize = 253;
pub const PEEK_BUDGET: usize = 4096;

fn be16(buf: &[u8], at: usize) -> Option<usize> {
    let hi = *buf.get(at)? as usize;
    let lo = *buf.get(at + 1)? as usize;
    Some((hi << 8) | lo)
}

fn be24(buf: &[u8], at: usize) -> Option<usize> {
    let a = *buf.get(at)? as usize;
    let b = *buf.get(at + 1)? as usize;
    let c = *buf.get(at + 2)? as usize;
    Some((a << 16) | (b << 8) | c)
}

fn plausible_host(raw: &[u8]) -> Option<String> {
    if raw.is_empty() || raw.len() > MAX_HOST_LEN {
        return None;
    }

    let name = std::str::from_utf8(raw).ok()?.trim().trim_end_matches('.');
    if name.is_empty() || name.len() > MAX_HOST_LEN {
        return None;
    }

    let allowed = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
    if !allowed || !name.contains('.') {
        return None;
    }

    if name.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    Some(name.to_lowercase())
}

/// Parses the Server Name Indication (SNI) from a raw TLS ClientHello payload.
pub fn tls_sni(buf: &[u8]) -> Option<String> {
    if *buf.first()? != TLS_HANDSHAKE {
        return None;
    }

    let record_len = be16(buf, 3)?;
    let record_end = 5usize.checked_add(record_len)?.min(buf.len());

    let body = buf.get(5..record_end)?;
    if *body.first()? != TLS_CLIENT_HELLO {
        return None;
    }

    let hello_len = be24(body, 1)?;
    let hello_end = 4usize.checked_add(hello_len)?.min(body.len());
    let hello = body.get(4..hello_end)?;

    let mut at = 2 + 32;

    let session_len = *hello.get(at)? as usize;
    at = at.checked_add(1 + session_len)?;

    let cipher_len = be16(hello, at)?;
    at = at.checked_add(2 + cipher_len)?;

    let compression_len = *hello.get(at)? as usize;
    at = at.checked_add(1 + compression_len)?;

    let extensions_len = be16(hello, at)?;
    at = at.checked_add(2)?;
    let extensions_end = at.checked_add(extensions_len)?.min(hello.len());

    while at + 4 <= extensions_end {
        let kind = be16(hello, at)? as u16;
        let len = be16(hello, at + 2)?;
        let data_start = at + 4;
        let data_end = data_start.checked_add(len)?;
        if data_end > extensions_end {
            return None;
        }

        if kind == EXT_SERVER_NAME {
            let data = hello.get(data_start..data_end)?;
            return first_server_name(data);
        }

        at = data_end;
    }

    None
}

fn first_server_name(data: &[u8]) -> Option<String> {
    let list_len = be16(data, 0)?;
    let list_end = 2usize.checked_add(list_len)?.min(data.len());

    let mut at = 2usize;
    while at + 3 <= list_end {
        let kind = *data.get(at)?;
        let len = be16(data, at + 1)?;
        let start = at + 3;
        let end = start.checked_add(len)?;
        if end > list_end {
            return None;
        }

        if kind == SNI_HOST_NAME {
            return plausible_host(data.get(start..end)?);
        }

        at = end;
    }

    None
}

/// Extracts the target hostname from an HTTP/1.x plaintext request header.
pub fn http_host(buf: &[u8]) -> Option<String> {
    let head_end = buf.len().min(PEEK_BUDGET);
    let head = buf.get(..head_end)?;

    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");

    let request_line = lines.next()?;
    if !looks_like_http(request_line) {
        return None;
    }

    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = match line.split_once(':') {
            Some(pair) => pair,
            None => continue,
        };
        if !name.eq_ignore_ascii_case("host") {
            continue;
        }

        let value = value.trim();
        let without_port = match value.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
            _ => value,
        };
        return plausible_host(without_port.as_bytes());
    }

    None
}

fn looks_like_http(line: &str) -> bool {
    const METHODS: [&str; 9] = [
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
    ];
    METHODS.iter().any(|method| line.starts_with(method)) && line.contains("HTTP/")
}

/// Sniffs destination hostname from connection buffer (TLS SNI or HTTP Host).
pub fn sniff_hostname(buf: &[u8]) -> Option<String> {
    tls_sni(buf).or_else(|| http_host(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_host_extraction() {
        let request = b"GET /index.html HTTP/1.1\r\nHost: api.cloudflare.com:443\r\nUser-Agent: test\r\n\r\n";
        assert_eq!(http_host(request).as_deref(), Some("api.cloudflare.com"));
        assert_eq!(sniff_hostname(request).as_deref(), Some("api.cloudflare.com"));
    }

    #[test]
    fn test_non_http_rejected() {
        let junk = b"\x00\x01\x02\x03\x04";
        assert_eq!(http_host(junk), None);
    }
}
