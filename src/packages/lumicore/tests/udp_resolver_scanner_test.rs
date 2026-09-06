use std::net::Ipv4Addr;
use lumicore::scanner::udp_resolver_scanner::*;

#[test]
fn test_build_dns_a_query() {
    let txid: u16 = 0xABCD;
    let query = build_dns_a_query("example.com", txid).expect("query build failed");

    // Header checks
    assert_eq!(&query[0..2], &txid.to_be_bytes());
    assert_eq!(&query[2..4], &[0x01, 0x00]); // Standard query + RD
    assert_eq!(&query[4..6], &[0x00, 0x01]); // 1 question
    assert_eq!(&query[6..8], &[0x00, 0x00]); // 0 answers

    // QNAME: 7'example' 3'com' 0
    let mut expected_qname = vec![7];
    expected_qname.extend_from_slice(b"example");
    expected_qname.push(3);
    expected_qname.extend_from_slice(b"com");
    expected_qname.push(0);

    let offset = 12;
    let qname_len = expected_qname.len();
    assert_eq!(&query[offset..offset + qname_len], &expected_qname);

    // QTYPE = 1 (A), QCLASS = 1 (IN)
    assert_eq!(&query[offset + qname_len..offset + qname_len + 4], &[0x00, 0x01, 0x00, 0x01]);
}

#[test]
fn test_is_valid_dns_response() {
    let txid: u16 = 0x4321;
    let expected_ip: Ipv4Addr = "93.184.216.34".parse().unwrap();

    // Construct a synthetic valid response packet
    let mut resp = Vec::new();
    // 1. Transaction ID
    resp.extend_from_slice(&txid.to_be_bytes());
    // 2. Flags: QR=1, AA=0, TC=0, RD=1, RA=1, RCODE=0 -> 0x8180
    resp.extend_from_slice(&[0x81, 0x80]);
    // 3. QDCOUNT: 1
    resp.extend_from_slice(&[0x00, 0x01]);
    // 4. ANCOUNT: 1
    resp.extend_from_slice(&[0x00, 0x01]);
    // 5. NSCOUNT: 0
    resp.extend_from_slice(&[0x00, 0x00]);
    // 6. ARCOUNT: 0
    resp.extend_from_slice(&[0x00, 0x00]);

    // Question section: 7'example' 3'com' 0, type 1, class 1
    resp.extend_from_slice(&[7]);
    resp.extend_from_slice(b"example");
    resp.extend_from_slice(&[3]);
    resp.extend_from_slice(b"com");
    resp.push(0);
    resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    // Answer section using pointer 0xC00C to point to question domain name
    resp.extend_from_slice(&[0xC0, 0x0C]); // Pointer
    resp.extend_from_slice(&[0x00, 0x01]); // Type A
    resp.extend_from_slice(&[0x00, 0x01]); // Class IN
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
    resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
    resp.extend_from_slice(&expected_ip.octets()); // 93.184.216.34

    // Positive case: matching TXID and matching IP
    assert!(is_valid_dns_response(&resp, txid, Some(expected_ip)));
    // Positive case: matching TXID, no strict IP check
    assert!(is_valid_dns_response(&resp, txid, None));

    // Negative case: wrong TXID
    assert!(!is_valid_dns_response(&resp, txid + 1, Some(expected_ip)));

    // Negative case: wrong expected IP
    let wrong_ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
    assert!(!is_valid_dns_response(&resp, txid, Some(wrong_ip)));
}

#[test]
fn test_parse_resolver_entry() {
    // Bracketed tag with explicit port
    let addrs1 = parse_resolver_entry("[IR-MCI] 1.1.1.1:53", &[53, 5353]).unwrap();
    assert_eq!(addrs1.len(), 1);
    assert_eq!(addrs1[0], "1.1.1.1:53".parse().unwrap());

    // Raw IP with default port expansion
    let addrs2 = parse_resolver_entry("8.8.8.8", &[53, 5353]).unwrap();
    assert_eq!(addrs2.len(), 2);
    assert_eq!(addrs2[0], "8.8.8.8:53".parse().unwrap());
    assert_eq!(addrs2[1], "8.8.8.8:5353".parse().unwrap());

    // Comment and empty lines
    assert!(parse_resolver_entry("# commented resolver", &[53]).is_none());
    assert!(parse_resolver_entry("", &[53]).is_none());

    // Invalid domain or string
    assert!(parse_resolver_entry("not_an_ip", &[53]).is_none());
}
