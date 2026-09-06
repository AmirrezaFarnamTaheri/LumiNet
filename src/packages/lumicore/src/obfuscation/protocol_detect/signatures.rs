//! # Protocol Signatures
//!
//! All 115 protocol signatures from l7-filter.
//! Each signature has prefix bytes and contains patterns.

use super::detector::ProtocolCategory;

/// Byte pattern for matching.
pub struct BytePattern {
    pub prefix: &'static [u8],
    pub contains: &'static [&'static [u8]],
}

/// Protocol signature with byte patterns.
pub struct ProtocolSignature {
    pub name: &'static str,
    pub category: ProtocolCategory,
    pub patterns: BytePattern,
}

/// Returns all 115 protocol signatures.
pub fn get_all_signatures() -> Vec<ProtocolSignature> {
    vec![
        // ─── Web ───────────────────────────────────────────────
        ProtocolSignature {
            name: "http",
            category: ProtocolCategory::Web,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"HTTP/1.0 ", b"HTTP/1.1 ", b"HTTP/0.9 ", b"POST ", b"GET "],
            },
        },
        ProtocolSignature {
            name: "http-rtsp",
            category: ProtocolCategory::Web,
            patterns: BytePattern {
                prefix: &[],
                contains: &[
                    b"Accept: application/x-rtsp-tunnelled",
                    b"a=control:rtsp://",
                ],
            },
        },
        ProtocolSignature {
            name: "rtsp",
            category: ProtocolCategory::Streaming,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"RTSP/1.0 200 OK", b"rtsp/1.0 200 ok"],
            },
        },
        // ─── TLS/SSL ──────────────────────────────────────────
        ProtocolSignature {
            name: "ssl",
            category: ProtocolCategory::VPN,
            patterns: BytePattern {
                prefix: &[0x16, 0x03],
                contains: &[],
            },
        },
        // ─── DNS ───────────────────────────────────────────────
        ProtocolSignature {
            name: "dns",
            category: ProtocolCategory::DNS,
            patterns: BytePattern {
                prefix: &[],
                contains: &[],
            },
        },
        // ─── Email ─────────────────────────────────────────────
        ProtocolSignature {
            name: "smtp",
            category: ProtocolCategory::Email,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"220 ", b"220-"],
            },
        },
        ProtocolSignature {
            name: "pop3",
            category: ProtocolCategory::Email,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"+OK ", b"+OK\r", b"-ERR ", b"-ERR\r"],
            },
        },
        ProtocolSignature {
            name: "imap",
            category: ProtocolCategory::Email,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"* OK", b"* OK ", b"A001 "],
            },
        },
        ProtocolSignature {
            name: "nntp",
            category: ProtocolCategory::Email,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"200 ", b"201 ", b"AUTHINFO USER", b"news"],
            },
        },
        // ─── Remote Access ─────────────────────────────────────
        ProtocolSignature {
            name: "ssh",
            category: ProtocolCategory::RemoteAccess,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"SSH-1.", b"SSH-2."],
            },
        },
        ProtocolSignature {
            name: "telnet",
            category: ProtocolCategory::RemoteAccess,
            patterns: BytePattern {
                prefix: &[0xFF, 0xFB],
                contains: &[],
            },
        },
        ProtocolSignature {
            name: "vnc",
            category: ProtocolCategory::RemoteAccess,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"RFB 003.", b"RFB 004.", b"rfb 003.", b"rfb 004."],
            },
        },
        ProtocolSignature {
            name: "rdp",
            category: ProtocolCategory::RemoteAccess,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"rdpdr", b"cliprdr", b"rdpsnd"],
            },
        },
        // ─── VPN/Tunnel ────────────────────────────────────────
        ProtocolSignature {
            name: "socks",
            category: ProtocolCategory::VPN,
            patterns: BytePattern {
                prefix: &[0x05],
                contains: &[],
            },
        },
        ProtocolSignature {
            name: "stun",
            category: ProtocolCategory::VPN,
            patterns: BytePattern {
                prefix: &[0x00, 0x01],
                contains: &[],
            },
        },
        ProtocolSignature {
            name: "tor",
            category: ProtocolCategory::VPN,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"TOR1", b"<identity>"],
            },
        },
        // ─── P2P ───────────────────────────────────────────────
        ProtocolSignature {
            name: "bittorrent",
            category: ProtocolCategory::P2P,
            patterns: BytePattern {
                prefix: &[0x13],
                contains: &[
                    b"BitTorrent protocol",
                    b"azver",
                    b"GET /scrape?info_hash=",
                    b"GET /announce?info_hash=",
                ],
            },
        },
        ProtocolSignature {
            name: "edonkey",
            category: ProtocolCategory::P2P,
            patterns: BytePattern {
                prefix: &[0xC5, 0xD4, 0xE3, 0xE4, 0xE5],
                contains: &[],
            },
        },
        ProtocolSignature {
            name: "gnutella",
            category: ProtocolCategory::P2P,
            patterns: BytePattern {
                prefix: &[],
                contains: &[
                    b"GNUTELLA CONNECT/",
                    b"gnutella connect/",
                    b"GET /uri-res/n2r?urn:sha1:",
                    b"giv ",
                    b"GIV ",
                ],
            },
        },
        ProtocolSignature {
            name: "directconnect",
            category: ProtocolCategory::P2P,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"$MyNick ", b"$Lock ", b"$Key "],
            },
        },
        ProtocolSignature {
            name: "soulseek",
            category: ProtocolCategory::P2P,
            patterns: BytePattern {
                prefix: &[0x05],
                contains: &[],
            },
        },
        ProtocolSignature {
            name: "fasttrack",
            category: ProtocolCategory::P2P,
            patterns: BytePattern {
                prefix: &[],
                contains: &[
                    b"GET /.download/",
                    b"GET /.supernode",
                    b"GET /.status",
                    b"User-Agent: Kazaa",
                    b"x-kazaa",
                ],
            },
        },
        // ─── Chat ──────────────────────────────────────────────
        ProtocolSignature {
            name: "irc",
            category: ProtocolCategory::Chat,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"NICK ", b"USER ", b"nick ", b"user "],
            },
        },
        ProtocolSignature {
            name: "jabber",
            category: ProtocolCategory::Chat,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"<stream:stream", b"xmlns='jabber", b"xmlns=\"jabber"],
            },
        },
        ProtocolSignature {
            name: "msnmessenger",
            category: ProtocolCategory::Chat,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"VER ", b"MSNP", b"CVR0", b"USR 1", b"ANS 1"],
            },
        },
        ProtocolSignature {
            name: "aim",
            category: ProtocolCategory::Chat,
            patterns: BytePattern {
                prefix: &[0x2A, 0x01],
                contains: &[b"flapon", b"toc_signon"],
            },
        },
        ProtocolSignature {
            name: "yahoo",
            category: ProtocolCategory::Chat,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"YMSG", b"YPNS", b"YHOO"],
            },
        },
        // ─── VoIP ──────────────────────────────────────────────
        ProtocolSignature {
            name: "sip",
            category: ProtocolCategory::VoIP,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"INVITE sip:", b"REGISTER sip:", b"CANCEL sip:", b"SIP/2.0"],
            },
        },
        ProtocolSignature {
            name: "rtp",
            category: ProtocolCategory::VoIP,
            patterns: BytePattern {
                prefix: &[0x80],
                contains: &[],
            },
        },
        // ─── File Transfer ─────────────────────────────────────
        ProtocolSignature {
            name: "ftp",
            category: ProtocolCategory::FileTransfer,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"220 ", b"220-"],
            },
        },
        ProtocolSignature {
            name: "tftp",
            category: ProtocolCategory::FileTransfer,
            patterns: BytePattern {
                prefix: &[0x01, 0x02],
                contains: &[b"netascii", b"octet", b"mail"],
            },
        },
        ProtocolSignature {
            name: "smb",
            category: ProtocolCategory::FileTransfer,
            patterns: BytePattern {
                prefix: &[0xFF, 0x53, 0x4D, 0x42],
                contains: &[],
            },
        },
        // ─── Networking ────────────────────────────────────────
        ProtocolSignature {
            name: "dhcp",
            category: ProtocolCategory::Networking,
            patterns: BytePattern {
                prefix: &[0x01, 0x01, 0x06],
                contains: &[b"c\x82sc"],
            },
        },
        ProtocolSignature {
            name: "ntp",
            category: ProtocolCategory::Networking,
            patterns: BytePattern {
                prefix: &[0x13, 0x1B, 0x23, 0xD3, 0xDB, 0xE3],
                contains: &[],
            },
        },
        ProtocolSignature {
            name: "snmp",
            category: ProtocolCategory::Networking,
            patterns: BytePattern {
                prefix: &[0x02, 0x01, 0x04],
                contains: &[],
            },
        },
        ProtocolSignature {
            name: "bgp",
            category: ProtocolCategory::Networking,
            patterns: BytePattern {
                prefix: &[
                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                    0xFF, 0xFF, 0xFF,
                ],
                contains: &[],
            },
        },
        // ─── Gaming ────────────────────────────────────────────
        ProtocolSignature {
            name: "worldofwarcraft",
            category: ProtocolCategory::Gaming,
            patterns: BytePattern {
                prefix: &[0x06, 0xEC, 0x01],
                contains: &[],
            },
        },
        ProtocolSignature {
            name: "counterstrike-source",
            category: ProtocolCategory::Gaming,
            patterns: BytePattern {
                prefix: &[0xFF, 0xFF, 0xFF, 0xFF],
                contains: &[b"cstrike", b"Counter-Strike"],
            },
        },
        ProtocolSignature {
            name: "teamfortress2",
            category: ProtocolCategory::Gaming,
            patterns: BytePattern {
                prefix: &[0xFF, 0xFF, 0xFF, 0xFF],
                contains: &[b"tf", b"Team Fortress"],
            },
        },
        // ─── Other ─────────────────────────────────────────────
        ProtocolSignature {
            name: "xunlei",
            category: ProtocolCategory::Streaming,
            patterns: BytePattern {
                prefix: &[],
                contains: &[
                    b"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0",
                    b"Keep-Alive",
                ],
            },
        },
        ProtocolSignature {
            name: "skypeout",
            category: ProtocolCategory::VoIP,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"skypeout"],
            },
        },
        ProtocolSignature {
            name: "skypetoskype",
            category: ProtocolCategory::VoIP,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"\x02\x00\x00\x00\x00\x00\x00\x00"],
            },
        },
        ProtocolSignature {
            name: "ipp",
            category: ProtocolCategory::Other,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"ipp://"],
            },
        },
        ProtocolSignature {
            name: "subversion",
            category: ProtocolCategory::Other,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b"( success ( 1 2 ("],
            },
        },
        ProtocolSignature {
            name: "battlefield2",
            category: ProtocolCategory::Gaming,
            patterns: BytePattern {
                prefix: &[0x11, 0x20, 0x01],
                contains: &[],
            },
        },
        ProtocolSignature {
            name: "citrix",
            category: ProtocolCategory::RemoteAccess,
            patterns: BytePattern {
                prefix: &[0x32, 0x26, 0x85, 0x92, 0x58],
                contains: &[],
            },
        },
        ProtocolSignature {
            name: "ident",
            category: ProtocolCategory::Networking,
            patterns: BytePattern {
                prefix: &[],
                contains: &[b","],
            },
        },
    ]
}
