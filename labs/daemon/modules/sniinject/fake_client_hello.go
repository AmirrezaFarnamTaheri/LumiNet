package sniinject

// SNI Injection / Fake ClientHello system.
//
// Source: sni-spoofing-rust-main (https://github.com/b3hnamrjd/sni-spoofing-rust)
//
// Architecture:
//   Client → local TCP listener (listener.rs) → handler.rs → upstream server
//                                   ↓
//                            sniffer/mod.rs (raw packet capture loop)
//
// Mechanism (TCP-level fake ClientHello injection):
//   1. A local TCP proxy accepts the client TLS connection.
//   2. Handler opens an outbound TCP connection to upstream (before the client sends data).
//   3. Sniffer registers the connection's (local_ip, src_port, dst_ip, dst_port).
//   4. Sniffer captures the outbound TCP SYN (records ISN = initial sequence number).
//   5. After the 3-way handshake (SYN → SYN-ACK → ACK), the sniffer captures the
//      3rd ACK (pure ACK, no payload, not injected yet).
//   6. Sniffer builds a FAKE ClientHello packet:
//      - Takes the header bytes from the 3rd ACK frame
//      - Replaces the payload with build_client_hello(fake_sni)
//      - Sets TCP seq = ISN+1 - len(fake_payload)  [so it appears BEFORE the real ClientHello]
//      - Adds PSH flag
//      - Recomputes IP and TCP checksums
//      - Injects (sends) the fake frame via raw socket
//   7. The real ClientHello (with the actual SNI) follows normally.
//   8. Deep packet inspection firewalls see the fake SNI first and (if it matches a
//      whitelisted domain) allow the connection. The real ClientHello may be ignored.
//   9. Sniffer monitors the server's ACK: if it ACKs back to ISN+1 (acknowledging
//      the real data, not the fake), the fake was confirmed ignored.
//
// Scan Module (scan.rs):
//   - Probes a list of SNI candidates against a Cloudflare IP (104.18.4.130:443)
//   - Sends a raw TLS ClientHello (no real TLS handshake) and checks if the response
//     starts with 0x16 (TLS record). If yes, the SNI "works" (DPI allowed it through).
//   - Default: 10 concurrent probes, 6s timeout.
//   - Default Cloudflare probe target: 104.18.4.130:443
//
// ClientHello Template (tls.rs):
//   - Template SNI in hex: "mci.ir" (an Iranian provider domain that passes DPI)
//   - Template is a fixed 517-byte ClientHello with randomized random/session-id/key-share
//   - Padding extension (0x0015) pads to exactly 517 bytes regardless of SNI length
//   - SNI max length: 219 bytes (enforced)
//   - SNI parsed at offset 127 from ClientHello start (after TLS record header + handshake header)
//
// Config (config.rs):
//   - Listeners: listen addr, connect addr (upstream), fake_sni
//   - Timeouts: conn_timeout=5s, handshake_timeout=2s, keepalive_time=11s, keepalive_interval=2s
//   - Default fake SNI: "security.vercel.com"
//   - Default upstream: 172.67.139.236:443 (Cloudflare IP)
//   - Default listen: 127.0.0.1:40443

// SNI-ByPass-main (sni-bypass-installer.sh):
//   SNIProxy-based approach:
//   - Install sniproxy from dlundquist/sniproxy (libpcre2/libev based)
//   - Config: listener 443 {proto tls} with wildcard table (.* → *)
//   - DNS override: dnsmasq (no-resolv, upstream 1.1.1.1+8.8.8.8)
//   - Resolver: nameserver 1.1.1.1, 8.8.8.8, mode ipv4_only
//   This is a server-side SNI reverse proxy (transparent SNI routing).
//   Value: Low — well-known SNIProxy pattern, no novel logic.

// ---------------------------------------------------------------------------
// TLS ClientHello Builder
// Source: sni-spoofing-rust/src/packet/tls.rs
// ---------------------------------------------------------------------------

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const (
	// clientHelloTemplateHex is the fixed TLS 1.3 ClientHello template.
	// Template SNI = "mci.ir" (6 bytes, Iranian telco domain that bypasses DPI).
	// Source: sni-spoofing-rust/src/packet/tls.rs TPL_HEX
	clientHelloTemplateHex = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5"

	// templateSNI is the SNI in the template that gets replaced.
	templateSNI = "mci.ir"

	// ClientHelloSize is the fixed size of all generated ClientHello packets.
	// Source: sni-spoofing-rust/src/packet/tls.rs CLIENT_HELLO_SIZE
	ClientHelloSize = 517

	// MaxSNILength is the maximum SNI length supported by the template format.
	// Source: sni-spoofing-rust/src/packet/tls.rs (assert sni.len() <= 219)
	MaxSNILength = 219

	// DefaultFakeSNI is the default SNI to inject as the "fake" ClientHello.
	// Source: sni-spoofing-rust/src/config.rs ListenerConfig default
	DefaultFakeSNI = "security.vercel.com"

	// DefaultUpstream is the default upstream CDN IP used for SNI spoofing.
	// Source: sni-spoofing-rust/src/config.rs ListenerConfig default
	DefaultUpstream = "172.67.139.236:443"

	// DefaultScanTarget is the Cloudflare IP probed during SNI scanning.
	// Source: sni-spoofing-rust/src/scan.rs DEFAULT_TARGET
	DefaultScanTarget = "104.18.4.130:443"

	// DefaultScanConcurrency is the number of parallel SNI probes.
	// Source: sni-spoofing-rust/src/scan.rs DEFAULT_CONCURRENCY
	DefaultScanConcurrency = 10

	// DefaultScanTimeoutSecs is the per-probe timeout.
	// Source: sni-spoofing-rust/src/scan.rs DEFAULT_TIMEOUT_SECS
	DefaultScanTimeoutSecs = 6
)

// SNI offsets in the 517-byte ClientHello built from the template.
// These are fixed because the template is fixed-size with padding.
// Source: sni-spoofing-rust/src/packet/tls.rs parse_sni() offsets
const (
	// sniLenOffset is the byte offset of the SNI length (2 bytes, big-endian)
	// within the raw ClientHello payload. Offset 125-126.
	sniLenOffset = 125

	// sniDataOffset is the byte offset of the SNI string data. Offset 127.
	sniDataOffset = 127
)

// DefaultListenerConfig holds the default timing config from sni-spoofing-rust.
// Source: sni-spoofing-rust/src/config.rs
type DefaultListenerConfig struct {
	ConnTimeoutSec      int // 5
	HandshakeTimeoutSec int // 2
	KeepaliveTimeSec    int // 11
	KeepaliveIntervalSec int // 2
}

// DefaultTimings returns the default timeout/keepalive values.
func DefaultTimings() DefaultListenerConfig {
	return DefaultListenerConfig{
		ConnTimeoutSec:       5,
		HandshakeTimeoutSec:  2,
		KeepaliveTimeSec:     11,
		KeepaliveIntervalSec: 2,
	}
}

// templateBytes holds the decoded template bytes (loaded once).
var templateBytes []byte

func init() {
	b, err := hex.DecodeString(clientHelloTemplateHex)
	if err != nil {
		panic("sniinject: invalid ClientHello template hex: " + err.Error())
	}
	templateBytes = b
}

// BuildClientHello builds a 517-byte TLS ClientHello with the given SNI.
// The random, session_id, and key_share fields are randomized.
// The SNI field is set to sni, and a padding extension fills the remaining space.
//
// Returns an error if sni is longer than MaxSNILength (219 bytes).
//
// Source: sni-spoofing-rust/src/packet/tls.rs build_client_hello()
func BuildClientHello(sni string) ([]byte, error) {
	sniBytes := []byte(sni)
	if len(sniBytes) > MaxSNILength {
		return nil, fmt.Errorf("sniinject: SNI too long: %d > %d", len(sniBytes), MaxSNILength)
	}

	tpl := templateBytes
	tplSNILen := len(templateSNI)

	// Static sections of the template (matching the Rust offsets):
	// static1: bytes [0, 11)   — TLS record header + handshake header fragment
	// static3: bytes [76, 120) — cipher suites + compression + extensions header
	// static4: bytes [127+tplSNILen, 262+tplSNILen) — extensions after SNI + key share prefix
	static1 := tpl[0:11]
	static3 := tpl[76:120]
	static4 := tpl[127+tplSNILen : 262+tplSNILen]

	// Generate random bytes
	random := make([]byte, 32)
	sessID := make([]byte, 32)
	keyShare := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, fmt.Errorf("sniinject: rand.Read: %w", err)
	}
	if _, err := rand.Read(sessID); err != nil {
		return nil, fmt.Errorf("sniinject: rand.Read sessID: %w", err)
	}
	if _, err := rand.Read(keyShare); err != nil {
		return nil, fmt.Errorf("sniinject: rand.Read keyShare: %w", err)
	}

	padLen := MaxSNILength - len(sniBytes)
	out := make([]byte, 0, ClientHelloSize)

	// Assembly: static1 + random(32) + 0x20 + sessID(32) + static3
	out = append(out, static1...)
	out = append(out, random...)
	out = append(out, 0x20)
	out = append(out, sessID...)
	out = append(out, static3...)

	// SNI extension:
	// [sni_ext_len(2)] [sni_list_len(2)] [0x00] [sni_len(2)] [sni_bytes]
	sniExtLen := uint16(len(sniBytes) + 5)
	sniListLen := uint16(len(sniBytes) + 3)
	sniLen := uint16(len(sniBytes))
	out = append(out, byte(sniExtLen>>8), byte(sniExtLen))
	out = append(out, byte(sniListLen>>8), byte(sniListLen))
	out = append(out, 0x00)
	out = append(out, byte(sniLen>>8), byte(sniLen))
	out = append(out, sniBytes...)

	// static4 + key_share(32)
	out = append(out, static4...)
	out = append(out, keyShare...)

	// Padding extension (type 0x0015):
	// [0x00, 0x15] [pad_len(2)] [0x00 * pad_len]
	out = append(out, 0x00, 0x15)
	out = append(out, byte(padLen>>8), byte(padLen))
	out = append(out, make([]byte, padLen)...)

	if len(out) != ClientHelloSize {
		return nil, fmt.Errorf("sniinject: ClientHello size mismatch: got %d, want %d", len(out), ClientHelloSize)
	}
	return out, nil
}

// ParseSNI extracts the SNI from a 517-byte ClientHello built by BuildClientHello.
// Returns empty string if the data is too short or the SNI is not valid UTF-8.
//
// Source: sni-spoofing-rust/src/packet/tls.rs parse_sni()
func ParseSNI(clientHello []byte) string {
	if len(clientHello) < ClientHelloSize {
		return ""
	}
	sniLen := int(uint16(clientHello[sniLenOffset])<<8 | uint16(clientHello[sniLenOffset+1]))
	end := sniDataOffset + sniLen
	if end > len(clientHello) {
		return ""
	}
	return string(clientHello[sniDataOffset:end])
}

// IsTLSServerHello returns true if the 5-byte prefix indicates a TLS record
// (response type 0x16 = handshake). Used by the scan probe to detect success.
//
// Source: sni-spoofing-rust/src/scan.rs probe_sni() check buf[0] == 0x16
func IsTLSServerHello(prefix []byte) bool {
	return len(prefix) >= 1 && prefix[0] == 0x16
}

// ---------------------------------------------------------------------------
// TCP Packet Injection — Fake Frame Construction
// Source: sni-spoofing-rust/src/sniffer/mod.rs build_fake_frame()
// ---------------------------------------------------------------------------

// FakeClientHelloSeq computes the TCP sequence number for the injected fake
// ClientHello, given the connection's ISN (initial sequence number) and the
// length of the fake payload.
//
// The fake frame is sent with seq = ISN+1 - len(fakePayload), so it appears
// in the TCP stream before the real ClientHello (which starts at ISN+1).
// This tricks DPI into seeing the fake SNI first.
//
// Source: sni-spoofing-rust/src/sniffer/mod.rs
//   fake_seq = isn.wrapping_add(1).wrapping_sub(fake_payload.len() as u32)
func FakeClientHelloSeq(isn uint32, fakePayloadLen int) uint32 {
	return isn + 1 - uint32(fakePayloadLen)
}

// SNISpoofConnID uniquely identifies an outbound TCP connection being monitored
// by the raw sniffer, by 4-tuple.
// Source: sni-spoofing-rust/src/proto.rs ConnId
type SNISpoofConnID struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// SNISpoofConfig is the per-listener configuration for SNI injection.
// Source: sni-spoofing-rust/src/config.rs ListenerConfig
type SNISpoofConfig struct {
	// ListenAddr is the local address to accept client connections on.
	ListenAddr string

	// ConnectAddr is the upstream server address to forward to.
	ConnectAddr string

	// FakeSNI is the SNI injected as the fake ClientHello before the real one.
	// Must be <= 219 bytes.
	FakeSNI string

	// ConnTimeoutSec is the dial timeout to the upstream server.
	ConnTimeoutSec int

	// HandshakeTimeoutSec is the timeout waiting for the sniffer to confirm
	// that the fake ClientHello was processed (i.e. the server sent an ACK
	// that confirms it was ignored / accepted).
	HandshakeTimeoutSec int

	// KeepaliveTimeSec is the TCP keepalive idle time.
	KeepaliveTimeSec int

	// KeepaliveIntervalSec is the TCP keepalive probe interval.
	KeepaliveIntervalSec int
}

// DefaultSNISpoofConfig returns the sni-spoofing-rust default config values.
func DefaultSNISpoofConfig() SNISpoofConfig {
	return SNISpoofConfig{
		ListenAddr:           "127.0.0.1:40443",
		ConnectAddr:          DefaultUpstream,
		FakeSNI:              DefaultFakeSNI,
		ConnTimeoutSec:       5,
		HandshakeTimeoutSec:  2,
		KeepaliveTimeSec:     11,
		KeepaliveIntervalSec: 2,
	}
}

// SNISpoofProbeOutcome describes the result of a single SNI probe.
// Source: sni-spoofing-rust/src/scan.rs ProbeOutcome
type SNISpoofProbeOutcome int

const (
	SNISpoofProbeOK SNISpoofProbeOutcome = iota
	SNISpoofProbeConnectFailed
	SNISpoofProbeConnectTimeout
	SNISpoofProbeHandshakeFailed
	SNISpoofProbeReadTimeout
	SNISpoofProbeBadResponse
	SNISpoofProbeEmptyResponse
)

// SNIBypassSNIProxyConfig is the sniproxy config from SNI-ByPass-main.
// SNIProxy routes incoming TLS connections by reading the SNI (no decryption)
// and forwarding to the matching backend.
// Source: SNI-ByPass-main/sni-bypass-installer.sh /etc/sniproxy.conf
type SNIBypassSNIProxyConfig struct {
	// DNS resolvers used by sniproxy to resolve upstream hostnames.
	// Default: ["1.1.1.1", "8.8.8.8"]
	Nameservers []string

	// Mode: "ipv4_only" prevents sniproxy from using IPv6.
	Mode string

	// Port is the listening port for TLS SNI routing.
	// Default: 443
	Port int

	// Table maps SNI patterns to backend addresses. ".*" → "*" = wildcard passthrough.
	Table map[string]string
}

// DefaultSNIBypassProxyConfig returns the SNI-ByPass-main sniproxy config.
func DefaultSNIBypassProxyConfig() SNIBypassSNIProxyConfig {
	return SNIBypassSNIProxyConfig{
		Nameservers: []string{"1.1.1.1", "8.8.8.8"},
		Mode:        "ipv4_only",
		Port:        443,
		Table:       map[string]string{".*": "*"}, // wildcard: pass all SNIs through
	}
}
