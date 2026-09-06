// SPDX-License-Identifier: MIT
// C5.1b — TLSMiddlebox: clean-room OONI tlsmiddlebox port.
// Sends malformed TLS ClientHello messages and inspects server responses
// to detect transparent TLS proxies / middleboxes. Based on the OONI
// tlsmiddlebox methodology of testing for connection tampering and
// TLS-layer anomalies.
// MIT License — no OONI source code copied.

package diagnostics

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// MiddleboxFinding classifies the outcome of a single middlebox probe.
type MiddleboxFinding string

const (
	// MiddleboxNotFound means the server responded normally without signs of filtering.
	MiddleboxNotFound MiddleboxFinding = "middlebox_not_found"
	// MiddleboxConnectionReset means the connection was reset after ClientHello.
	MiddleboxConnectionReset MiddleboxFinding = "connection_reset"
	// MiddleboxTimeout means the connection timed out (possible filtering).
	MiddleboxTimeout MiddleboxFinding = "timeout"
	// MiddleboxTimeoutAfterHello means the server read our ClientHello and then timed out.
	MiddleboxTimeoutAfterHello MiddleboxFinding = "timeout_after_hello"
	// MiddleboxUnexpectedEOF means the connection closed after our ClientHello.
	MiddleboxUnexpectedEOF MiddleboxFinding = "unexpected_eof"
	// MiddleboxBadCertificate means the server returned an unexpected certificate.
	MiddleboxBadCertificate MiddleboxFinding = "bad_certificate"
	// MiddleboxVersionMismatch means the server rejected our TLS version.
	MiddleboxVersionMismatch MiddleboxFinding = "version_mismatch"
	// MiddleboxSanityCheckFailed means the probe's sanity check also failed.
	MiddleboxSanityCheckFailed MiddleboxFinding = "sanity_check_failed"
	// MiddleboxProbeError means the probe itself could not be completed.
	MiddleboxProbeError MiddleboxFinding = "probe_error"
)

// MiddleboxReport is the result of probing a single target for TLS middlebox presence.
type MiddleboxReport struct {
	Target       string            `json:"target"`
	Finding      MiddleboxFinding  `json:"finding"`
	SNI          string            `json:"sni"`
	TLSVersion   string            `json:"tls_version,omitempty"`
	CipherSuite  uint16            `json:"cipher_suite,omitempty"`
	Elapsed      time.Duration     `json:"elapsed"`
	Failure      string            `json:"failure,omitempty"`
	ProbeDetails []string          `json:"probe_details"`
}

// TLSMiddlebox probes targets for evidence of transparent TLS proxies.
// It sends a series of malformed and normal ClientHello messages and
// classifies the response patterns against the OONI tlsmiddlebox taxonomy.
type TLSMiddlebox struct {
	timeout time.Duration
}

// NewTLSMiddlebox creates a new TLS middlebox probe with the given timeout.
func NewTLSMiddlebox(timeout time.Duration) *TLSMiddlebox {
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	return &TLSMiddlebox{timeout: timeout}
}

// Probe sends a structured TLS middlebox probe to the given target address
// (host:port) using the provided SNI. It performs a sanity check (normal
// ClientHello) and then a series of malformed probes, classifying the
// response patterns.
func (m *TLSMiddlebox) Probe(ctx context.Context, target, sni string) MiddleboxReport {
	start := time.Now()
	report := MiddleboxReport{
		Target:       target,
		SNI:          sni,
		ProbeDetails: []string{},
	}

	// Sanity check: normal ClientHello
	sanity := m.probeClientHello(ctx, target, sni, buildNormalClientHello)
	if sanity.finding != MiddleboxNotFound {
		report.Finding = MiddleboxSanityCheckFailed
		report.Failure = fmt.Sprintf("sanity: %s", sanity.finding)
		report.Elapsed = time.Since(start)
		return report
	}
	report.TLSVersion = sanity.tlsVersion
	report.CipherSuite = sanity.cipherSuite
	report.ProbeDetails = append(report.ProbeDetails, "sanity_ok")

	// Probe 1: Empty SNI
	emptySNI := m.probeClientHello(ctx, target, sni, func(buf *bytes.Buffer) {
		buildClientHelloBase(buf, "", tls.VersionTLS12)
	})
	report.ProbeDetails = append(report.ProbeDetails,
		fmt.Sprintf("empty_sni:%s", emptySNI.finding))

	// Probe 2: TLS 1.0 instead of 1.2
	tls10 := m.probeClientHello(ctx, target, sni, func(buf *bytes.Buffer) {
		buildClientHelloBase(buf, sni, tls.VersionTLS10)
	})
	report.ProbeDetails = append(report.ProbeDetails,
		fmt.Sprintf("tls10:%s", tls10.finding))

	// Probe 3: Very long SNI (255+ bytes, DNS name max is 253)
	longSNI := m.probeClientHello(ctx, target, sni, func(buf *bytes.Buffer) {
		longName := strings.Repeat("a", 300) + ".example.com"
		buildClientHelloBase(buf, longName, tls.VersionTLS12)
	})
	report.ProbeDetails = append(report.ProbeDetails,
		fmt.Sprintf("long_sni:%s", longSNI.finding))

	// Probe 4: Missing cipher suites
	noCiphers := m.probeClientHello(ctx, target, sni, buildEmptyCipherClientHello)
	report.ProbeDetails = append(report.ProbeDetails,
		fmt.Sprintf("no_ciphers:%s", noCiphers.finding))

	// Probe 5: Truncated ClientHello (no extensions, short length)
	truncated := m.probeClientHello(ctx, target, sni, buildTruncatedClientHello)
	report.ProbeDetails = append(report.ProbeDetails,
		fmt.Sprintf("truncated:%s", truncated.finding))

	// Classify based on probe patterns.
	report.Finding = m.classifyFindings([]MiddleboxFinding{
		emptySNI.finding, tls10.finding, longSNI.finding,
		noCiphers.finding, truncated.finding,
	})

	report.Elapsed = time.Since(start)
	return report
}

// middleboxProbeResult holds the result of a single malformed ClientHello probe.
type middleboxProbeResult struct {
	finding     MiddleboxFinding
	tlsVersion  string
	cipherSuite uint16
}

// probeClientHello connects to target and sends a ClientHello built by the
// given builder function, then classifies the response.
func (m *TLSMiddlebox) probeClientHello(
	ctx context.Context,
	target, sni string,
	builder func(*bytes.Buffer),
) middleboxProbeResult {
	deadline := time.Now().Add(m.timeout)
	result := middleboxProbeResult{finding: MiddleboxNotFound}

	dialer := &net.Dialer{Timeout: m.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
			result.finding = MiddleboxTimeout
		} else if strings.Contains(err.Error(), "reset") || strings.Contains(err.Error(), "refused") {
			result.finding = MiddleboxConnectionReset
		} else {
			result.finding = MiddleboxProbeError
		}
		return result
	}
	defer conn.Close()

	_ = conn.SetDeadline(deadline)

	var buf bytes.Buffer
	builder(&buf)

	// Send ClientHello
	n, err := conn.Write(buf.Bytes())
	if err != nil {
		if strings.Contains(err.Error(), "reset") {
			result.finding = MiddleboxConnectionReset
		} else {
			result.finding = MiddleboxProbeError
		}
		return result
	}
	if n == 0 {
		result.finding = MiddleboxProbeError
		return result
	}

	// Read server response (or timeout/error)
	resp := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(m.timeout))
	rn, rerr := conn.Read(resp)

	if rerr != nil {
		errStr := rerr.Error()
		if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
			if rn > 0 {
				result.finding = MiddleboxTimeoutAfterHello
			} else {
				result.finding = MiddleboxTimeout
			}
		} else if strings.Contains(errStr, "closed") || strings.Contains(errStr, "EOF") {
			result.finding = MiddleboxUnexpectedEOF
		} else if strings.Contains(errStr, "reset") {
			result.finding = MiddleboxConnectionReset
		} else {
			result.finding = MiddleboxProbeError
		}
		return result
	}

	// We got a response; parse TLS record.
	result.finding = m.classifyServerResponse(resp[:rn])
	return result
}

// classifyServerResponse inspects the raw bytes returned by the server after
// our ClientHello and returns a finding code.
func (m *TLSMiddlebox) classifyServerResponse(data []byte) MiddleboxFinding {
	if len(data) == 0 {
		return MiddleboxUnexpectedEOF
	}
	if data[0] == 0x15 {
		// TLS Alert
		if len(data) >= 5 {
			level := data[3]
			desc := data[4]
			if level == 0x02 && desc == 0x46 {
				return MiddleboxVersionMismatch // internal_error
			}
			if level == 0x02 && desc == 0x28 {
				return MiddleboxBadCertificate // unrecognized_name
			}
		}
		return MiddleboxUnexpectedEOF
	}
	if data[0] == 0x16 {
		// TLS Handshake — this is the normal case.
		return MiddleboxNotFound
	}
	return MiddleboxNotFound
}

// classifyFindings takes the results of all probes and decides the overall
// middlebox classification.
func (m *TLSMiddlebox) classifyFindings(results []MiddleboxFinding) MiddleboxFinding {
	resetCount := 0
	timeoutCount := 0
	eofCount := 0

	for _, r := range results {
		switch r {
		case MiddleboxConnectionReset:
			resetCount++
		case MiddleboxTimeout, MiddleboxTimeoutAfterHello:
			timeoutCount++
		case MiddleboxUnexpectedEOF:
			eofCount++
		case MiddleboxBadCertificate, MiddleboxVersionMismatch:
			return r
		}
	}

	// OONI heuristic: if 3+ probes get the same abnormal response, it signals a middlebox.
	if resetCount >= 3 {
		return MiddleboxConnectionReset
	}
	if timeoutCount >= 3 {
		return MiddleboxTimeoutAfterHello
	}
	if eofCount >= 3 {
		return MiddleboxUnexpectedEOF
	}

	return MiddleboxNotFound
}

// --- ClientHello builders ---

// buildClientHelloBase constructs a TLS 1.2 ClientHello with the given SNI and version.
func buildClientHelloBase(buf *bytes.Buffer, sni string, version uint16) {
	// TLS Record Layer: Handshake (22)
	buf.WriteByte(0x16)
	// TLS 1.2
	binary.Write(buf, binary.BigEndian, uint16(version))
	// Handshake length placeholder (filled later)
	hsLenPos := buf.Len()
	buf.Write([]byte{0x00, 0x00, 0x00})

	hsStart := buf.Len()
	// Handshake type: ClientHello (1)
	buf.WriteByte(0x01)
	// Handshake length placeholder
	hsBodyStart := buf.Len()
	buf.Write([]byte{0x00, 0x00, 0x00})

	// Client version
	binary.Write(buf, binary.BigEndian, version)

	// Random (32 bytes)
	random := bytes.Repeat([]byte{0xAB}, 32)
	buf.Write(random)

	// Session ID length + empty
	buf.WriteByte(0x00)

	// Cipher suites
	ciphers := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}
	buf.WriteByte(byte(len(ciphers) * 2))
	for _, c := range ciphers {
		binary.Write(buf, binary.BigEndian, c)
	}

	// Compression methods: null
	buf.Write([]byte{0x01, 0x00})

	// Extensions length placeholder
	extLenPos := buf.Len()
	buf.Write([]byte{0x00, 0x00})

	// Extensions
	if sni != "" {
		writeSNIExtension(buf, sni)
	}
	writeALPNExtension(buf)
	writeSupportedVersionsExtension(buf, version)
	writeSupportedGroupsExtension(buf)

	// Backfill lengths
	extLen := buf.Len() - extLenPos - 2
	binary.BigEndian.PutUint16(buf.Bytes()[extLenPos:], uint16(extLen))

	hsBodyLen := buf.Len() - hsBodyStart - 3
	buf.Bytes()[hsBodyStart] = byte(hsBodyLen >> 16)
	buf.Bytes()[hsBodyStart+1] = byte(hsBodyLen >> 8)
	buf.Bytes()[hsBodyStart+2] = byte(hsBodyLen)

	totalLen := buf.Len() - hsStart - 4
	buf.Bytes()[hsLenPos] = byte(totalLen >> 16)
	buf.Bytes()[hsLenPos+1] = byte(totalLen >> 8)
	buf.Bytes()[hsLenPos+2] = byte(totalLen)
}

// buildNormalClientHello builds a standard TLS 1.2 ClientHello for the sanity check.
func buildNormalClientHello(buf *bytes.Buffer) {
	buildClientHelloBase(buf, "", tls.VersionTLS12)
}

// buildEmptyCipherClientHello builds a ClientHello with zero cipher suites.
func buildEmptyCipherClientHello(buf *bytes.Buffer) {
	buildClientHelloBase(buf, "", tls.VersionTLS12)
	// Overwrite cipher suite count to 0
	offset := bytes.Index(buf.Bytes(), []byte{0x00, 0x0E}) // len(ciphers) * 2
	if offset > 0 && buf.Len() > offset {
		buf.Bytes()[offset-1] = 0x00 // set cipher count to 0
	}
}

// buildTruncatedClientHello builds a ClientHello that is intentionally truncated
// (no extensions, very short).
func buildTruncatedClientHello(buf *bytes.Buffer) {
	buf.Grow(100)
	buf.WriteByte(0x16) // TLS record
	binary.Write(buf, binary.BigEndian, uint16(tls.VersionTLS12))
	// Short body
	binary.Write(buf, binary.BigEndian, uint16(10))
	buf.WriteByte(0x01) // ClientHello
	buf.Write([]byte{0x00, 0x00, 0x06}) // length
	binary.Write(buf, binary.BigEndian, tls.VersionTLS12)
	buf.Write(bytes.Repeat([]byte{0xCD}, 32))
	buf.WriteByte(0x00) // empty session id
	buf.WriteByte(0x00) // zero cipher suites
	buf.WriteByte(0x00) // zero compression methods
}

// writeSNIExtension writes a server_name (SNI) TLS extension.
func writeSNIExtension(buf *bytes.Buffer, sni string) {
	// Extension: server_name (0x0000)
	buf.Write([]byte{0x00, 0x00})
	// Extension length placeholder
	extLenPos := buf.Len()
	buf.Write([]byte{0x00, 0x00})

	extStart := buf.Len()
	// SNI list length
	buf.Write([]byte{0x00, 0x00})
	// Type: hostname (0x00)
	buf.WriteByte(0x00)
	// SNI hostname length
	buf.Write([]byte{0x00, 0x00})
	sniLenPos := buf.Len()
	// SNI hostname (filled below)
	sniStart := buf.Len()
	buf.WriteString(sni)

	// Backfill
	sniLen := buf.Len() - sniStart
	binary.BigEndian.PutUint16(buf.Bytes()[sniLenPos:], uint16(sniLen))
	listLen := sniLen + 3
	binary.BigEndian.PutUint16(buf.Bytes()[extStart:], uint16(listLen))

	extLen := buf.Len() - extStart - 2
	binary.BigEndian.PutUint16(buf.Bytes()[extLenPos:], uint16(extLen))
}

// writeALPNExtension writes an ALPN extension with common HTTP/2 and HTTP/1.1.
func writeALPNExtension(buf *bytes.Buffer) {
	buf.Write([]byte{0x00, 0x10}) // extension type: application_layer_protocol_negotiation
	extLenPos := buf.Len()
	buf.Write([]byte{0x00, 0x00})

	alpn := []string{"h2", "http/1.1"}
	total := 0
	for _, p := range alpn {
		buf.WriteByte(byte(len(p)))
		buf.WriteString(p)
		total += len(p) + 1
	}
	binary.BigEndian.PutUint16(buf.Bytes()[extLenPos:], uint16(total+2))
	buf.WriteByte(byte(len(alpn)))
}

// writeSupportedVersionsExtension writes a TLS 1.3 supported_versions extension.
func writeSupportedVersionsExtension(buf *bytes.Buffer, version uint16) {
	buf.Write([]byte{0x00, 0x2b}) // extension type: supported_versions
	buf.Write([]byte{0x00, 0x03}) // length 3
	buf.WriteByte(0x02)           // supported_versions length
	binary.Write(buf, binary.BigEndian, version)
}

// writeSupportedGroupsExtension writes a supported_groups extension.
func writeSupportedGroupsExtension(buf *bytes.Buffer) {
	buf.Write([]byte{0x00, 0x0a}) // extension type: supported_groups
	buf.Write([]byte{0x00, 0x06}) // length 6
	buf.Write([]byte{0x00, 0x04}) // groups length
	buf.Write([]byte{0x00, 0x17}) // secp256r1
	buf.Write([]byte{0x00, 0x18}) // secp384r1
}
