// SPDX-License-Identifier: MIT
// C5.5a — JA3/JA4 Fingerprint: clean-room implementation of JA3 and JA4 TLS
// fingerprint computation. JA3 computes an MD5 hash of the TLS ClientHello
// (TLS version, cipher suites, extensions, elliptic curves, and ec point formats).
// JA4 computes a more modern, parseable fingerprint (truncated SHA256, ordering
// insensitive, transport-aware).
// MIT License — no existing JA3/JA4 library source code copied.

package diagnostics

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// JA3Fingerprint represents the components of a JA3 TLS fingerprint.
type JA3Fingerprint struct {
	// TLSVersion is the numeric TLS version from the ClientHello.
	TLSVersion uint16 `json:"tls_version"`
	// CipherSuites is the sorted list of 16-bit cipher suite IDs.
	CipherSuites []uint16 `json:"cipher_suites"`
	// Extensions is the sorted list of extension IDs present.
	Extensions []uint16 `json:"extensions"`
	// EllipticCurves is the sorted list of supported elliptic curves.
	EllipticCurves []uint16 `json:"elliptic_curves"`
	// EcPointFormats is the list of EC point formats.
	EcPointFormats []uint8 `json:"ec_point_formats"`
	// Raw is the raw ClientHello bytes used to compute the fingerprint.
	Raw []byte `json:"raw,omitempty"`
}

// JA4Fingerprint is the modern TLS fingerprint format.
// Format: t13d1516h2_9b0f8e7d6c5a4b3_2a1_e6a9b3c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1
// Fields: transport_version_cipher_sni_segment_truncated_hash
type JA4Fingerprint struct {
	// Raw is the full JA4 fingerprint string.
	Raw string `json:"ja4"`
	// Transport is the transport protocol (tcp/quic).
	Transport string `json:"transport"`
	// Version is the TLS version string.
	Version string `json:"version"`
	// CipherSuites is the sorted list of cipher suite IDs used.
	CipherSuites []uint16 `json:"cipher_suites"`
	// Extensions is the sorted list of extension IDs present.
	Extensions []uint16 `json:"extensions"`
	// SNI is the Server Name Indication value (or "sni" if absent).
	SNI string `json:"sni"`
	// ALPN is the selected ALPN protocol (or "" if absent).
	ALPN string `json:"alpn"`
	// IsInsecure is true if the fingerprint includes suspicious/weak ciphers.
	IsInsecure bool `json:"is_insecure"`
}

// JA3Hash computes the JA3 MD5 hash string from a parsed ClientHello fingerprint.
// The hash is computed as:
//   TLSVersion,CipherSuites,Extensions,EllipticCurves,EcPointFormats
// with each field's values joined by "-" and the whole string MD5-hashed.
func JA3Hash(fp JA3Fingerprint) string {
	var b strings.Builder

	// TLS version
	b.WriteString(fmt.Sprintf("%d", fp.TLSVersion))
	b.WriteString(",")

	// Cipher suites (in order as received)
	for i, c := range fp.CipherSuites {
		if i > 0 {
			b.WriteString("-")
		}
		b.WriteString(fmt.Sprintf("%d", c))
	}
	b.WriteString(",")

	// Extensions (in order as received)
	for i, e := range fp.Extensions {
		if i > 0 {
			b.WriteString("-")
		}
		b.WriteString(fmt.Sprintf("%d", e))
	}
	b.WriteString(",")

	// Elliptic curves
	for i, ec := range fp.EllipticCurves {
		if i > 0 {
			b.WriteString("-")
		}
		b.WriteString(fmt.Sprintf("%d", ec))
	}
	b.WriteString(",")

	// EC point formats
	for i, pf := range fp.EcPointFormats {
		if i > 0 {
			b.WriteString("-")
		}
		b.WriteString(fmt.Sprintf("%d", pf))
	}

	return fmt.Sprintf("%x", md5.Sum([]byte(b.String())))
}

// JA4Hash computes the JA4 fingerprint string from a parsed ClientHello fingerprint.
// JA4 is transport-aware, version-aware, and uses a truncated SHA256 hash for
// privacy. Format: t13d1516h2_9b0f8e7d6c5a4b3_2a1_e6a9b3c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1
func JA4Hash(fp JA4Fingerprint) string {
	var sb strings.Builder

	// Part a: transport_version
	sb.WriteString(fp.Transport)
	sb.WriteString("_")
	sb.WriteString(fp.Version)

	// Part b: sorted cipher suites (first 12 chars)
	var sortedC []uint16
	sortedC = append(sortedC, fp.CipherSuites...)
	sort.Slice(sortedC, func(i, j int) bool { return sortedC[i] < sortedC[j] })
	var cb strings.Builder
	for i, c := range sortedC {
		if i > 0 {
			cb.WriteString(",")
		}
		cb.WriteString(fmt.Sprintf("%d", c))
	}
	cbStr := cb.String()
	if len(cbStr) > 12 {
		cbStr = cbStr[:12]
	}
	sb.WriteString(cbStr)
	sb.WriteString("_")

	// Part c: SNI or "sni"
	if fp.SNI != "" {
		sb.WriteString(fp.SNI[:min(len(fp.SNI), 3)])
	} else {
		sb.WriteString("sni")
	}
	sb.WriteString("_")

	// Part d: truncated SHA256 of the full fingerprint string
	full := fmt.Sprintf("%s_%s_%s_%s",
		fp.Transport, fp.Version,
		cb.String(), fp.SNI)
	sum := sha256.Sum256([]byte(full))
	var hb strings.Builder
	for i := 0; i < 16; i++ {
		if i > 0 {
			hb.WriteString("_")
		}
		hb.WriteString(fmt.Sprintf("%02x", sum[i]))
	}
	sb.WriteString(hb.String())

	return sb.String()
}

// ClientHelloInfo holds the parsed components of a TLS ClientHello packet.
type ClientHelloInfo struct {
	Version         uint16
	CipherSuites    []uint16
	Extensions      []uint16
	EllipticCurves  []uint16
	EcPointFormats  []uint8
	SNI             string
	ALPN            string
	SessionID       []byte
	SupportedVersions []uint16
}

// ComputeFingerprint parses a raw ClientHello byte slice and returns both the
// JA3 and JA4 fingerprints. It returns an error if the bytes are not a valid
// TLS ClientHello record.
func ComputeFingerprint(clientHello []byte) (*JA3Fingerprint, *JA4Fingerprint, error) {
	info, err := parseClientHello(clientHello)
	if err != nil {
		return nil, nil, err
	}

	ja3 := &JA3Fingerprint{
		TLSVersion:     info.Version,
		CipherSuites:   info.CipherSuites,
		Extensions:     info.Extensions,
		EllipticCurves: info.EllipticCurves,
		EcPointFormats: info.EcPointFormats,
		Raw:            clientHello,
	}

	transport := "tcp"
	verStr := fmt.Sprintf("%x", info.Version)
	if len(info.SupportedVersions) > 0 {
		verStr = fmt.Sprintf("%x", info.SupportedVersions[0])
	}

	ja4 := &JA4Fingerprint{
		Transport:    transport,
		Version:      verStr,
		CipherSuites: info.CipherSuites,
		Extensions:   info.Extensions,
		SNI:          info.SNI,
		ALPN:         info.ALPN,
		IsInsecure:   checkWeakCiphers(info.CipherSuites),
	}

	return ja3, ja4, nil
}

// JA3HashString is a convenience that computes JA3 directly from raw ClientHello bytes.
func JA3HashString(clientHello []byte) (string, error) {
	ja3, _, err := ComputeFingerprint(clientHello)
	if err != nil {
		return "", err
	}
	return JA3Hash(*ja3), nil
}

// JA4HashString is a convenience that computes JA4 directly from raw ClientHello bytes.
func JA4HashString(clientHello []byte) (string, error) {
	_, ja4, err := ComputeFingerprint(clientHello)
	if err != nil {
		return "", err
	}
	return JA4Hash(*ja4), nil
}

// parseClientHello parses a TLS ClientHello byte slice and returns its components.
func parseClientHello(data []byte) (*ClientHelloInfo, error) {
	info := &ClientHelloInfo{}

	if len(data) < 5 {
		return nil, fmt.Errorf("client hello too short: %d bytes", len(data))
	}

	// TLS Record: type (1) + version (2) + length (2)
	if data[0] != 0x16 {
		return nil, fmt.Errorf("not a TLS handshake record: 0x%02x", data[0])
	}

	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return nil, fmt.Errorf("truncated TLS record: got %d, want %d", len(data), 5+recordLen)
	}

	// Handshake: type (1) + length (3)
	handshakeStart := 5
	if data[handshakeStart] != 0x01 {
		return nil, fmt.Errorf("not a ClientHello: handshake type 0x%02x", data[handshakeStart])
	}
	handshakeLen := int(data[handshakeStart+1])<<16 | int(data[handshakeStart+2])<<8 | int(data[handshakeStart+3])
	if len(data) < handshakeStart+4+handshakeLen {
		return nil, fmt.Errorf("truncated ClientHello handshake: got %d, want %d", len(data), handshakeStart+4+handshakeLen)
	}
	bodyStart := handshakeStart + 4

	// Client Version (2)
	info.Version = uint16(data[bodyStart])<<8 | uint16(data[bodyStart+1])

	// Random (32 bytes)
	randomEnd := bodyStart + 2 + 32

	// Session ID
	sidLen := int(data[randomEnd])
	sidStart := randomEnd + 1
	info.SessionID = data[sidStart : sidStart+sidLen]
	next := sidStart + sidLen

	// Cipher Suites
	if next+2 > len(data) {
		return nil, fmt.Errorf("cipher suites length out of bounds")
	}
	csLen := int(data[next])<<8 | int(data[next+1])
	csStart := next + 2
	if csStart+csLen > len(data) {
		return nil, fmt.Errorf("cipher suites out of bounds")
	}
	for i := 0; i < csLen; i += 2 {
		info.CipherSuites = append(info.CipherSuites,
			uint16(data[csStart+i])<<8|uint16(data[csStart+i+1]))
	}
	next = csStart + csLen

	// Compression Methods
	if next >= len(data) {
		return nil, fmt.Errorf("compression methods out of bounds")
	}
	compLen := int(data[next])
	next++

	// Extensions
	if next+compLen >= len(data) {
		return nil, fmt.Errorf("extensions out of bounds")
	}
	next += compLen

	if next+2 > len(data) {
		return nil, fmt.Errorf("extensions length out of bounds")
	}
	extLen := int(data[next])<<8 | int(data[next+1])
	extStart := next + 2
	if extStart+extLen > len(data) {
		return nil, fmt.Errorf("extensions out of bounds")
	}

	extEnd := extStart + extLen
	i := extStart
	for i+4 < extEnd {
		extType := uint16(data[i])<<8 | uint16(data[i+1])
		extLen := int(data[i+2])<<8 | int(data[i+3])
		i += 4

		info.Extensions = append(info.Extensions, extType)

		if i+extLen > extEnd {
			break
		}
		extData := data[i : i+extLen]
		i += extLen

		switch extType {
		case 0: // server_name
			info.SNI = parseSNIExtension(extData)
		case 10: // supported_groups
			info.EllipticCurves = parseEllipticCurves(extData)
		case 11: // ec_point_formats
			info.EcPointFormats = parseEcPointFormats(extData)
		case 16: // application_layer_protocol_negotiation
			info.ALPN = parseALPNExtension(extData)
		case 43: // supported_versions
			info.SupportedVersions = parseSupportedVersions(extData)
		}
	}

	return info, nil
}

func parseSNIExtension(data []byte) string {
	if len(data) < 5 {
		return ""
	}
	// server_name_list length
	listLen := int(data[0])<<8 | int(data[1])
	if listLen == 0 || len(data) < 3 {
		return ""
	}
	// First entry: type (1) + length (2)
	typ := data[2]
	if typ != 0x00 { // hostname
		return ""
	}
	sniLen := int(data[3])<<8 | int(data[4])
	if 5+sniLen > len(data) {
		return ""
	}
	return string(data[5 : 5+sniLen])
}

func parseEllipticCurves(data []byte) []uint16 {
	if len(data) < 3 {
		return nil
	}
	curvesLen := int(data[0])<<8 | int(data[1])
	var curves []uint16
	for i := 0; i+1 < curvesLen; i += 2 {
		curves = append(curves, uint16(data[2+i])<<8|uint16(data[2+i+1]))
	}
	return curves
}

func parseEcPointFormats(data []byte) []uint8 {
	if len(data) < 2 {
		return nil
	}
	fmtLen := int(data[0])
	var formats []uint8
	for i := 1; i <= fmtLen && i < len(data); i++ {
		formats = append(formats, data[i])
	}
	return formats
}

func parseALPNExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	// We take the first protocol listed.
	firstLen := int(data[0])
	if 1+firstLen > len(data) {
		return ""
	}
	return string(data[1 : 1+firstLen])
}

func parseSupportedVersions(data []byte) []uint16 {
	if len(data) < 2 {
		return nil
	}
	var versions []uint16
	// Check if this is a ClientHello-style supported_versions (length prefix)
	if len(data) == 1 {
		// TLS 1.3 single version
		versions = append(versions, 0x0304)
		return versions
	}
	// Version list: first byte is length
	listLen := int(data[0])
	for i := 1; i+1 < listLen && i+1 < len(data); i += 2 {
		versions = append(versions, uint16(data[i])<<8|uint16(data[i+1]))
	}
	return versions
}

// checkWeakCiphers returns true if the cipher suite list contains known
// weak or suspicious ciphers that may indicate MITM interference.
func checkWeakCiphers(ciphers []uint16) bool {
	weak := map[uint16]bool{
		0x0004: true, // TLS_RSA_WITH_RC4_128_SHA
		0x0005: true, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
		0x002f: true, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x0035: true, // TLS_RSA_WITH_AES_256_CBC_SHA
	}
	for _, c := range ciphers {
		if weak[c] {
			return true
		}
	}
	return false
}

// FingerprintSet bundles JA3 and JA4 results for serialization.
type FingerprintSet struct {
	JA3 JA3Fingerprint `json:"ja3"`
	JA4 JA4Fingerprint `json:"ja4"`
}

// MarshalJSON serializes both JA3 and JA4 as a combined fingerprint set.
func (fs FingerprintSet) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"ja3_hash": JA3Hash(fs.JA3),
		"ja4_hash": JA4Hash(fs.JA4),
		"ja3":      fs.JA3,
		"ja4":      fs.JA4,
	}
	return json.Marshal(m)
}
