// Package transport provides RFC 7685 constant-size padded TLS ClientHello generation.
//
// Ported and elevated from `sni-spoofing-rust-main`.
// Generates deterministic 517-byte ClientHello packets to defeat DPI length profiling.
// Conforms to strict architectural isolation rules: zero vendor prefixes.
package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

const (
	ClientHelloConstantSize = 517
	ExtensionServerName     = 0x0000
	ExtensionPadding        = 0x0015 // RFC 7685
	MaxSniLengthForPadding  = 215
)

var (
	ErrEmptySNI    = errors.New("sni_padded: SNI must not be empty")
	ErrSNITooLong  = errors.New("sni_padded: SNI exceeds 215-byte limit for 517B constant size")
)

// BuildPaddedClientHello constructs a deterministic TLS 1.3 ClientHello of exactly 517 bytes.
func BuildPaddedClientHello(sni string) ([]byte, error) {
	sniBytes := []byte(sni)
	if len(sniBytes) == 0 {
		return nil, ErrEmptySNI
	}
	if len(sniBytes) > MaxSniLengthForPadding {
		return nil, ErrSNITooLong
	}

	extensions := make([]byte, 0, 400)

	// 1. SNI Extension (0x0000)
	sniExtLen := uint16(5 + len(sniBytes))
	extensions = binary.BigEndian.AppendUint16(extensions, ExtensionServerName)
	extensions = binary.BigEndian.AppendUint16(extensions, sniExtLen)
	extensions = binary.BigEndian.AppendUint16(extensions, uint16(3+len(sniBytes))) // server_name_list len
	extensions = append(extensions, 0x00)                                          // host_name type
	extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(sniBytes)))
	extensions = append(extensions, sniBytes...)

	// 2. Supported Versions (0x002B) -> TLS 1.3 (0x0304), TLS 1.2 (0x0303)
	extensions = append(extensions, 0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03)

	// 3. Supported Groups (0x000A) -> X25519 (0x001D), secp256r1 (0x0017)
	extensions = append(extensions, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17)

	// 4. EC Point Formats (0x000B) -> uncompressed (0)
	extensions = append(extensions, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00)

	// 5. Signature Algorithms (0x000D)
	extensions = append(extensions,
		0x00, 0x0d, 0x00, 0x0c, 0x00, 0x0a,
		0x04, 0x03, // ecdsa_secp256r1_sha256
		0x08, 0x04, // rsa_pss_rsae_sha256
		0x04, 0x01, // rsa_pkcs1_sha256
		0x05, 0x03, // ecdsa_secp384r1_sha384
		0x08, 0x05, // rsa_pss_rsae_sha384
	)

	// 6. Key Share (0x0033) with dummy X25519 public key (32 bytes)
	extensions = append(extensions, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20)
	dummyKeyShare := make([]byte, 32)
	_, _ = rand.Read(dummyKeyShare)
	extensions = append(extensions, dummyKeyShare...)

	// Compute base record overhead:
	// Record Header: 5 bytes
	// Handshake Header: 4 bytes
	// ClientVersion: 2 bytes
	// Random: 32 bytes
	// SessionID: 1 + 32 = 33 bytes
	// CipherSuites: 2 + 6 = 8 bytes
	// CompressionMethods: 1 + 1 = 2 bytes
	// Extensions Length: 2 bytes
	// Base size = 5 + 4 + 2 + 32 + 33 + 8 + 2 + 2 = 88 bytes.
	baseLength := 88 + len(extensions)

	// Padding extension header = 4 bytes (ext_type: 2, ext_len: 2)
	if baseLength+4 > ClientHelloConstantSize {
		return nil, ErrSNITooLong
	}
	padLen := ClientHelloConstantSize - (baseLength + 4)

	// 7. RFC 7685 Padding Extension
	extensions = binary.BigEndian.AppendUint16(extensions, ExtensionPadding)
	extensions = binary.BigEndian.AppendUint16(extensions, uint16(padLen))
	zeroPadding := make([]byte, padLen)
	extensions = append(extensions, zeroPadding...)

	// Assemble Handshake Body
	handshakeBody := make([]byte, 0, ClientHelloConstantSize-5)
	handshakeBody = binary.BigEndian.AppendUint16(handshakeBody, 0x0303) // Legacy TLS 1.2 client_version

	// Client Random (32 bytes)
	clientRandom := make([]byte, 32)
	_, _ = rand.Read(clientRandom)
	handshakeBody = append(handshakeBody, clientRandom...)

	// Legacy Session ID (32 bytes)
	handshakeBody = append(handshakeBody, 0x20)
	sessionID := make([]byte, 32)
	_, _ = rand.Read(sessionID)
	handshakeBody = append(handshakeBody, sessionID...)

	// Cipher Suites (3 standard suites: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256)
	handshakeBody = binary.BigEndian.AppendUint16(handshakeBody, 6)
	handshakeBody = append(handshakeBody, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03)

	// Legacy Compression Methods (1 byte null)
	handshakeBody = append(handshakeBody, 0x01, 0x00)

	// Extensions
	handshakeBody = binary.BigEndian.AppendUint16(handshakeBody, uint16(len(extensions)))
	handshakeBody = append(handshakeBody, extensions...)

	// Assemble Complete TLS Record
	record := make([]byte, 0, ClientHelloConstantSize)
	record = append(record, 0x16)                                     // ContentType: Handshake (22)
	record = binary.BigEndian.AppendUint16(record, 0x0301)            // Legacy Record Version: TLS 1.0
	record = binary.BigEndian.AppendUint16(record, uint16(4+len(handshakeBody))) // Record length

	// Handshake Header
	record = append(record, 0x01) // HandshakeType: ClientHello (1)
	record = append(record,
		byte((len(handshakeBody)>>16)&0xff),
		byte((len(handshakeBody)>>8)&0xff),
		byte(len(handshakeBody)&0xff),
	)
	record = append(record, handshakeBody...)

	if len(record) != ClientHelloConstantSize {
		return nil, errors.New("sni_padded: failed to assemble exact 517-byte ClientHello")
	}

	return record, nil
}
