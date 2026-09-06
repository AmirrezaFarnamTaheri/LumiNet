// Package tlsdecoy owns construction and validation for LumiNet's bounded,
// fixed-size TLS ClientHello decoys. It performs no network I/O.
package tlsdecoy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

const (
	ClientHelloSize = 517
	MaxSNIBytes     = 219
	templateSNI     = "mci.ir"
	templateHex     = "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5"
)

var templateBytes = mustDecodeTemplate()

func mustDecodeTemplate() []byte {
	decoded, err := hex.DecodeString(templateHex)
	if err != nil {
		panic("invalid built-in TLS decoy template: " + err.Error())
	}
	return decoded
}

// ValidSNI accepts only bounded ASCII DNS hostnames representable in the SNI
// extension. IP literals, empty labels, and underscore/service labels are not
// admitted as decoy hostnames.
func ValidSNI(s string) bool {
	if len(s) == 0 || len(s) > MaxSNIBytes || !isASCII(s) || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// BuildPaddedClientHello returns the canonical 517-byte decoy ClientHello.
// Entropy and key-share bytes are regenerated for every call; an explicit TLS
// padding extension preserves the fixed record size as SNI length changes.
func BuildPaddedClientHello(sni string) ([]byte, error) {
	if !ValidSNI(sni) {
		return nil, fmt.Errorf("invalid decoy SNI")
	}
	if len(templateBytes) < 262+len(templateSNI) {
		return nil, fmt.Errorf("built-in TLS decoy template is truncated")
	}

	static1 := templateBytes[:11]
	static3 := templateBytes[76:120]
	static4 := templateBytes[127+len(templateSNI) : 262+len(templateSNI)]
	random := make([]byte, 32)
	sessionID := make([]byte, 32)
	keyShare := make([]byte, 32)
	for _, buf := range [][]byte{random, sessionID, keyShare} {
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return nil, fmt.Errorf("generate TLS decoy entropy: %w", err)
		}
	}

	sniBytes := []byte(sni)
	paddingLen := MaxSNIBytes - len(sniBytes)
	out := make([]byte, 0, ClientHelloSize)
	out = append(out, static1...)
	out = append(out, random...)
	out = append(out, 0x20)
	out = append(out, sessionID...)
	out = append(out, static3...)

	sniExtLen := len(sniBytes) + 5
	sniListLen := len(sniBytes) + 3
	out = append(out, byte(sniExtLen>>8), byte(sniExtLen))
	out = append(out, byte(sniListLen>>8), byte(sniListLen))
	out = append(out, 0x00, byte(len(sniBytes)>>8), byte(len(sniBytes)))
	out = append(out, sniBytes...)

	out = append(out, static4...)
	out = append(out, keyShare...)
	out = append(out, 0x00, 0x15, byte(paddingLen>>8), byte(paddingLen))
	out = append(out, make([]byte, paddingLen)...)
	if len(out) != ClientHelloSize {
		return nil, fmt.Errorf("TLS decoy size mismatch: got %d want %d", len(out), ClientHelloSize)
	}
	return out, nil
}
