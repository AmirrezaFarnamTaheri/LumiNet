// Package tlsdecoy provides TLS 1.3 ClientHello & ServerHello template synthesis
// and component parsing for DPI bypass SNI spoofing.
// Originates from SNI-Spoofing-Go-main and adapted for LumiNet.

package tlsdecoy

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	shTemplateHex = "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1dae291c5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbde406130200002e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5b0e4eb188ebd30193271e8171152eb4e"
	shTemplate    []byte

	shStatic1 []byte // template[:11]
	shStatic2 = []byte{0x20}
	shStatic3 []byte // template[76:95]

	// TLS Change Cipher Spec + Application Data header
	TLSChangeCipher  = []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	TLSAppDataHeader = []byte{0x17, 0x03, 0x03}
)

func init() {
	var err error
	shTemplate, err = hex.DecodeString(shTemplateHex)
	if err != nil {
		panic("tlsdecoy: failed to decode ServerHello template hex: " + err.Error())
	}

	shStatic1 = shTemplate[:11]
	shStatic3 = shTemplate[76:95]
}

// BuildServerHelloWith synthesizes a TLS ServerHello packet with ChangeCipherSpec and ApplicationData envelope.
func BuildServerHelloWith(rnd, sessID, keyShare, appData1 []byte) []byte {
	result := make([]byte, 0, len(shStatic1)+len(rnd)+len(shStatic2)+len(sessID)+len(shStatic3)+len(keyShare)+len(TLSChangeCipher)+len(TLSAppDataHeader)+2+len(appData1))
	result = append(result, shStatic1...)
	result = append(result, rnd...)
	result = append(result, shStatic2...)
	result = append(result, sessID...)
	result = append(result, shStatic3...)
	result = append(result, keyShare...)
	result = append(result, TLSChangeCipher...)
	result = append(result, TLSAppDataHeader...)

	dataLen := uint16(len(appData1))
	result = append(result, byte(dataLen>>8), byte(dataLen))
	result = append(result, appData1...)
	return result
}

// ParseServerHello parses a synthesized ServerHello packet (must be >= 159 bytes).
func ParseServerHello(data []byte) (rnd, sessID, keyShare, appData1 []byte, err error) {
	if len(data) < 159 {
		return nil, nil, nil, nil, fmt.Errorf("expected >= 159 bytes, got %d", len(data))
	}

	rnd = data[11:43]
	sessID = data[44:76]
	keyShare = data[95:127]
	appData1 = data[138:]

	return rnd, sessID, keyShare, appData1, nil
}

// ParseClientHello parses a canonical 517-byte ClientHello packet back into its constituent components.
func ParseClientHello(data []byte) (rnd, sessID []byte, sni string, keyShare []byte, err error) {
	if len(data) != ClientHelloSize {
		return nil, nil, "", nil, fmt.Errorf("expected %d bytes, got %d", ClientHelloSize, len(data))
	}

	rnd = data[11:43]
	sessID = data[44:76]

	sniLenField := binary.BigEndian.Uint16(data[125:127])
	sni = string(data[127 : 127+sniLenField])

	ksInd := 262 + len(sni)
	if ksInd+32 > len(data) {
		return nil, nil, "", nil, errors.New("key share offset out of bounds")
	}
	keyShare = data[ksInd : ksInd+32]

	return rnd, sessID, sni, keyShare, nil
}

// BuildClientResponseWith wraps application data in a TLS ChangeCipherSpec + ApplicationData envelope.
func BuildClientResponseWith(appData []byte) []byte {
	result := make([]byte, 0, len(TLSChangeCipher)+len(TLSAppDataHeader)+2+len(appData))
	result = append(result, TLSChangeCipher...)
	result = append(result, TLSAppDataHeader...)
	dataLen := uint16(len(appData))
	result = append(result, byte(dataLen>>8), byte(dataLen))
	result = append(result, appData...)
	return result
}

// ParseClientResponse unwraps application data from a TLS client response envelope.
func ParseClientResponse(data []byte) ([]byte, error) {
	if len(data) < 11 {
		return nil, errors.New("client response packet too short")
	}
	for i := 0; i < len(TLSChangeCipher); i++ {
		if data[i] != TLSChangeCipher[i] {
			return nil, errors.New("invalid ChangeCipherSpec header")
		}
	}
	for i := 0; i < len(TLSAppDataHeader); i++ {
		if data[6+i] != TLSAppDataHeader[i] {
			return nil, errors.New("invalid ApplicationData header")
		}
	}
	length := binary.BigEndian.Uint16(data[9:11])
	if len(data) < 11+int(length) {
		return nil, errors.New("truncated application data in client response")
	}
	return data[11 : 11+length], nil
}

