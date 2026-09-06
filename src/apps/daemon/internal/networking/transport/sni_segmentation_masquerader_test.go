package transport

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func createDummyTlsHello(sni string) []byte {
	var data []byte
	data = append(data, 0x16, 0x03, 0x01, 0x00, 0x00) // record header
	data = append(data, 0x01, 0x00, 0x00, 0x00, 0x03, 0x03)
	data = append(data, make([]byte, 32)...) // random
	data = append(data, 0x00)                // session id
	data = append(data, 0x00, 0x02, 0x13, 0x01)
	data = append(data, 0x01, 0x00) // compression

	sniBytes := []byte(sni)
	sniExtLen := 5 + len(sniBytes)
	extLen := 4 + sniExtLen

	extBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(extBuf, uint16(extLen))
	data = append(data, extBuf...)

	data = append(data, 0x00, 0x00) // SNI type
	extSizeBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(extSizeBuf, uint16(sniExtLen))
	data = append(data, extSizeBuf...)

	listLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(listLenBuf, uint16(len(sniBytes)+3))
	data = append(data, listLenBuf...)
	data = append(data, 0x00) // host_name

	sniNameLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(sniNameLenBuf, uint16(len(sniBytes)))
	data = append(data, sniNameLenBuf...)
	data = append(data, sniBytes...)

	recLen := uint16(len(data) - 5)
	binary.BigEndian.PutUint16(data[3:5], recLen)

	return data
}

func TestSniSegmentationMasquerader(t *testing.T) {
	dummy := createDummyTlsHello("target.forbidden.com")
	masq := NewSniSegmentationMasquerader(StrategyMidSniSplit, 8, 32)

	sni, start, end, ok := masq.ExtractSNI(dummy)
	if !ok || sni != "target.forbidden.com" {
		t.Fatalf("failed to extract SNI: %s, %v", sni, ok)
	}
	if start >= end {
		t.Fatalf("invalid start/end offsets")
	}

	chunks := masq.SegmentStream(dummy, 1234)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks with MidSniSplit, got %d", len(chunks))
	}

	var reassembled []byte
	for _, c := range chunks {
		reassembled = append(reassembled, c...)
	}
	if !bytes.Equal(reassembled, dummy) {
		t.Fatalf("reassembled bytes do not match original")
	}
}
