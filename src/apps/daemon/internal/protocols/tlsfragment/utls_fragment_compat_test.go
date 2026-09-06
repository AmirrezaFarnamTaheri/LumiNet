package tlsfragment

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// helper to build a structurally valid TLS ClientHello record with SNI.
// The canonical parser intentionally rejects old pattern-only fixtures that omit
// the mandatory ClientHello fields before extensions.
func buildMockClientHelloForFragment(sni string) []byte {
	name := []byte(sni)
	sniData := make([]byte, 5+len(name))
	binary.BigEndian.PutUint16(sniData[0:2], uint16(3+len(name)))
	sniData[2] = 0
	binary.BigEndian.PutUint16(sniData[3:5], uint16(len(name)))
	copy(sniData[5:], name)

	extension := make([]byte, 4+len(sniData))
	binary.BigEndian.PutUint16(extension[0:2], 0)
	binary.BigEndian.PutUint16(extension[2:4], uint16(len(sniData)))
	copy(extension[4:], sniData)

	body := make([]byte, 0, 64+len(extension))
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0x13, 0x01)
	body = append(body, 1, 0)
	body = append(body, byte(len(extension)>>8), byte(len(extension)))
	body = append(body, extension...)

	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x01
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	copy(handshake[4:], body)

	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1], record[2] = 0x03, 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)
	return record
}

func TestFindSNIOffset(t *testing.T) {
	mockCH := buildMockClientHelloForFragment("google.com")
	offset, length := findSNIOffset(mockCH)

	if offset < 0 {
		t.Fatal("Failed to locate SNI offset in mock ClientHello")
	}
	if length != len("google.com") {
		t.Errorf("Expected SNI length %d, got %d", len("google.com"), length)
	}

	extracted := string(mockCH[offset : offset+length])
	if extracted != "google.com" {
		t.Errorf("Expected extracted SNI %s, got %s", "google.com", extracted)
	}
}

func TestFragmentAtSNI(t *testing.T) {
	mockCH := buildMockClientHelloForFragment("example.org")
	frags := fragmentAtSNI(mockCH)

	if len(frags) != 2 {
		t.Fatalf("Expected 2 fragments for sni_split, got %d", len(frags))
	}

	reconstructed := append(frags[0], frags[1]...)
	if !bytes.Equal(mockCH, reconstructed) {
		t.Error("Reconstructed data does not match original ClientHello")
	}
}

func TestFragmentMulti(t *testing.T) {
	data := []byte("abcdefghijklmnopqrstuvwxyz")
	frags := fragmentMulti(data, 5)

	if len(frags) != 6 {
		t.Fatalf("Expected 6 fragments, got %d", len(frags))
	}
	if len(frags[0]) != 5 || len(frags[5]) != 1 {
		t.Errorf("Unexpected fragment sizes: first %d, last %d", len(frags[0]), len(frags[5]))
	}
}

func TestTLSRecordFragment(t *testing.T) {
	mockCH := buildMockClientHelloForFragment("yahoo.com")
	frags := tlsRecordFragment(mockCH)

	if len(frags) != 2 {
		t.Fatalf("Expected 2 records, got %d", len(frags))
	}
	for i, f := range frags {
		if f[0] != 0x16 {
			t.Errorf("Fragment %d is not a valid TLS record type", i)
		}
	}
}
