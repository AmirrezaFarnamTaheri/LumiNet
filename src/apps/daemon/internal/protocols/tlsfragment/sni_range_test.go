package tlsfragment

import (
	"encoding/binary"
	"testing"
)

func buildClientHelloWithSNI(host string) []byte {
	name := []byte(host)
	sniData := make([]byte, 5+len(name))
	binary.BigEndian.PutUint16(sniData[0:2], uint16(3+len(name)))
	sniData[2] = 0
	binary.BigEndian.PutUint16(sniData[3:5], uint16(len(name)))
	copy(sniData[5:], name)

	extension := make([]byte, 4+len(sniData))
	binary.BigEndian.PutUint16(extension[0:2], 0) // server_name
	binary.BigEndian.PutUint16(extension[2:4], uint16(len(sniData)))
	copy(extension[4:], sniData)

	body := make([]byte, 0, 64+len(extension))
	body = append(body, 0x03, 0x03) // legacy_version
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id length
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)             // compression methods
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

func TestSNIHostRangeFindsHostname(t *testing.T) {
	data := buildClientHelloWithSNI("example.org")
	start, end := SNIHostRange(data)
	if start <= 0 || end <= start {
		t.Fatalf("SNIHostRange() = (%d,%d)", start, end)
	}
	if got := string(data[start:end]); got != "example.org" {
		t.Fatalf("hostname = %q, want example.org", got)
	}
}

func TestSNIHostRangeRejectsMalformedInput(t *testing.T) {
	if start, end := SNIHostRange([]byte{0x16, 0x03}); start != 0 || end != 0 {
		t.Fatalf("malformed input range = (%d,%d), want (0,0)", start, end)
	}
}

func TestPostRefactor225SNIHostRangeRejectsFakeExtensionPatternOutsideExtensions(t *testing.T) {
	data := buildClientHelloWithSNI("real.example")
	start, end := SNIHostRange(data)
	if start == 0 || end == 0 {
		t.Fatal("fixture missing real SNI")
	}
	// Corrupt the real SNI extension type while leaving a convincing 00 00 SNI-like
	// byte sequence elsewhere in the record. A pattern scanner could accept it;
	// the structured parser must not.
	for i := 0; i+4 < start; i++ {
		if data[i] == 0 && data[i+1] == 0 && i+4 <= len(data) {
			// The server_name extension directly precedes the name-list payload in this fixture.
			if i+9 == start {
				data[i+1] = 1
				break
			}
		}
	}
	fake := []byte{0, 0, 0, 16, 0, 14, 0, 0, 11, 'f', 'a', 'k', 'e', '.', 't', 'e', 's', 't'}
	data = append(data, fake...)
	if s, e := SNIHostRange(data); s != 0 || e != 0 {
		t.Fatalf("fake pattern accepted at %d..%d", s, e)
	}
	if off, n := findSNIOffset(data); off != -1 || n != 0 {
		t.Fatalf("fragment parser accepted fake pattern at %d len %d", off, n)
	}
}
