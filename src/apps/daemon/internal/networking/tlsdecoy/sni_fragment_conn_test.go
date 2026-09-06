package tlsdecoy

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// mockConn implements a minimal in-memory net.Conn recording written segments.
type mockConn struct {
	net.Conn
	writes [][]byte
}

func (m *mockConn) Write(b []byte) (int, error) {
	cp := make([]byte, len(b))
	copy(cp, b)
	m.writes = append(m.writes, cp)
	return len(b), nil
}

func (m *mockConn) Close() error { return nil }

func buildSyntheticClientHello(sniHost string) []byte {
	var buf bytes.Buffer
	// Record header: 0x16, 0x03, 0x01, len(placeholder)
	buf.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	hsStart := buf.Len()
	// Handshake: type=0x01 (ClientHello), len placeholder
	buf.Write([]byte{0x01, 0x00, 0x00, 0x00})
	// Version 0x03, 0x03
	buf.Write([]byte{0x03, 0x03})
	// 32-byte random
	buf.Write(bytes.Repeat([]byte{0x11}, 32))
	// Session ID (0 len)
	buf.WriteByte(0x00)
	// Cipher suites: len=2, suite=0x1301
	buf.Write([]byte{0x00, 0x02, 0x13, 0x01})
	// Compression methods: len=1, method=0x00
	buf.Write([]byte{0x01, 0x00})

	// Extensions
	var extBuf bytes.Buffer
	// Type 0x0000 (SNI)
	extBuf.Write([]byte{0x00, 0x00})
	sniExtDataLen := 2 + 1 + 2 + len(sniHost)
	var extLenBytes [2]byte
	binary.BigEndian.PutUint16(extLenBytes[:], uint16(sniExtDataLen))
	extBuf.Write(extLenBytes[:])
	// List len
	binary.BigEndian.PutUint16(extLenBytes[:], uint16(len(sniHost)+3))
	extBuf.Write(extLenBytes[:])
	// NameType=0
	extBuf.WriteByte(0x00)
	// Host len
	binary.BigEndian.PutUint16(extLenBytes[:], uint16(len(sniHost)))
	extBuf.Write(extLenBytes[:])
	// Host
	extBuf.WriteString(sniHost)

	var totalExtLen [2]byte
	binary.BigEndian.PutUint16(totalExtLen[:], uint16(extBuf.Len()))
	buf.Write(totalExtLen[:])
	buf.Write(extBuf.Bytes())

	raw := buf.Bytes()
	// Fix Handshake length
	hsLen := uint32(len(raw) - hsStart - 4)
	raw[hsStart+1] = byte(hsLen >> 16)
	raw[hsStart+2] = byte(hsLen >> 8)
	raw[hsStart+3] = byte(hsLen)

	// Fix Record length
	recLen := uint16(len(raw) - 5)
	raw[3] = byte(recLen >> 8)
	raw[4] = byte(recLen)

	return raw
}

func TestFindSNIHostnameOffset_And_Split(t *testing.T) {
	sni := "api.telegram.org"
	hello := buildSyntheticClientHello(sni)

	offset, hostLen := FindSNIHostnameOffset(hello)
	if offset <= 0 {
		t.Fatalf("Failed to find SNI offset")
	}
	if hostLen != len(sni) {
		t.Fatalf("Expected hostLen %d, got %d", len(sni), hostLen)
	}
	if string(hello[offset:offset+hostLen]) != sni {
		t.Fatalf("Extracted SNI mismatch: got %s", string(hello[offset:offset+hostLen]))
	}

	chunks := SplitClientHello(hello, "sni_split")
	if len(chunks) != 2 {
		t.Fatalf("Expected 2 chunks, got %d", len(chunks))
	}
	if !bytes.Equal(bytes.Join(chunks, nil), hello) {
		t.Errorf("Reconstructed chunks do not match original ClientHello")
	}
}

func TestFragmentConn_InterceptClientHello(t *testing.T) {
	mock := &mockConn{}
	fragConn := NewFragmentConn(mock, "sni_split", 1*time.Millisecond)

	hello := buildSyntheticClientHello("example.com")
	n, err := fragConn.Write(hello)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(hello) {
		t.Errorf("Expected %d bytes written, reported %d", len(hello), n)
	}

	// Should have been split into 2 writes
	if len(mock.writes) != 2 {
		t.Fatalf("Expected 2 fragmented writes, got %d", len(mock.writes))
	}

	// Subsequent non-ClientHello writes should not be fragmented
	appData := []byte("APPLICATION_DATA_PAYLOAD")
	mock.writes = nil
	_, _ = fragConn.Write(appData)
	if len(mock.writes) != 1 {
		t.Errorf("Subsequent writes should not be fragmented, got %d writes", len(mock.writes))
	}
}

func TestSplitMulti_And_Half(t *testing.T) {
	data := []byte("12345678901234567890123456789012345678901234567890")

	half := SplitHalf(data)
	if len(half) != 2 || !bytes.Equal(bytes.Join(half, nil), data) {
		t.Errorf("SplitHalf failed")
	}

	multi := SplitMulti(data, 24)
	if len(multi) != 3 || !bytes.Equal(bytes.Join(multi, nil), data) {
		t.Errorf("SplitMulti failed")
	}
}
