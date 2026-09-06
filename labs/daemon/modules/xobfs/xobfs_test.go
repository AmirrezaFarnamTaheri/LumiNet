package xobfs

import (
	"bytes"
	"net"
	"testing"
)

func TestObfuscator(t *testing.T) {
	password := []byte("stealth-password-123")
	obfs := NewObfuscator(password)

	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	cipherText := make([]byte, len(payload)+smSaltLen)
	obfs.Obfuscate(payload, cipherText)

	if bytes.Equal(payload, cipherText[smSaltLen:]) {
		t.Error("obfuscation did not change the payload")
	}

	decrypted := make([]byte, len(payload))
	obfs.Deobfuscate(cipherText, decrypted)

	if !bytes.Equal(payload, decrypted) {
		t.Errorf("decrypted payload does not match original: %q vs %q", decrypted, payload)
	}
}

type mockPacketConn struct {
	net.PacketConn
	written     []byte
	addr        net.Addr
	readQueue   [][]byte
	readIdx     int
	writeToFunc func(p []byte, addr net.Addr) (int, error)
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if m.writeToFunc != nil {
		return m.writeToFunc(p, addr)
	}
	m.written = append([]byte(nil), p...)
	m.addr = addr
	return len(p), nil
}

func (m *mockPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(m.readQueue) > 0 {
		if m.readIdx >= len(m.readQueue) {
			return 0, m.addr, net.ErrClosed // simulate blocking/end
		}
		pkt := m.readQueue[m.readIdx]
		m.readIdx++
		copy(p, pkt)
		return len(pkt), m.addr, nil
	}
	copy(p, m.written)
	return len(m.written), m.addr, nil
}

func (m *mockPacketConn) Close() error {
	return nil
}

func TestGeckoConn_ShortHeader(t *testing.T) {
	cfg := GeckoConfig{
		Password:      "gecko-pass",
		MinPacketSize: 100,
		MaxPacketSize: 200,
	}

	mock := &mockPacketConn{}
	gConn, err := NewGeckoConn(cfg, mock)
	if err != nil {
		t.Fatalf("NewGeckoConn: %v", err)
	}
	defer gConn.Close()

	payload := []byte{0x40, 0x01, 0x02, 0x03} // Top bit clear (short header)
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}

	_, _ = gConn.WriteTo(payload, addr)

	// Since top bit is clear, it should not be fragmented.
	// It should only be obfuscated.
	readBuf := make([]byte, 500)
	n, _, err := gConn.ReadFrom(readBuf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}

	if !bytes.Equal(payload, readBuf[:n]) {
		t.Errorf("expected original payload, got %v", readBuf[:n])
	}
}

func TestGeckoConn_Fragmented(t *testing.T) {
	cfg := GeckoConfig{
		Password:      "gecko-pass",
		MinPacketSize: 50,
		MaxPacketSize: 100,
	}

	mock := &mockPacketConn{}
	gConn, err := NewGeckoConn(cfg, mock)
	if err != nil {
		t.Fatalf("NewGeckoConn: %v", err)
	}
	defer gConn.Close()

	// Top bit set (0x80) indicates QUIC long-header packet to be fragmented
	payload := make([]byte, 120)
	payload[0] = 0x80
	for i := 1; i < len(payload); i++ {
		payload[i] = byte(i)
	}

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}

	// We intercept the written frames on the mock connection
	var frames [][]byte
	mockWrite := func(p []byte, a net.Addr) (int, error) {
		cp := make([]byte, len(p))
		copy(cp, p)
		frames = append(frames, cp)
		return len(p), nil
	}
	mock.writeToFunc = mockWrite

	_, err = gConn.WriteTo(payload, addr)
	if err != nil {
		t.Fatalf("WriteTo fragmented: %v", err)
	}

	if len(frames) < 2 {
		t.Fatalf("expected at least 2 fragmented frames, got %d", len(frames))
	}

	// Feed the frames back to a receiving GeckoConn
	queueMock := &mockPacketConn{
		readQueue: frames,
		addr:      addr,
	}
	recvConn, _ := NewGeckoConn(cfg, queueMock)
	defer recvConn.Close()

	readBuf := make([]byte, 500)
	n, rAddr, err := recvConn.ReadFrom(readBuf)
	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}

	assembled := readBuf[:n]
	assembledAddr := rAddr

	if len(assembled) == 0 {
		t.Fatal("failed to assemble fragmented frames")
	}

	if !bytes.Equal(payload, assembled) {
		t.Errorf("assembled payload mismatch")
	}

	if assembledAddr.String() != addr.String() {
		t.Errorf("address mismatch: %s vs %s", assembledAddr, addr)
	}
}
