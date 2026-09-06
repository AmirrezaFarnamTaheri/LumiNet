// Package proxy — TUIC v5 spec wire format tests.
//
// Source: tuic-master protocol specification
// Verifies that TuicSession correctly encodes all command frames per spec.
package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// testWriter captures bytes written to it.
type testWriter struct {
	bytes.Buffer
}

func (w *testWriter) Write(p []byte) (int, error)        { return w.Buffer.Write(p) }
func (w *testWriter) Read(b []byte) (n int, err error)   { return 0, nil }
func (w *testWriter) Close() error                       { return nil }
func (w *testWriter) LocalAddr() net.Addr                { return nil }
func (w *testWriter) RemoteAddr() net.Addr               { return nil }
func (w *testWriter) SetDeadline(t time.Time) error      { return nil }
func (w *testWriter) SetReadDeadline(t time.Time) error  { return nil }
func (w *testWriter) SetWriteDeadline(t time.Time) error { return nil }

func newTestSession() (*TuicSession, *testWriter) {
	w := &testWriter{}
	var uuid [16]byte
	var token [32]byte
	for i := range uuid {
		uuid[i] = byte(i)
	}
	for i := range token {
		token[i] = byte(i + 16)
	}
	return NewTuicSession(w, uuid, token), w
}

// TestAuthenticateFrame verifies: [version:1][cmd:1][uuid:16][token:32] = 50 bytes
func TestAuthenticateFrame(t *testing.T) {
	sess, w := newTestSession()
	if err := sess.WriteAuthenticate(); err != nil {
		t.Fatalf("WriteAuthenticate: %v", err)
	}

	frame := w.Bytes()
	if len(frame) != 50 {
		t.Errorf("authenticate frame: got %d bytes, want 50", len(frame))
	}
	if frame[0] != TuicVersion {
		t.Errorf("version byte: got 0x%02x, want 0x%02x", frame[0], TuicVersion)
	}
	if frame[1] != TuicCmdAuthenticate {
		t.Errorf("cmd byte: got 0x%02x, want 0x%02x", frame[1], TuicCmdAuthenticate)
	}
	// UUID bytes [2:18]
	for i := 0; i < 16; i++ {
		if frame[2+i] != byte(i) {
			t.Errorf("uuid[%d]: got 0x%02x, want 0x%02x", i, frame[2+i], byte(i))
		}
	}
	// Token bytes [18:50]
	for i := 0; i < 32; i++ {
		if frame[18+i] != byte(i+16) {
			t.Errorf("token[%d]: got 0x%02x, want 0x%02x", i, frame[18+i], byte(i+16))
		}
	}
}

// TestConnectFrame_IPv4 verifies Connect frame wire format for an IPv4 address.
// Expected: [0x05][0x01][0x01][ip4:4][port:2]
func TestConnectFrame_IPv4(t *testing.T) {
	sess, w := newTestSession()
	if err := sess.WriteConnect(TuicAddrTypeIPv4, "1.2.3.4", 8080); err != nil {
		t.Fatalf("WriteConnect IPv4: %v", err)
	}

	frame := w.Bytes()
	// version + cmd + addrtype + 4 bytes IPv4 + 2 bytes port = 9 bytes
	if len(frame) != 9 {
		t.Errorf("connect IPv4 frame: got %d bytes, want 9", len(frame))
	}
	if frame[0] != TuicVersion {
		t.Errorf("version: got 0x%02x", frame[0])
	}
	if frame[1] != TuicCmdConnect {
		t.Errorf("cmd: got 0x%02x, want 0x%02x", frame[1], TuicCmdConnect)
	}
	if frame[2] != TuicAddrTypeIPv4 {
		t.Errorf("addr type: got 0x%02x, want 0x%02x", frame[2], TuicAddrTypeIPv4)
	}
	wantIP := []byte{1, 2, 3, 4}
	if !bytes.Equal(frame[3:7], wantIP) {
		t.Errorf("IPv4: got %v, want %v", frame[3:7], wantIP)
	}
	gotPort := binary.BigEndian.Uint16(frame[7:9])
	if gotPort != 8080 {
		t.Errorf("port: got %d, want 8080", gotPort)
	}
}

// TestConnectFrame_Domain verifies Connect frame for a domain address.
// Expected: [0x05][0x01][0x00][len:1][domain...][port:2]
func TestConnectFrame_Domain(t *testing.T) {
	sess, w := newTestSession()
	const host = "example.com"
	if err := sess.WriteConnect(TuicAddrTypeDomain, host, 443); err != nil {
		t.Fatalf("WriteConnect Domain: %v", err)
	}

	frame := w.Bytes()
	// version + cmd + addrtype + len(1) + domain + port(2)
	wantLen := 2 + 1 + 1 + len(host) + 2
	if len(frame) != wantLen {
		t.Errorf("connect domain frame: got %d bytes, want %d", len(frame), wantLen)
	}
	if frame[2] != TuicAddrTypeDomain {
		t.Errorf("addr type: got 0x%02x", frame[2])
	}
	if int(frame[3]) != len(host) {
		t.Errorf("domain len byte: got %d, want %d", frame[3], len(host))
	}
	if string(frame[4:4+len(host)]) != host {
		t.Errorf("domain: got %q, want %q", string(frame[4:4+len(host)]), host)
	}
}

// TestHeartbeatFrame verifies Heartbeat frame: [0x05][0x04] = 2 bytes
func TestHeartbeatFrame(t *testing.T) {
	sess, w := newTestSession()
	if err := sess.WriteHeartbeat(); err != nil {
		t.Fatalf("WriteHeartbeat: %v", err)
	}

	frame := w.Bytes()
	if len(frame) != 2 {
		t.Errorf("heartbeat frame: got %d bytes, want 2", len(frame))
	}
	if frame[0] != TuicVersion {
		t.Errorf("version: got 0x%02x", frame[0])
	}
	if frame[1] != TuicCmdHeartbeat {
		t.Errorf("cmd: got 0x%02x, want 0x%02x", frame[1], TuicCmdHeartbeat)
	}
}

// TestDissociateFrame verifies Dissociate frame: [0x05][0x03][assocID:2] = 4 bytes
func TestDissociateFrame(t *testing.T) {
	sess, w := newTestSession()
	const assocID uint16 = 0xABCD
	if err := sess.WriteDissociate(assocID); err != nil {
		t.Fatalf("WriteDissociate: %v", err)
	}

	frame := w.Bytes()
	if len(frame) != 4 {
		t.Errorf("dissociate frame: got %d bytes, want 4", len(frame))
	}
	if frame[0] != TuicVersion {
		t.Errorf("version: got 0x%02x", frame[0])
	}
	if frame[1] != TuicCmdDissociate {
		t.Errorf("cmd: got 0x%02x, want 0x%02x", frame[1], TuicCmdDissociate)
	}
	gotID := binary.BigEndian.Uint16(frame[2:4])
	if gotID != assocID {
		t.Errorf("assocID: got 0x%04x, want 0x%04x", gotID, assocID)
	}
}

// TestReadCommandHeader verifies round-trip encoding of command headers.
func TestReadCommandHeader(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(TuicVersion)
	buf.WriteByte(TuicCmdConnect)

	ver, cmd, err := ReadCommandHeader(&buf)
	if err != nil {
		t.Fatalf("ReadCommandHeader: %v", err)
	}
	if ver != TuicVersion {
		t.Errorf("version: got 0x%02x, want 0x%02x", ver, TuicVersion)
	}
	if cmd != TuicCmdConnect {
		t.Errorf("cmd: got 0x%02x, want 0x%02x", cmd, TuicCmdConnect)
	}
}

// TestReadCommandHeader_EOF verifies proper error on truncated input.
func TestReadCommandHeader_EOF(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteByte(TuicVersion) // only 1 byte, need 2
	_, _, err := ReadCommandHeader(&buf)
	if err == nil {
		t.Fatal("expected EOF error, got nil")
	}
	if err != io.ErrUnexpectedEOF {
		t.Errorf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

func TestAuthenticateTracksFrameSentNotPeerAcceptance(t *testing.T) {
	sess, _ := newTestSession()
	if sess.AuthenticationFrameSent() {
		t.Fatal("authentication frame must not start as sent")
	}
	if err := sess.WriteAuthenticate(); err != nil {
		t.Fatalf("WriteAuthenticate: %v", err)
	}
	if !sess.AuthenticationFrameSent() {
		t.Fatal("successful authenticate write must be recorded")
	}
}

func TestConnectRejectsDomainLengthOverflow(t *testing.T) {
	sess, w := newTestSession()
	host := string(bytes.Repeat([]byte{'a'}, 256))
	if err := sess.WriteConnect(TuicAddrTypeDomain, host, 443); err == nil {
		t.Fatal("expected domain length overflow rejection")
	}
	if w.Len() != 0 {
		t.Fatalf("invalid connect must not write a partial frame: %d bytes", w.Len())
	}
}

func TestPacketRejectsMalformedFragmentAndWireLengthOverflow(t *testing.T) {
	tests := []struct {
		name      string
		fragTotal byte
		fragID    byte
		host      string
		payload   []byte
	}{
		{name: "zero fragment total", fragTotal: 0, fragID: 0, host: "example.com"},
		{name: "fragment id outside total", fragTotal: 2, fragID: 2, host: "example.com"},
		{name: "oversized domain", fragTotal: 1, fragID: 0, host: string(bytes.Repeat([]byte{'a'}, 256))},
		{name: "oversized payload", fragTotal: 1, fragID: 0, host: "example.com", payload: make([]byte, 65536)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sess, w := newTestSession()
			if err := sess.WritePacket(1, 1, tc.fragTotal, tc.fragID, tc.host, 53, tc.payload); err == nil {
				t.Fatal("expected invalid packet rejection")
			}
			if w.Len() != 0 {
				t.Fatalf("invalid packet must not write a partial frame: %d bytes", w.Len())
			}
		})
	}
}

func TestPacketAllowsNonFirstFragmentWithoutAddress(t *testing.T) {
	sess, w := newTestSession()
	if err := sess.WritePacket(9, 7, 2, 1, "", 0, []byte("tail")); err != nil {
		t.Fatalf("WritePacket non-first fragment: %v", err)
	}
	frame := w.Bytes()
	if len(frame) < 11 || frame[10] != TuicAddrTypeNone {
		t.Fatalf("non-first fragment must encode none address, frame=%x", frame)
	}
}
