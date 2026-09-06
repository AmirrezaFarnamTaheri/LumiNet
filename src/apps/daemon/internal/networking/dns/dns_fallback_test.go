package dns

import (
	"net"
	"testing"
	"time"
)

func TestVerifyDNSServerTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen TCP: %v", err)
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	ok := VerifyDNSServerTCP(l.Addr().String(), 500*time.Millisecond)
	if !ok {
		t.Errorf("expected VerifyDNSServerTCP success, got failure")
	}

	ok = VerifyDNSServerTCP("127.0.0.1:1", 50*time.Millisecond)
	if ok {
		t.Errorf("expected VerifyDNSServerTCP failure for port 1, got success")
	}
}

func TestDNSUDPFallbackListener(t *testing.T) {
	listener := NewDNSUDPFallbackListener("127.0.0.1:0")
	defer listener.Stop()

	err := listener.Start()
	if err != nil {
		t.Fatalf("failed to start fallback listener: %v", err)
	}

	err = listener.Start()
	if err == nil {
		t.Errorf("expected double start to fail")
	}
}

func TestDNSUDPFallbackListenerReturnsTruncatedNoErrorResponse(t *testing.T) {
	listener := NewDNSUDPFallbackListener("127.0.0.1:0")
	if err := listener.Start(); err != nil {
		t.Fatal(err)
	}
	defer listener.Stop()
	listener.runningMu.Lock()
	addr := listener.conn.LocalAddr().(*net.UDPAddr)
	listener.runningMu.Unlock()

	client, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))

	query := []byte{
		0x12, 0x34, // transaction id
		0x01, 0x03, // RD set; low RCODE bits intentionally non-zero for clearing check
		0x00, 0x01, // QDCOUNT
		0x00, 0x02, // ANCOUNT
		0x00, 0x03, // NSCOUNT
		0x00, 0x04, // ARCOUNT
		0x00, // minimal payload beyond header
	}
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	resp := buf[:n]
	if len(resp) != len(query) || resp[0] != 0x12 || resp[1] != 0x34 {
		t.Fatalf("response identity/length drift: %x", resp)
	}
	if resp[2]&0x82 != 0x82 {
		t.Fatalf("QR+TC not set: flags=%02x%02x", resp[2], resp[3])
	}
	if resp[3]&0x0f != 0 {
		t.Fatalf("RCODE not cleared: flags=%02x%02x", resp[2], resp[3])
	}
	if resp[4] != 0 || resp[5] != 1 {
		t.Fatalf("question count changed: %x", resp[4:6])
	}
	for _, pair := range [][2]int{{6, 8}, {8, 10}, {10, 12}} {
		if resp[pair[0]] != 0 || resp[pair[0]+1] != 0 {
			t.Fatalf("response count not zeroed at %d: %x", pair[0], resp[pair[0]:pair[1]])
		}
	}
}
