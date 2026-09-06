package tarpit

import (
	"net"
	"testing"
	"time"
)

func TestTarpitServer(t *testing.T) {
	logger := newLogger("debug")
	server := newTarpitServer(logger)

	// Bind to local loopback port
	addr := "127.0.0.1:8489"
	err := server.Start(addr)
	if err != nil {
		t.Fatalf("Failed to start tarpit server: %v", err)
	}
	defer server.Stop()

	// Connect to tarpit
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to connect to tarpit: %v", err)
	}
	defer conn.Close()

	// Write payload (NOP sled shellcode)
	code := []byte{
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
	}
	_, err = conn.Write(code)
	if err != nil {
		t.Fatalf("Failed to write to tarpit: %v", err)
	}

	// Allow goroutine execution slice
	time.Sleep(100 * time.Millisecond)
}
