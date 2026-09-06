package system

import (
	"net"
	"strconv"
	"testing"
)

func TestCheckLocalTCPPortReportsOccupiedAndFree(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(rawPort)

	occupied, err := CheckLocalTCPPort("127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	if occupied.Available {
		t.Fatalf("occupied port reported available: %+v", occupied)
	}
	_ = listener.Close()

	free, err := CheckLocalTCPPort("127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	if !free.Available {
		t.Fatalf("released port reported unavailable: %+v", free)
	}
}

func TestCheckLocalTCPPortRejectsRemoteHostsAndInvalidPort(t *testing.T) {
	for _, tc := range []struct {
		host string
		port int
	}{
		{"198.51.100.8", 443},
		{"example.com", 443},
		{"127.0.0.1", 0},
		{"127.0.0.1", 65536},
	} {
		if _, err := CheckLocalTCPPort(tc.host, tc.port); err == nil {
			t.Fatalf("accepted invalid preflight %s:%d", tc.host, tc.port)
		}
	}
}
