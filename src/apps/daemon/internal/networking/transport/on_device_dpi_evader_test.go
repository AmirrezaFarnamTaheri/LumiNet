package transport

import (
	"bytes"
	"strings"
	"testing"
)

func TestOnDeviceDpiEvader(t *testing.T) {
	evader := NewOnDeviceDpiEvader(2)

	// SNI Split test
	tlsHello := []byte{0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x02}
	frags := evader.ApplySniSplit(tlsHello, 2)
	if len(frags) != 2 || len(frags[0]) != 2 || len(frags[1]) != 5 {
		t.Fatalf("unexpected SNI fragments: %v", frags)
	}

	// HTTP Desync test
	httpReq := []byte("GET / HTTP/1.1\r\nHost: censorship.gov\r\n\r\n")
	desynced := evader.ApplyHttpDesync(httpReq)
	if !strings.Contains(string(desynced), "hOst: censorship.gov") {
		t.Fatalf("expected desynced hOst header: %s", string(desynced))
	}

	// Out of order test
	data := []byte("111122223333")
	chunks := evader.GenerateOutOfOrderChunks(data, 4)
	if len(chunks) != 3 || string(chunks[0]) != "2222" || string(chunks[1]) != "1111" {
		t.Fatalf("unexpected chunks swapped: %v", chunks)
	}

	// Decoy TTL test
	decoyTTL, decoy, realTTL, real := evader.CraftDecoyPair([]byte("SECRET"), 3)
	if decoyTTL != 3 || realTTL != 64 || bytes.Equal(decoy, real) {
		t.Fatalf("unexpected decoy pair results")
	}
}
