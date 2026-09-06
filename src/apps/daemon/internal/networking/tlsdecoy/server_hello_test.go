package tlsdecoy

import (
	"bytes"
	"testing"
)

func TestServerHelloRoundTrip(t *testing.T) {
	rnd := make([]byte, 32)
	sessID := make([]byte, 32)
	keyShare := make([]byte, 32)
	for i := 0; i < 32; i++ {
		rnd[i] = byte(i)
		sessID[i] = byte(i + 32)
		keyShare[i] = byte(i + 64)
	}
	appData := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	packet := BuildServerHelloWith(rnd, sessID, keyShare, appData)
	if len(packet) < 159 {
		t.Fatalf("ServerHello too short: %d", len(packet))
	}

	parsedRnd, parsedSessID, parsedKeyShare, parsedAppData, err := ParseServerHello(packet)
	if err != nil {
		t.Fatalf("ParseServerHello failed: %v", err)
	}

	if !bytes.Equal(parsedRnd, rnd) {
		t.Error("rnd mismatch")
	}
	if !bytes.Equal(parsedSessID, sessID) {
		t.Error("sessID mismatch")
	}
	if !bytes.Equal(parsedKeyShare, keyShare) {
		t.Error("keyShare mismatch")
	}
	if !bytes.Equal(parsedAppData, appData) {
		t.Error("appData mismatch")
	}
}

func TestParseClientHelloRoundTrip(t *testing.T) {
	sni := "auth.vercel.com"
	ch, err := BuildPaddedClientHello(sni)
	if err != nil {
		t.Fatalf("BuildPaddedClientHello failed: %v", err)
	}
	if len(ch) != ClientHelloSize {
		t.Fatalf("ClientHello size %d != %d", len(ch), ClientHelloSize)
	}

	rnd, sessID, parsedSNI, keyShare, err := ParseClientHello(ch)
	if err != nil {
		t.Fatalf("ParseClientHello failed: %v", err)
	}

	if parsedSNI != sni {
		t.Errorf("SNI mismatch: %q != %q", parsedSNI, sni)
	}
	if len(rnd) != 32 {
		t.Errorf("rnd len %d != 32", len(rnd))
	}
	if len(sessID) != 32 {
		t.Errorf("sessID len %d != 32", len(sessID))
	}
	if len(keyShare) != 32 {
		t.Errorf("keyShare len %d != 32", len(keyShare))
	}
}

func TestClientResponseRoundTrip(t *testing.T) {
	appData := []byte("GET /index.html HTTP/1.1\r\nHost: target.com\r\n\r\n")
	resp := BuildClientResponseWith(appData)
	if len(resp) != 11+len(appData) {
		t.Fatalf("Length %d != %d", len(resp), 11+len(appData))
	}

	parsed, err := ParseClientResponse(resp)
	if err != nil {
		t.Fatalf("ParseClientResponse failed: %v", err)
	}

	if !bytes.Equal(parsed, appData) {
		t.Error("Parsed client response data does not match original")
	}
}

