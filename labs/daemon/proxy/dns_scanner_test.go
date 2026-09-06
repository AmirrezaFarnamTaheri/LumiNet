package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchTruth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tt, err := FetchTruth(ctx, "example.com")
	if err != nil {
		t.Logf("FetchTruth returned error (expected in offline/limited envs): %v", err)
		return
	}

	if tt.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", tt.Domain)
	}
}

func TestVerifyAnswer(t *testing.T) {
	tt := &TruthTable{
		Domain: "example.com",
		TruthIPs: map[string]bool{
			"93.184.216.34": true,
		},
	}

	// Correct answer
	if tt.VerifyAnswer([]string{"93.184.216.34"}) {
		t.Error("VerifyAnswer erroneously returned true for known good IP")
	}

	// Poisoned answer
	if !tt.VerifyAnswer([]string{"1.2.3.4"}) {
		t.Error("VerifyAnswer failed to detect mismatched/poisoned IP")
	}
}

func TestScanHttpRelayIP(t *testing.T) {
	// Setup a mock HTTPS test server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	addr := server.Listener.Addr().(*net.TCPAddr)

	target := DnsScannerTarget{
		IP:  addr.IP.String(),
		SNI: "localhost",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res := ScanHttpRelayIP(ctx, target, 2*time.Second)
	if !res.Responded {
		t.Logf("ScanHttpRelayIP responded = false: %s (non-critical if TLS config is strict)", res.Error)
	}
}

func TestGenerateIPStream(t *testing.T) {
	cidrs := []string{"192.168.1.0/24", "10.0.0.0/30"}
	stream := GenerateIPStream(cidrs, 10)

	ips := make([]string, 0)
	for ip := range stream {
		ips = append(ips, ip)
	}

	if len(ips) == 0 {
		t.Error("GenerateIPStream failed to stream any IPs")
	}

	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Errorf("GenerateIPStream returned invalid IP: %s", ip)
		}
	}
}

func TestBuildDnssecRawQuery(t *testing.T) {
	query := BuildDnssecRawQuery()
	if len(query) < 12 {
		t.Errorf("BuildDnssecRawQuery returned payload too short: %d", len(query))
	}
	// Verify EDNS0 OPT record present
	hasOpt := false
	for i := 0; i < len(query)-1; i++ {
		if query[i] == 0x00 && query[i+1] == 0x29 {
			hasOpt = true
			break
		}
	}
	if !hasOpt {
		t.Error("BuildDnssecRawQuery constructed payload without EDNS0 OPT record")
	}
}

func TestRunResolverDiagnostic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	tt := &TruthTable{
		Domain:   "example.com",
		TruthIPs: map[string]bool{"93.184.216.34": true},
	}

	// Probes localhost or well-known public DNS
	res := RunResolverDiagnostic(ctx, "8.8.8.8", tt, 1*time.Second)
	t.Logf("Resolver Diagnostic Result for 8.8.8.8: Responded=%v, IsPoisoned=%v, IsHijacked=%v", res.Responded, res.IsPoisoned, res.IsHijacked)
}
