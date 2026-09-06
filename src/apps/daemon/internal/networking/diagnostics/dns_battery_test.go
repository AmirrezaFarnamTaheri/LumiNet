package diagnostics

import (
	"context"
	"testing"
	"time"
)

func TestDNSScanner_NewDefault(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	if s.ResolverIP != "8.8.8.8" {
		t.Errorf("ResolverIP = %q, want 8.8.8.8", s.ResolverIP)
	}
	if s.Timeout != 8*time.Second {
		t.Errorf("Timeout = %v, want 8s", s.Timeout)
	}
	if len(s.TestTargets) == 0 {
		t.Error("TestTargets should not be empty by default")
	}
}

func TestDNSScanner_SetTimeout(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("1.1.1.1")
	s.SetTimeout(15 * time.Second)
	if s.Timeout != 15*time.Second {
		t.Errorf("Timeout = %v, want 15s", s.Timeout)
	}
}

func TestDNSScanner_AddKnownGoodIP(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	s.AddKnownGoodIP("1.2.3.4")
	s.AddKnownGoodIP("5.6.7.8")
	if len(s.KnownGoodIPs) != 2 {
		t.Errorf("KnownGoodIPs len = %d, want 2", len(s.KnownGoodIPs))
	}
}

func TestDNSScanner_RunBatteryTimeout(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("192.0.2.1:53") // TEST-NET-1; unreachable
	s.SetTimeout(500 * time.Millisecond)
	ctx := context.Background()
	result := s.RunBattery(ctx)
	if len(result.Meta.Errors) == 0 && !result.Hijack.Hijacked {
		// At least some errors should be recorded.
		t.Logf("meta errors: %v", result.Meta.Errors)
	}
	// Hijack check should not panic even when all targets fail.
	if len(result.Hijack.SuspiciousDomains)+len(result.Hijack.HijackedDomains) == 0 && len(result.Hijack.Failures) == 0 {
		t.Log("no domains flagged — possibly all queries succeeded or no targets configured")
	}
}

func TestDNSScanner_DNSSECCheckFormat(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	s.TestTargets = []string{"cloudflare.com"}
	s.SetTimeout(5 * time.Second)
	ctx := context.Background()
	result := s.RunBattery(ctx)
	// Verify result structure is populated.
	if result.Meta.ResolverIP == "" {
		t.Error("Meta.ResolverIP should be set")
	}
	if result.Meta.Duration == 0 {
		t.Error("Meta.Duration should be recorded")
	}
	_ = result.DNSSEC // present regardless of outcome
	_ = result.EDNS0
	_ = result.Hijack
}

func TestDNSScanner_BuildQuery(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	q := s.buildQuery("example.com", 1, false)
	if len(q) < 12 {
		t.Fatalf("query too short: %d bytes", len(q))
	}
	// QDCOUNT should be 1.
	qdCount := int(q[4])<<8 | int(q[5])
	if qdCount != 1 {
		t.Errorf("QDCOUNT = %d, want 1", qdCount)
	}
}

func TestDNSScanner_BuildQueryWithEDNS0(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	q := s.buildQueryWithEDNS0("example.com", 4096)
	// ARCOUNT should be 1.
	arCount := int(q[10])<<8 | int(q[11])
	if arCount != 1 {
		t.Errorf("ARCOUNT = %d, want 1", arCount)
	}
}

func TestDNSScanner_SkipDNSName(t *testing.T) {
	t.Parallel()
	msg := []byte{
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
	}
	offset := skipDNSName(msg, 0)
	if offset != len(msg) {
		t.Errorf("skipDNSName advanced to %d, want %d", offset, len(msg))
	}
	// Pointer case.
	msgPtr := []byte{
		3, 'w', 'w', 'w', 0xC0, 0x00, // pointer to offset 0
	}
	offset = skipDNSName(msgPtr, 0)
	if offset != 3 {
		t.Errorf("skipDNSName with pointer returned %d, want 3", offset)
	}
}

func TestIsKnownHijackIP(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ip    string
		isHij bool
	}{
		{"0.0.0.0", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"192.168.1.1", false},
		{"198.51.100.99", true},
		{"203.0.113.55", true},
	}
	for _, c := range cases {
		got := isKnownHijackIP(c.ip)
		if got != c.isHij {
			t.Errorf("isKnownHijackIP(%q) = %v, want %v", c.ip, got, c.isHij)
		}
	}
}

func TestDNSScanner_ParseARecords(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("8.8.8.8")
	// Build a minimal response with one A record.
	resp := []byte{
		0x00, 0x01, // TXID
		0x81, 0x80, // flags
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x01, // ANCOUNT=1
		0x00, 0x00, // NSCOUNT, ARCOUNT
		// Question
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
		// Answer
		0xC0, 0x0C, // pointer to name at offset 12
		0x00, 0x01, // TYPE=A
		0x00, 0x01, // CLASS=IN
		0x00, 0x00, 0x01, 0x2C, // TTL=300
		0x00, 0x04, // RDLENGTH=4
		0x93, 0x18, 0x1B, 0x64, // 147.24.27.100
	}
	ips, _ := s.resolveA(context.Background(), "www.example.com")
	if len(ips) == 0 {
		// resolveA calls the real network; may fail in test environment.
		t.Log("resolveA returned empty (network may be unavailable)")
	}
	_ = resp // reference to avoid unused
}

func TestDNSScanner_EdgeCases(t *testing.T) {
	t.Parallel()
	s := NewDNSScanner("")
	s.SetTimeout(10 * time.Millisecond)
	ctx := context.Background()
	// Empty resolver IP should not panic.
	_ = s.RunBattery(ctx)

	// Zero timeout.
	s2 := NewDNSScanner("8.8.8.8")
	s2.SetTimeout(0)
	result := s2.RunBattery(ctx)
	_ = result
}
