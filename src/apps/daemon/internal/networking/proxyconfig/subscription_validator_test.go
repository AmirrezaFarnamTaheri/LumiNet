package proxyconfig

import (
	"fmt"
	"testing"
	"time"
)

func TestReserveLoopbackPorts(t *testing.T) {
	ports, err := ReserveLoopbackPorts(5, 3)
	if err != nil {
		t.Fatalf("ReserveLoopbackPorts failed: %v", err)
	}
	if len(ports) != 5 {
		t.Fatalf("expected 5 ports, got %d", len(ports))
	}

	seen := make(map[int]bool)
	for _, p := range ports {
		if seen[p] {
			t.Fatalf("duplicate port reserved: %d", p)
		}
		seen[p] = true
		if p <= 1024 || p > 65535 {
			t.Fatalf("invalid ephemeral port reserved: %d", p)
		}
	}
}

func TestIsPermanentHTTPError(t *testing.T) {
	cases := []struct {
		code      int
		permanent bool
	}{
		{400, true},
		{401, true},
		{403, true},
		{404, true},
		{410, true},
		{408, false}, // timeout -> retryable
		{429, false}, // rate limited -> retryable
		{500, false}, // server error -> retryable
		{502, false},
		{503, false},
		{200, false},
		{204, false},
	}

	for _, c := range cases {
		got := IsPermanentHTTPError(c.code)
		if got != c.permanent {
			t.Errorf("IsPermanentHTTPError(%d) = %v, expected %v", c.code, got, c.permanent)
		}
	}
}

func TestEvaluateQuorum(t *testing.T) {
	round1 := map[string]time.Duration{
		"node-A": 100 * time.Millisecond,
		"node-B": 50 * time.Millisecond,
		"node-C": 30 * time.Millisecond,
	}
	round2 := map[string]time.Duration{
		"node-A": 120 * time.Millisecond,
		"node-B": 60 * time.Millisecond,
		"node-C": 40 * time.Millisecond,
	}
	round3 := map[string]time.Duration{
		"node-A": 110 * time.Millisecond,
		"node-C": 35 * time.Millisecond, // node-B failed round 3!
	}

	rounds := []map[string]time.Duration{round1, round2, round3}
	evaluation := EvaluateQuorum(rounds)

	if len(evaluation.Survivors) != 2 {
		t.Fatalf("expected 2 survivors, got %d", len(evaluation.Survivors))
	}

	// node-C median is 35ms, node-A median is 110ms => node-C must be first
	if evaluation.Survivors[0] != "node-C" || evaluation.Survivors[1] != "node-A" {
		t.Fatalf("unexpected survivor ordering: %v", evaluation.Survivors)
	}

	// 3 ever passed, 2 survived => 1 flaky => 33.33% flaky
	if evaluation.FlakyPercent < 33.0 || evaluation.FlakyPercent > 34.0 {
		t.Errorf("expected ~33.33%% flaky, got %f", evaluation.FlakyPercent)
	}
}

func TestBalancedPortCapper(t *testing.T) {
	var pool []string
	for i := 0; i < 10; i++ {
		pool = append(pool, fmt.Sprintf("vless://user@1.1.1.1:443?type=ws&host=a.com#n%d", i))
	}
	for i := 0; i < 10; i++ {
		pool = append(pool, fmt.Sprintf("vless://user@1.1.1.1:8080?type=ws&host=b.com#n%d", i))
	}

	capped := BalancedPortCapper(pool, ParsePortFromShareLink, 6)
	if len(capped) != 6 {
		t.Fatalf("expected 6 capped items, got %d", len(capped))
	}

	count443 := 0
	count8080 := 0
	for _, link := range capped {
		p := ParsePortFromShareLink(link)
		if p == 443 {
			count443++
		} else if p == 8080 {
			count8080++
		}
	}

	if count443 != 3 || count8080 != 3 {
		t.Fatalf("expected balanced 3 on 443 and 3 on 8080, got %d and %d", count443, count8080)
	}
}

func TestParsePortFromShareLink(t *testing.T) {
	cases := []struct {
		link string
		port int
	}{
		{"vless://uuid@1.2.3.4:443?type=ws#test", 443},
		{"trojan://pass@domain.com:8443?security=tls", 8443},
		{"vless://uuid@[2001:db8::1]:2053?type=ws", 2053},
		{"invalid", 0},
	}

	for _, c := range cases {
		p := ParsePortFromShareLink(c.link)
		if p != c.port {
			t.Errorf("ParsePortFromShareLink(%q) = %d, expected %d", c.link, p, c.port)
		}
	}
}
