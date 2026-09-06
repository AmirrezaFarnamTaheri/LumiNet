package scanner

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestTunnelScore(t *testing.T) {
	res := &TunnelStageResult{
		NsOk:           true,
		TxtOk:          true,
		RandomSubOk:    true,
		TunnelRealism:  true,
		Edns0Supported: true,
		NxdomainRatio:  0.8,
	}
	score := ComputeTunnelScore(res)
	if score != 6 {
		t.Fatalf("expected perfect score 6, got %d", score)
	}

	resPartial := &TunnelStageResult{
		NsOk:          true,
		TxtOk:         false,
		NxdomainRatio: 0.5,
	}
	scorePartial := ComputeTunnelScore(resPartial)
	if scorePartial != 1 {
		t.Fatalf("expected score 1, got %d", scorePartial)
	}
}

func TestFormatTunnelRealismQName(t *testing.T) {
	qname := FormatTunnelRealismQName("tunnel.example.com")
	if !strings.HasSuffix(qname, ".tunnel.example.com.") {
		t.Fatalf("expected suffix .tunnel.example.com., got %s", qname)
	}
	parts := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if len(parts) < 3 {
		t.Fatalf("unexpected qname structure: %s", qname)
	}
	label := parts[0]
	if len(label) != 57 {
		t.Fatalf("expected 57-char Base32 label, got len %d (%s)", len(label), label)
	}
}

func TestGenerateNearbyIPs(t *testing.T) {
	center := netip.MustParseAddr("192.168.1.100")
	offsets := []int{-5, -1, 1, 5, -150, 200}
	nearby := GenerateNearbyIPs(center, offsets)

	// -150 would result in 100 - 150 = -50 (invalid, skipped)
	// 200 would result in 100 + 200 = 300 (invalid, skipped)
	// -5 => 95, -1 => 99, 1 => 101, 5 => 105 (all 4 valid)
	if len(nearby) != 4 {
		t.Fatalf("expected 4 valid nearby IPs, got %d: %v", len(nearby), nearby)
	}

	for _, ip := range nearby {
		if ip == center {
			t.Fatalf("candidate should not include center IP: %s", ip)
		}
		octets := ip.As4()
		if octets[0] != 192 || octets[1] != 168 || octets[2] != 1 {
			t.Fatalf("candidate changed network prefix: %s", ip)
		}
		if octets[3] <= 0 || octets[3] >= 255 {
			t.Fatalf("candidate touched network or broadcast address: %s", ip)
		}
	}
}

func TestMockEvaluateTunnelCapability(t *testing.T) {
	// Start mock local DNS server
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind local udp port: %v", err)
	}
	serverAddr := pc.LocalAddr().(*net.UDPAddr)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetEdns0(1232, false)

		q := r.Question[0]
		if strings.HasPrefix(q.Name, "nonexistent-") {
			m.Rcode = dns.RcodeNameError
		} else if q.Qtype == dns.TypeTXT {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"dnstt-test-token"},
			})
		} else if q.Qtype == dns.TypeNS {
			m.Answer = append(m.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  "ns1.example.com.",
			})
		}
		_ = w.WriteMsg(m)
	})

	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()

	time.Sleep(50 * time.Millisecond)

	cfg := DefaultTunnelProberConfig()
	cfg.Timeout = 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	res := EvaluateTunnelCapability(ctx, "127.0.0.1", serverAddr.Port, "tunnel.local", cfg)
	if !res.NsOk {
		t.Errorf("expected NsOk to be true")
	}
	if !res.TxtOk {
		t.Errorf("expected TxtOk to be true")
	}
	if !res.TunnelRealism {
		t.Errorf("expected TunnelRealism to be true")
	}
	if !res.Edns0Supported {
		t.Errorf("expected Edns0Supported to be true")
	}
	if res.NxdomainRatio < 0.75 {
		t.Errorf("expected NxdomainRatio >= 0.75, got %f", res.NxdomainRatio)
	}
	if res.TotalScore < 5 {
		t.Errorf("expected TotalScore >= 5, got %d", res.TotalScore)
	}
	if !res.Qualified {
		t.Errorf("expected resolver to be qualified")
	}
}
