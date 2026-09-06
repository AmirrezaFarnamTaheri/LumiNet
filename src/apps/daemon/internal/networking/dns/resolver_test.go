package dns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestResolver_ResolveDoH(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/dns-message" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp := new(dns.Msg)
		resp.SetReply(msg)

		rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A 192.168.1.10", msg.Question[0].Name))
		resp.Answer = append(resp.Answer, rr)

		respBytes, err := resp.Pack()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		w.Write(respBytes)
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	r := NewResolver("127.0.0.1:0", "tunnel.test")
	r.dohEndpoints = []string{server.URL}

	ips, err := r.resolveDoH(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("resolveDoH failed: %v", err)
	}

	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("192.168.1.10")) {
		t.Errorf("expected 192.168.1.10, got %v", ips)
	}
}

func TestResolver_ResolveRegional(t *testing.T) {
	dnsHandler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A 10.0.0.5", req.Question[0].Name))
		m.Answer = append(m.Answer, rr)
		w.WriteMsg(m)
	})

	// Get local free UDP port first
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	localAddr := pc.LocalAddr().String()
	pc.Close()

	dnsServer := &dns.Server{Addr: localAddr, Net: "udp", Handler: dnsHandler}
	go func() {
		_ = dnsServer.ListenAndServe()
	}()
	defer dnsServer.Shutdown()

	time.Sleep(100 * time.Millisecond)

	r := NewResolver("127.0.0.1:0", "tunnel.test")
	r.regionalIPs = []string{localAddr}

	ips, err := r.resolveRegional(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("resolveRegional failed: %v", err)
	}

	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.0.0.5")) {
		t.Errorf("expected 10.0.0.5, got %v", ips)
	}
}

func TestResolver_ResolveTunnel(t *testing.T) {
	dnsHandler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)

		// Expected query domain: <encoded>.tunnel.test
		qName := req.Question[0].Name
		rr, _ := dns.NewRR(fmt.Sprintf("%s 60 IN A 172.16.0.20", qName))
		m.Answer = append(m.Answer, rr)
		w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen packet: %v", err)
	}
	localAddr := pc.LocalAddr().String()
	pc.Close()

	dnsServer := &dns.Server{Addr: localAddr, Net: "udp", Handler: dnsHandler}
	go func() {
		_ = dnsServer.ListenAndServe()
	}()
	defer dnsServer.Shutdown()

	time.Sleep(100 * time.Millisecond)

	r := NewResolver("127.0.0.1:0", "tunnel.test")
	r.regionalIPs = []string{localAddr}

	ips, err := r.resolveTunnel(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("resolveTunnel failed: %v", err)
	}

	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("172.16.0.20")) {
		t.Errorf("expected 172.16.0.20, got %v", ips)
	}
}

func TestIsCentralizedDNSResolver(t *testing.T) {
	testCases := []struct {
		ip       string
		expected bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"9.9.9.9", true},
		{"4.2.2.4", true},
		{"2001:4860:4860::8888", true},
		{"2606:4700:4700::1001", true},
		{"192.168.1.1", false},
		{"8.8.8.9", false},
	}

	for _, tc := range testCases {
		res := IsCentralizedDNSResolver(tc.ip)
		if res != tc.expected {
			t.Errorf("IsCentralizedDNSResolver(%s) = %v, expected %v", tc.ip, res, tc.expected)
		}
	}
}
