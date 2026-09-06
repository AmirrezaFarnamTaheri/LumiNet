package proxy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type trustedDoHProvider struct {
	Name string
	URL  string
}

var trustedProviders = []trustedDoHProvider{
	{Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query?name=%s&type=A"},
	{Name: "Google", URL: "https://dns.google/dns-query?name=%s&type=A"},
	{Name: "Quad9", URL: "https://dns.quad9.net/dns-query?name=%s&type=A"},
}

type dohJSONResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

type DnsTruthTable struct {
	Domain   string
	TruthIPs map[string]bool
	mu       sync.RWMutex
	Provider string
}

func NewDnsTruthTable(domain string) *DnsTruthTable {
	return &DnsTruthTable{
		Domain:   domain,
		TruthIPs: make(map[string]bool),
	}
}

func (t *DnsTruthTable) FetchTruth() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}

	for _, provider := range trustedProviders {
		url := fmt.Sprintf(provider.URL, t.Domain)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}

		var dohResp dohJSONResponse
		if err := json.Unmarshal(body, &dohResp); err != nil {
			continue
		}

		if dohResp.Status != 0 {
			continue
		}

		for _, ans := range dohResp.Answer {
			if ans.Type == 1 {
				ip := strings.TrimSpace(ans.Data)
				if net.ParseIP(ip) != nil {
					t.TruthIPs[ip] = true
				}
			}
		}

		if len(t.TruthIPs) > 0 {
			t.Provider = provider.Name
			return nil
		}
	}

	fallbacks := map[string][]string{
		"google.com":    {"142.250.80.46", "142.250.80.78", "142.250.80.110"},
		"speedtest.net": {"151.139.72.2"},
		"facebook.com":  {"157.240.1.35", "157.240.3.35"},
	}

	if ips, ok := fallbacks[t.Domain]; ok {
		for _, ip := range ips {
			t.TruthIPs[ip] = true
		}
		t.Provider = "Hardcoded Fallback"
		return nil
	}

	return fmt.Errorf("dns_truth_table: failed to fetch truth for %s", t.Domain)
}

func (t *DnsTruthTable) Verify(ips []string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.TruthIPs) == 0 {
		return true
	}

	for _, ip := range ips {
		if t.TruthIPs[ip] {
			return true
		}
	}
	return false
}
