package diagnostics

import (
	"context"
	"testing"
)

func TestIPSecurityClassificationContract(t *testing.T) {
	cases := []struct {
		asn      int
		org      string
		score    int
		category string
	}{
		{13335, "Cloudflare", 30, "Hosting/Datacenter"}, {0, "NordVPN", 50, "VPN/Proxy"}, {0, "MCI", 100, "Mobile/Cellular"}, {0, "Comcast", 100, "Residential/Clean"},
	}
	for _, c := range cases {
		got := AnalyzeIPSecurity(context.Background(), "1.2.3.4", c.asn, c.org)
		if got.Score != c.score || got.Category != c.category {
			t.Fatalf("%s => %#v", c.org, got)
		}
	}
}
