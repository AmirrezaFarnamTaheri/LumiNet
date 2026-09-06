package diagnostics

import (
	"context"
	"strings"
)

// IPSecurityReport is the public classification result.
type IPSecurityReport struct {
	IP       string `json:"ip"`
	Score    int    `json:"score"`
	Category string `json:"category"`
}

var hostingASNs = func() map[int]bool {
	values := []int{13335, 15169, 16509, 14618, 8075, 14061, 16276, 24940, 20473, 63949, 31898, 45102, 20940, 54113, 60068, 9009, 62240, 53667, 398101, 396982, 395747, 396356, 212238, 202425, 199524, 51167, 12876, 24961, 20454, 36352, 55286, 8100, 40676, 18779, 29802, 46652, 35916, 30083, 30633, 138997}
	out := make(map[int]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}()
var hostingWords = []string{"hosting", "host", "cloud", "datacenter", "data center", "server", "colo", "vps", "amazon", "aws", "google llc", "microsoft", "azure", "digitalocean", "hetzner", "ovh", "vultr", "linode", "fastly", "cloudflare"}
var vpnWords = []string{"vpn", "proxy", "privacy", "anonymous", "tor", "exit", "relay", "tunnel", "hide", "residential proxy", "nordvpn", "expressvpn", "surfshark", "mullvad", "proton", "windscribe"}
var mobileWords = []string{"mobile", "cellular", "wireless", "lte", "4g", "5g", "telecom", "vodafone", "verizon", "t-mobile", "orange", "mtn", "irancell", "mci"}

// AnalyzeIPSecurity classifies connection metadata using the repository's
// canonical immutable ASN/organization signatures.
func AnalyzeIPSecurity(_ context.Context, ip string, asn int, org string) IPSecurityReport {
	score, category := 100, "Residential/Clean"
	lower := strings.ToLower(org)
	if hostingASNs[asn] {
		score -= 40
		category = "Hosting/Datacenter"
	}
	for _, word := range hostingWords {
		if strings.Contains(lower, word) {
			score -= 30
			category = "Hosting/Datacenter"
			break
		}
	}
	for _, word := range vpnWords {
		if strings.Contains(lower, word) {
			score -= 50
			category = "VPN/Proxy"
			break
		}
	}
	for _, word := range mobileWords {
		if strings.Contains(lower, word) {
			score += 10
			category = "Mobile/Cellular"
			break
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return IPSecurityReport{IP: ip, Score: score, Category: category}
}
