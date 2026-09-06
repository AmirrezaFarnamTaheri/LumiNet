package proxyconfig

import (
	"fmt"
	"net"
	"strings"
)

// Standard Cloudflare Edge Ingress Ports
var (
	EdgeHttpPorts  = []int{80, 8080, 8880, 2052, 2082, 2086, 2095}
	EdgeHttpsPorts = []int{443, 8443, 2053, 2083, 2087, 2096}
)

// IsEdgeHttpPort checks if a port is in the allowed Cloudflare HTTP port set.
func IsEdgeHttpPort(port int) bool {
	for _, p := range EdgeHttpPorts {
		if p == port {
			return true
		}
	}
	return false
}

// IsEdgeHttpsPort checks if a port is in the allowed Cloudflare HTTPS port set.
func IsEdgeHttpsPort(port int) bool {
	for _, p := range EdgeHttpsPorts {
		if p == port {
			return true
		}
	}
	return false
}

// EdgeRemarkOptions configures remark generation for edge panel proxies.
type EdgeRemarkOptions struct {
	Index          int
	Port           int
	Address        string
	Protocol       string
	Domain         string
	CustomDomain   string
	IsFragment     bool
	IsChain        bool
	CleanIPs       []string
	CustomCdnAddrs []string
	UpstreamServer string
}

// GenerateEdgeRemark creates a standardized remark for edge panel subscription endpoints.
func GenerateEdgeRemark(opts EdgeRemarkOptions) string {
	chainSign := ""
	if opts.IsChain {
		chainSign = "🔗 "
	}

	protoSign := strings.ToUpper(opts.Protocol)

	configType := ""
	if opts.IsFragment {
		configType += "F "
	}
	if opts.CustomDomain != "" && opts.Domain == opts.CustomDomain {
		configType += "D "
	}
	for _, cdn := range opts.CustomCdnAddrs {
		if opts.Address == cdn {
			configType += "C "
			break
		}
	}

	addressType := "Domain"
	for _, clean := range opts.CleanIPs {
		if opts.Address == clean {
			addressType = "Clean IP"
			break
		}
	}
	if addressType != "Clean IP" {
		if ip := net.ParseIP(opts.Address); ip != nil {
			if ip.To4() != nil {
				addressType = "IPv4"
			} else {
				addressType = "IPv6"
			}
		}
	}

	if opts.UpstreamServer != "" && opts.Address == opts.UpstreamServer {
		return fmt.Sprintf("💦 %d. %s%s %s- Upstream Proxy", opts.Index, chainSign, protoSign, configType)
	}

	return fmt.Sprintf("💦 %d. %s%s %s- %s : %d", opts.Index, chainSign, protoSign, configType, addressType, opts.Port)
}

// EdgeFragmentConfig holds TLS client hello fragmentation parameters.
type EdgeFragmentConfig struct {
	Length   string `json:"length"`   // e.g. "100-200"
	Interval string `json:"interval"` // e.g. "10-20"
	Packets  string `json:"packets"`  // e.g. "1-3" or "tlshello"
}

// DefaultEdgeFragmentConfig returns recommended anti-DPI fragmentation ranges.
func DefaultEdgeFragmentConfig() EdgeFragmentConfig {
	return EdgeFragmentConfig{
		Length:   "100-200",
		Interval: "10-20",
		Packets:  "1-3",
	}
}

// EdgeUrlTestGroup defines an automated low-latency selector group for sing-box/clash.
type EdgeUrlTestGroup struct {
	Tag       string   `json:"tag"`
	Outbounds []string `json:"outbounds"`
	URL       string   `json:"url"`
	Interval  string   `json:"interval"`
	Tolerance int      `json:"tolerance"`
}

// BuildEdgeUrlTestGroup constructs a health-checked latency testing outbound group.
func BuildEdgeUrlTestGroup(tag string, outbounds []string, isWarp bool) EdgeUrlTestGroup {
	testUrl := "https://www.gstatic.com/generate_204"
	if isWarp {
		testUrl = "https://cloudflare.com/cdn-cgi/trace"
	}

	return EdgeUrlTestGroup{
		Tag:       tag,
		Outbounds: outbounds,
		URL:       testUrl,
		Interval:  "3m",
		Tolerance: 50,
	}
}
