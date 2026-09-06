package proxyconfig

import (
	"strings"
	"testing"
)

func TestIsEdgePorts(t *testing.T) {
	// Standard Cloudflare edge HTTP ports
	for _, port := range []int{80, 8080, 8880, 2052, 2082, 2086, 2095} {
		if !IsEdgeHttpPort(port) {
			t.Errorf("Expected port %d to be recognized as edge HTTP port", port)
		}
	}

	// Standard Cloudflare edge HTTPS ports
	for _, port := range []int{443, 8443, 2053, 2083, 2087, 2096} {
		if !IsEdgeHttpsPort(port) {
			t.Errorf("Expected port %d to be recognized as edge HTTPS port", port)
		}
	}

	// Non-edge ports
	if IsEdgeHttpPort(12345) || IsEdgeHttpsPort(12345) {
		t.Errorf("Port 12345 should not be recognized as an edge port")
	}
}

func TestGenerateEdgeRemark(t *testing.T) {
	// Clean IP with fragment and custom domain
	opts := EdgeRemarkOptions{
		Index:          1,
		Port:           443,
		Address:        "104.16.1.1",
		Protocol:       "vless",
		Domain:         "edge.worker.dev",
		CustomDomain:   "edge.worker.dev",
		IsFragment:     true,
		IsChain:        false,
		CleanIPs:       []string{"104.16.1.1"},
		CustomCdnAddrs: nil,
	}

	remark := GenerateEdgeRemark(opts)
	if !strings.Contains(remark, "💦 1. VLESS F D - Clean IP : 443") {
		t.Errorf("Unexpected remark output: %s", remark)
	}

	// Upstream proxy chain
	chainOpts := EdgeRemarkOptions{
		Index:          2,
		Port:           8443,
		Address:        "upstream.proxy.local",
		Protocol:       "trojan",
		Domain:         "main.domain",
		IsFragment:     false,
		IsChain:        true,
		UpstreamServer: "upstream.proxy.local",
	}

	chainRemark := GenerateEdgeRemark(chainOpts)
	if !strings.Contains(chainRemark, "💦 2. 🔗 TROJAN - Upstream Proxy") {
		t.Errorf("Unexpected chain remark output: %s", chainRemark)
	}
}

func TestBuildEdgeUrlTestGroup(t *testing.T) {
	group := BuildEdgeUrlTestGroup("Best Ping", []string{"node1", "node2"}, false)
	if group.Tag != "Best Ping" {
		t.Errorf("Expected tag 'Best Ping', got %s", group.Tag)
	}
	if group.URL != "https://www.gstatic.com/generate_204" {
		t.Errorf("Expected standard gstatic URL, got %s", group.URL)
	}

	warpGroup := BuildEdgeUrlTestGroup("Best Ping Warp", []string{"warp1"}, true)
	if warpGroup.URL != "https://cloudflare.com/cdn-cgi/trace" {
		t.Errorf("Expected Cloudflare trace URL for WARP, got %s", warpGroup.URL)
	}
}
