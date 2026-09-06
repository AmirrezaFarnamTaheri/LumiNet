package jobs

import (
	"fmt"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
)

type diagnosticPhase struct {
	id      int
	name    string
	metric  diagnostics.MetricType
	target  string
	timeout time.Duration
	options map[string]string
}

func buildDiagnosticPlan(config DiagnosticIntent) ([]diagnosticPhase, bool, error) {

	typeName := strings.ToLower(strings.TrimSpace(config.Type))
	if typeName == "" || typeName == "full" || typeName == "all" {
		return fullDiagnosticPlan(), false, nil
	}

	metric := diagnostics.MetricType(typeName)
	if !supportedDiagnosticMetric(metric) {
		return nil, false, fmt.Errorf("unsupported diagnostic type %q", config.Type)
	}

	timeoutSeconds := config.Timeout
	if timeoutSeconds <= 0 {
		timeoutSeconds = 15
	}
	if timeoutSeconds > 300 {
		return nil, false, fmt.Errorf("diagnostic timeout must not exceed 300 seconds")
	}

	return []diagnosticPhase{{
		id:      1,
		name:    diagnosticDisplayName(metric),
		metric:  metric,
		target:  defaultDiagnosticTarget(metric, strings.TrimSpace(config.Target)),
		timeout: time.Duration(timeoutSeconds) * time.Second,
		options: cloneStringMap(config.Options),
	}}, true, nil
}

func fullDiagnosticPlan() []diagnosticPhase {
	const timeout = 15 * time.Second
	return []diagnosticPhase{
		{id: 1, name: "Local Interface Check", metric: diagnostics.MetricPing, target: "127.0.0.1", timeout: timeout},
		{id: 2, name: "Gateway Connectivity", metric: diagnostics.MetricPing, target: "1.1.1.1", timeout: timeout},
		{id: 3, name: "DNS Resolution Audit", metric: diagnostics.MetricDNS, target: "google.com", timeout: timeout},
		{id: 4, name: "Protocol Handshake", metric: diagnostics.MetricHTTP, target: "http://cp.cloudflare.com/", timeout: timeout},
		{id: 5, name: "Path Trace Analytics", metric: diagnostics.MetricTraceRoute, target: "8.8.8.8", timeout: timeout},
		{id: 6, name: "Egress Throughput", metric: diagnostics.MetricSpeedTest, timeout: timeout},
		{id: 7, name: "Reliable UDP ARQ Benchmark", metric: diagnostics.MetricARQ, target: "loopback", timeout: timeout},
		{id: 8, name: "Browser Stealth & Anti-Fingerprint Audit", metric: diagnostics.MetricStealth, target: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", timeout: timeout},
		{id: 9, name: "ISP Spoofing & ASN Check", metric: diagnostics.MetricAsnSpoof, target: "1.1.1.1", timeout: timeout},
		{id: 10, name: "Network Sniffer Detection", metric: diagnostics.MetricSnifferDetect, timeout: timeout},
		{id: 11, name: "Local Subnet Discovery", metric: diagnostics.MetricArpCache, timeout: timeout},
	}
}

func supportedDiagnosticMetric(metric diagnostics.MetricType) bool {
	switch metric {
	case diagnostics.MetricPing,
		diagnostics.MetricTraceRoute,
		diagnostics.MetricDNS,
		diagnostics.MetricHTTP,
		diagnostics.MetricSpeedTest,
		diagnostics.MetricARQ,
		diagnostics.MetricStealth,
		diagnostics.MetricAsnSpoof,
		diagnostics.MetricSnifferDetect,
		diagnostics.MetricArpCache,
		diagnostics.MetricSniMatrix:
		return true
	default:
		return false
	}
}

func defaultDiagnosticTarget(metric diagnostics.MetricType, target string) string {
	if target != "" {
		return target
	}
	switch metric {
	case diagnostics.MetricPing, diagnostics.MetricTraceRoute, diagnostics.MetricAsnSpoof:
		return "1.1.1.1"
	case diagnostics.MetricDNS:
		return "google.com"
	case diagnostics.MetricHTTP:
		return "http://cp.cloudflare.com/"
	case diagnostics.MetricARQ:
		return "loopback"
	case diagnostics.MetricStealth:
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	case diagnostics.MetricSniMatrix:
		return "104.16.124.96"
	default:
		return ""
	}
}

func diagnosticDisplayName(metric diagnostics.MetricType) string {
	switch metric {
	case diagnostics.MetricPing:
		return "Ping"
	case diagnostics.MetricTraceRoute:
		return "Trace Route"
	case diagnostics.MetricDNS:
		return "DNS"
	case diagnostics.MetricHTTP:
		return "HTTP"
	case diagnostics.MetricSpeedTest:
		return "Speed Test"
	case diagnostics.MetricARQ:
		return "ARQ"
	case diagnostics.MetricStealth:
		return "Stealth"
	case diagnostics.MetricAsnSpoof:
		return "ASN Spoofing"
	case diagnostics.MetricSnifferDetect:
		return "Sniffer Detection"
	case diagnostics.MetricArpCache:
		return "ARP Cache"
	case diagnostics.MetricSniMatrix:
		return "SNI Matrix"
	default:
		return string(metric)
	}
}

func cloneStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}
