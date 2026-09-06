// Package telemetry implements observation and diagnostic endpoints.
package telemetry

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// LookingGlassResult holds one diagnostic probe result.
type LookingGlassResult struct {
	Type    string
	Target  string
	Output  string
	Latency time.Duration
	Error   error
}

// NetworkDiagnosticTools provides Looking Glass diagnostics (DNS, PTR, BGP, reachability).
type NetworkDiagnosticTools struct {
	HTTPClient   *http.Client
	RIPEAtlasKey string
}

func NewNetworkDiagnosticTools() *NetworkDiagnosticTools {
	return &NetworkDiagnosticTools{HTTPClient: &http.Client{Timeout: 15 * time.Second}}
}

// Diagnose runs DNS, PTR, and TCP reachability probes against target.
func (n *NetworkDiagnosticTools) Diagnose(ctx context.Context, target string) []LookingGlassResult {
	return []LookingGlassResult{
		n.probeDNS(ctx, target),
		n.probePTR(ctx, target),
		n.probeReach(ctx, target),
	}
}

func (n *NetworkDiagnosticTools) probeDNS(ctx context.Context, host string) LookingGlassResult {
	t0 := time.Now()
	addrs, err := (&net.Resolver{}).LookupHost(ctx, host)
	return LookingGlassResult{"dns", host, strings.Join(addrs, ", "), time.Since(t0), err}
}

func (n *NetworkDiagnosticTools) probePTR(ctx context.Context, ip string) LookingGlassResult {
	t0 := time.Now()
	names, err := (&net.Resolver{}).LookupAddr(ctx, ip)
	return LookingGlassResult{"ptr", ip, strings.Join(names, ", "), time.Since(t0), err}
}

func (n *NetworkDiagnosticTools) probeReach(ctx context.Context, host string) LookingGlassResult {
	t0 := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, "80"))
	lat := time.Since(t0)
	if err != nil {
		return LookingGlassResult{"reach", host, "unreachable", lat, err}
	}
	conn.Close()
	return LookingGlassResult{"reach", host, "reachable", lat, nil}
}

// BGPHint queries RIPE Stat API for prefix info about ip.
func (n *NetworkDiagnosticTools) BGPHint(ctx context.Context, ip string) (string, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/prefix-overview/data.json?resource=%s", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := n.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("NetworkDiagnosticTools.BGPHint: %w", err)
	}
	defer resp.Body.Close()
	return fmt.Sprintf("BGP data retrieved for %s (status %d)", ip, resp.StatusCode), nil
}