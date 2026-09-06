package diagnostics

import (
	"context"
	"net"
	"sort"
	"time"
)

var cloudflareCleanPool = []string{
	"104.16.248.249", "104.16.249.249", "104.18.26.155", "104.18.27.155",
	"172.67.73.91", "104.21.19.167", "104.21.57.172", "172.67.189.50",
}

type cleanIPResult struct {
	ip      string
	latency time.Duration
	err     error
}

// ProbeCleanCloudflareIPs probes the canonical candidate pool and returns the
// fastest reachable addresses plus a copy of the canonical pool.
func ProbeCleanCloudflareIPs(ctx context.Context, count int, timeout time.Duration) ([]string, []string) {
	pool := append([]string(nil), cloudflareCleanPool...)
	ch := make(chan cleanIPResult, len(pool))
	for _, ip := range pool {
		go func(target string) {
			start := time.Now()
			conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", net.JoinHostPort(target, "443"))
			if err == nil {
				_ = conn.Close()
			}
			ch <- cleanIPResult{ip: target, latency: time.Since(start), err: err}
		}(ip)
	}
	active := make([]cleanIPResult, 0, len(pool))
	for range pool {
		r := <-ch
		if r.err == nil {
			active = append(active, r)
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].latency < active[j].latency })
	if count <= 0 {
		count = len(active)
	}
	if count > len(active) {
		count = len(active)
	}
	found := make([]string, count)
	for i := 0; i < count; i++ {
		found[i] = active[i].ip
	}
	return found, pool
}
