package dns

import (
	"context"
	"net"
	"time"
)

// ResolveDomain resolves a domain with the system resolver, then falls back to
// Cloudflare DNS. The resolver is stateless; historical SmartDNS mutable state
// had no product consumer and is intentionally retired.
func ResolveDomain(ctx context.Context, domain string) ([]string, error) {
	ips, err := (&net.Resolver{}).LookupHost(ctx, domain)
	if err == nil {
		return ips, nil
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	fallback := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}
	return fallback.LookupHost(ctx, domain)
}
