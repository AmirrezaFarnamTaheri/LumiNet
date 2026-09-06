package auth

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// AcmeResolver verifies DNS-01 TXT challenge records.
type AcmeResolver struct {
	Timeout time.Duration
}

// NewAcmeResolver creates an instance of AcmeResolver.
func NewAcmeResolver() *AcmeResolver {
	return &AcmeResolver{
		Timeout: 5 * time.Second,
	}
}

// CheckPreflight queries dynamic DNS TXT records to confirm propagation.
func (r *AcmeResolver) CheckPreflight(ctx context.Context, domain, expectedTXT string) (bool, error) {
	fqdn := domain
	if !strings.HasPrefix(fqdn, "_acme-challenge.") {
		fqdn = "_acme-challenge." + fqdn
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.Timeout}
			return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	txts, err := resolver.LookupTXT(ctx, fqdn)
	if err != nil {
		return false, fmt.Errorf("preflight check failed: %w", err)
	}

	for _, txt := range txts {
		if txt == expectedTXT {
			return true, nil
		}
	}

	return false, nil
}
