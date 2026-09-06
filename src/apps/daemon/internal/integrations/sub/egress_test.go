package sub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestEgressRequiresExplicitEnablement(t *testing.T) {
	egress := NewEgress(EgressConfig{})
	_, err := egress.Fetch(context.Background(), "https://example.com/sub")
	if !errors.Is(err, ErrRemoteFetchDisabled) {
		t.Fatalf("err = %v, want %v", err, ErrRemoteFetchDisabled)
	}
}

func TestEgressRejectsUnsafeAddresses(t *testing.T) {
	privateResolver := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	egress := NewEgress(EgressConfig{Enabled: true, Resolve: privateResolver})
	_, err := egress.Fetch(context.Background(), "https://subscription.example/sub")
	if !errors.Is(err, ErrUnsafeRemoteTarget) {
		t.Fatalf("err = %v, want %v", err, ErrUnsafeRemoteTarget)
	}
}

func TestEgressRejectsHTTPAndNonstandardPorts(t *testing.T) {
	egress := NewEgress(EgressConfig{Enabled: true})
	for _, rawURL := range []string{"http://subscription.example/sub", "https://subscription.example:8443/sub"} {
		_, err := egress.Fetch(context.Background(), rawURL)
		if !errors.Is(err, ErrUnsafeRemoteTarget) {
			t.Fatalf("url=%s err=%v, want %v", rawURL, err, ErrUnsafeRemoteTarget)
		}
	}
}

func TestEgressAllowsPublicAddress(t *testing.T) {
	publicResolver := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	egress := NewEgress(EgressConfig{Enabled: true, Resolve: publicResolver})
	addresses, err := egress.resolvePublic(context.Background(), "subscription.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("addresses = %v", addresses)
	}
}

func TestEgressRejectsSpecialUseAddresses(t *testing.T) {
	for _, raw := range []string{"198.18.0.1", "198.51.100.1", "2001:db8::1"} {
		if isPublicAddress(netip.MustParseAddr(raw)) {
			t.Fatalf("special-use address %s was accepted", raw)
		}
	}
}

func TestValidateProfileSourceURLStaticBoundary(t *testing.T) {
	for _, raw := range []string{"http://example.com/sub", "https://user:pass@example.com/sub", "https://example.com:8443/sub", "https://" + strings.Repeat("x", maxProfileSourceURLLen)} {
		if err := ValidateProfileSourceURL(raw); err == nil {
			t.Fatalf("unsafe source accepted: %q", raw)
		}
	}
	if err := ValidateProfileSourceURL("https://example.com/sub?token=opaque"); err != nil {
		t.Fatalf("valid source rejected: %v", err)
	}
}

func TestNormalizeSourceETagRejectsUnsafeOrOversizedValues(t *testing.T) {
	for _, value := range []string{"", "abc\r\ndef", strings.Repeat("x", maxSourceETagLen+1)} {
		if got := normalizeSourceETag(value); got != "" {
			t.Fatalf("unsafe etag %q normalized to %q", value, got)
		}
	}
	if got := normalizeSourceETag(` W/"v1" `); got != `W/"v1"` {
		t.Fatalf("valid etag normalized to %q", got)
	}
}

func TestEgressRedirectPolicyRestoresFiniteBudget(t *testing.T) {
	publicResolver := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	egress := NewEgress(EgressConfig{Enabled: true, Resolve: publicResolver})
	via := make([]*http.Request, 0, maxSubscriptionRedirects)
	for i := 0; i < maxSubscriptionRedirects; i++ {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://example.com/r/%d", i), nil)
		if err != nil {
			t.Fatal(err)
		}
		via = append(via, req)
	}
	next, _ := http.NewRequest(http.MethodGet, "https://example.com/final", nil)
	if err := egress.client.CheckRedirect(next, via); !errors.Is(err, ErrSubscriptionRedirectLimit) {
		t.Fatalf("redirect limit err=%v, want %v", err, ErrSubscriptionRedirectLimit)
	}
}

func TestEgressRedirectPolicyRejectsLoopBeforeBudget(t *testing.T) {
	publicResolver := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	egress := NewEgress(EgressConfig{Enabled: true, Resolve: publicResolver})
	first, _ := http.NewRequest(http.MethodGet, "https://EXAMPLE.com/path#first", nil)
	next, _ := http.NewRequest(http.MethodGet, "https://example.com:443/path#second", nil)
	if err := egress.client.CheckRedirect(next, []*http.Request{first}); !errors.Is(err, ErrSubscriptionRedirectLimit) {
		t.Fatalf("redirect loop err=%v, want %v", err, ErrSubscriptionRedirectLimit)
	}
}

func TestEgressRedirectPolicyStripsValidatorAcrossOrigin(t *testing.T) {
	publicResolver := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	egress := NewEgress(EgressConfig{Enabled: true, Resolve: publicResolver})
	first, _ := http.NewRequest(http.MethodGet, "https://a.example/sub", nil)
	next, _ := http.NewRequest(http.MethodGet, "https://b.example/sub", nil)
	next.Header.Set("If-None-Match", `"opaque"`)
	if err := egress.client.CheckRedirect(next, []*http.Request{first}); err != nil {
		t.Fatal(err)
	}
	if got := next.Header.Get("If-None-Match"); got != "" {
		t.Fatalf("cross-origin validator leaked: %q", got)
	}
}
