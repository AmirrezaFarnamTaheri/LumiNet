package dns

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const maxPreflightResolvers = 8

func resolveManagedZone(ctx context.Context, checker ZoneChecker, domain string) (*Zone, error) {
	domain = normalizeDelegationName(domain)
	if domain == "" || checker == nil {
		return nil, errors.New("managed zone lookup is not configured")
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return nil, fmt.Errorf("domain %q has no registrable parent candidate", domain)
	}
	var lastErr error
	for i := 0; i <= len(labels)-2; i++ {
		candidate := strings.Join(labels[i:], ".")
		zone, err := checker.GetZoneByName(ctx, candidate)
		if err == nil && zone != nil {
			return zone, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no accessible managed zone found")
	}
	return nil, fmt.Errorf("resolve managed zone for %q: %w", domain, lastErr)
}

func nameServerSetsEqual(left, right []string) bool {
	l, lok := normalizeNameServerSet(left)
	r, rok := normalizeNameServerSet(right)
	if !lok || !rok || len(l) != len(r) || len(l) == 0 {
		return false
	}
	for i := range l {
		if l[i] != r[i] {
			return false
		}
	}
	return true
}

func normalizeNameServerSet(values []string) ([]string, bool) {
	if len(values) == 0 || len(values) > 32 {
		return nil, false
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		name := normalizeDelegationName(value)
		if name == "" || len(name) > 253 {
			return nil, false
		}
		if _, exists := seen[name]; exists {
			return nil, false
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out, true
}

func normalizePreflightResolvers(values []string) ([]string, error) {
	if len(values) > maxPreflightResolvers {
		return nil, fmt.Errorf("resolver count %d exceeds limit %d", len(values), maxPreflightResolvers)
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		resolver := strings.TrimSpace(value)
		if resolver == "" || len(resolver) > 255 {
			return nil, errors.New("preflight resolver is empty or too long")
		}
		if _, exists := seen[resolver]; exists {
			continue
		}
		seen[resolver] = struct{}{}
		out = append(out, resolver)
	}
	if len(out) == 0 {
		return nil, errors.New("no preflight resolvers configured")
	}
	return out, nil
}

func validateChildDelegation(domain, zoneName string, providerNS, childNS []string) error {
	domain = normalizeDelegationName(domain)
	zoneName = normalizeDelegationName(zoneName)
	if domain == "" || zoneName == "" {
		return errors.New("domain or managed zone is empty")
	}
	if domain == zoneName {
		return nil
	}
	if !strings.HasSuffix(domain, "."+zoneName) {
		return fmt.Errorf("domain %q is outside managed zone %q", domain, zoneName)
	}
	if len(childNS) == 0 {
		return nil
	}
	if !nameServerSetsEqual(providerNS, childNS) {
		return fmt.Errorf("subdomain %q is independently delegated", domain)
	}
	return nil
}

func normalizeDelegationName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
