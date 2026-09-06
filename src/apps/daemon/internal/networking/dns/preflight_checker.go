// Package dns implements domain name resolution and custom wizards.

package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

type PreflightKind string

const (
	PreflightKindToken PreflightKind = "token"
	PreflightKindZone  PreflightKind = "zone"
	PreflightKindDNS   PreflightKind = "dns"
)

var DefaultRecursiveResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// ZoneChecker interfaces zone retrieval logic.
type ZoneChecker interface {
	GetZoneByName(ctx context.Context, name string) (*Zone, error)
}

// DNSResolver interfaces DNS query exchanges.
type DNSResolver interface {
	Lookup(ctx context.Context, server, name string, qtype uint16) (DNSLookupResult, error)
}

// DelegationResolver returns the public nameserver targets carried by an NS
// answer. It is intentionally separate from DNSResolver: answer counts are
// sufficient for reachability checks but cannot establish delegation
// ownership.
type DelegationResolver interface {
	LookupNS(ctx context.Context, server, name string) ([]string, error)
}

// DNSLookupResult holds basic status and answer counts for queries.
type DNSLookupResult struct {
	RCode   int
	Answers int
}

// PreflightInput holds domain and token verification targets.
type PreflightInput struct {
	Domain      string
	ZoneChecker ZoneChecker
	Resolvers   []string
}

// PreflightChecker runs preflight verification queries.
type PreflightChecker struct {
	Resolver           DNSResolver
	DelegationResolver DelegationResolver
	Timeout            time.Duration
}

// PreflightError represents a failed preflight step.
type PreflightError struct {
	Kind        PreflightKind
	Domain      string
	Detail      string
	NameServers []string
	Cause       error
}

// Getters & Setters for PreflightError
func (e *PreflightError) GetKind() PreflightKind    { return e.Kind }
func (e *PreflightError) SetKind(v PreflightKind)   { e.Kind = v }
func (e *PreflightError) GetDomain() string         { return e.Domain }
func (e *PreflightError) SetDomain(v string)        { e.Domain = v }
func (e *PreflightError) GetDetail() string         { return e.Detail }
func (e *PreflightError) SetDetail(v string)        { e.Detail = v }
func (e *PreflightError) GetNameServers() []string  { return e.NameServers }
func (e *PreflightError) SetNameServers(v []string) { e.NameServers = v }

func (e PreflightError) Error() string {
	domain := strings.TrimSpace(e.Domain)
	if domain == "" {
		domain = "<domain>"
	}
	lines := []string{
		fmt.Sprintf("ACME DNS preflight failed for %s.", domain),
		fmt.Sprintf("WhiteDNS could not verify _acme-challenge.%s through public DNS.", domain),
		"Check that the domain is active in Cloudflare, registrar nameservers point to Cloudflare, and the API token is scoped to this zone.",
	}
	if strings.TrimSpace(e.Detail) != "" {
		lines = append(lines, "Detail: "+strings.TrimSpace(e.Detail))
	}
	if len(e.NameServers) > 0 {
		lines = append(lines, "Cloudflare nameservers: "+strings.Join(e.NameServers, ", "))
	}
	return strings.Join(lines, "\n")
}

func (e PreflightError) Unwrap() error {
	return e.Cause
}

func IsTokenPreflightError(err error) bool {
	var preflight PreflightError
	return errors.As(err, &preflight) && preflight.Kind == PreflightKindToken
}

func IsZoneOrDNSPreflightError(err error) bool {
	var preflight PreflightError
	return errors.As(err, &preflight) && (preflight.Kind == PreflightKindZone || preflight.Kind == PreflightKindDNS)
}

// Check validates nameservers, zone status, and SOA propagation.
// Maps to upstream PreflightChecker.Check().
func (c PreflightChecker) Check(ctx context.Context, input PreflightInput) error {
	domain := normalizeDomain(input.Domain)
	if domain == "" {
		return PreflightError{Kind: PreflightKindZone, Domain: input.Domain, Detail: "domain name is empty"}
	}
	if input.ZoneChecker == nil {
		return PreflightError{Kind: PreflightKindToken, Domain: domain, Detail: "Cloudflare zone checker is not configured"}
	}
	zone, err := resolveManagedZone(ctx, input.ZoneChecker, domain)
	if err != nil {
		return PreflightError{
			Kind:   PreflightKindToken,
			Domain: domain,
			Detail: fmt.Sprintf("Cloudflare zone %q was not found or the token cannot access it", domain),
			Cause:  err,
		}
	}
	if zone == nil {
		return PreflightError{Kind: PreflightKindToken, Domain: domain, Detail: fmt.Sprintf("Cloudflare zone %q was not found or the token cannot access it", domain)}
	}
	if !strings.EqualFold(strings.TrimSpace(zone.Status), "active") {
		return PreflightError{
			Kind:        PreflightKindZone,
			Domain:      domain,
			Detail:      fmt.Sprintf("Cloudflare zone status is %q, not active", zone.Status),
			NameServers: zone.NameServers,
		}
	}

	resolvers := input.Resolvers
	if len(resolvers) == 0 {
		resolvers = DefaultRecursiveResolvers
	}
	resolvers, err = normalizePreflightResolvers(resolvers)
	if err != nil {
		return PreflightError{Kind: PreflightKindDNS, Domain: domain, Detail: err.Error(), Cause: err}
	}
	zoneName := normalizeDomain(zone.Name)
	if zoneName == "" {
		return PreflightError{Kind: PreflightKindZone, Domain: domain, Detail: "managed zone name is empty"}
	}
	if _, ok := normalizeNameServerSet(zone.NameServers); !ok {
		return PreflightError{Kind: PreflightKindZone, Domain: domain, Detail: "provider returned an invalid nameserver assignment", NameServers: zone.NameServers}
	}
	delegationResolver := c.DelegationResolver
	if delegationResolver == nil {
		delegationResolver = DNSClientDelegationResolver{Timeout: c.Timeout}
	}
	if err := requirePublicDelegation(ctx, delegationResolver, resolvers, zoneName, zone.NameServers); err != nil {
		return PreflightError{Kind: PreflightKindDNS, Domain: domain, Detail: err.Error(), NameServers: zone.NameServers, Cause: err}
	}
	if domain != zoneName {
		if err := requireSafeChildDelegation(ctx, delegationResolver, resolvers, domain, zoneName, zone.NameServers); err != nil {
			return PreflightError{Kind: PreflightKindDNS, Domain: domain, Detail: err.Error(), NameServers: zone.NameServers, Cause: err}
		}
	}
	resolver := c.Resolver
	if resolver == nil {
		resolver = DNSClientResolver{Timeout: c.Timeout}
	}
	for _, check := range []struct {
		name  string
		qtype uint16
	}{
		{name: zoneName, qtype: mdns.TypeNS},
		{name: zoneName, qtype: mdns.TypeSOA},
	} {
		if err := requirePublicDNSAnswers(ctx, resolver, resolvers, check.name, check.qtype); err != nil {
			return PreflightError{Kind: PreflightKindDNS, Domain: domain, Detail: err.Error(), Cause: err}
		}
	}
	if err := requireChallengeSOAReachable(ctx, resolver, resolvers, "_acme-challenge."+domain); err != nil {
		return PreflightError{Kind: PreflightKindDNS, Domain: domain, Detail: err.Error(), Cause: err}
	}
	return nil
}

// DNSClientDelegationResolver resolves NS targets through a chosen recursive
// resolver. It does not follow or mutate provider state; it is evidence only.
type DNSClientDelegationResolver struct {
	Timeout time.Duration
}

func (r DNSClientDelegationResolver) LookupNS(ctx context.Context, server, name string) ([]string, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := &mdns.Client{Net: "udp", Timeout: timeout}
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(name), mdns.TypeNS)
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("empty DNS response received")
	}
	if resp.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("NS %s @%s returned %s", mdns.Fqdn(name), server, mdns.RcodeToString[resp.Rcode])
	}
	out := make([]string, 0, len(resp.Answer))
	for _, answer := range resp.Answer {
		ns, ok := answer.(*mdns.NS)
		if !ok {
			continue
		}
		out = append(out, ns.Ns)
		if len(out) > 32 {
			return nil, errors.New("NS answer exceeds 32-target limit")
		}
	}
	return out, nil
}

func requirePublicDelegation(ctx context.Context, resolver DelegationResolver, resolvers []string, zone string, providerNS []string) error {
	var details []string
	successes := 0
	for _, server := range resolvers {
		observed, err := resolver.LookupNS(ctx, server, zone)
		if err != nil {
			details = append(details, fmt.Sprintf("NS %s @%s failed: %v", mdns.Fqdn(zone), server, err))
			continue
		}
		successes++
		if !nameServerSetsEqual(providerNS, observed) {
			return fmt.Errorf("public delegation for %s at %s does not exactly match provider-assigned nameservers", mdns.Fqdn(zone), server)
		}
	}
	if successes == 0 {
		return fmt.Errorf("public delegation for %s could not be established: %s", mdns.Fqdn(zone), strings.Join(details, "; "))
	}
	return nil
}

func requireSafeChildDelegation(ctx context.Context, resolver DelegationResolver, resolvers []string, domain, zone string, providerNS []string) error {
	successes := 0
	for _, server := range resolvers {
		observed, err := resolver.LookupNS(ctx, server, domain)
		if err != nil {
			continue
		}
		successes++
		if err := validateChildDelegation(domain, zone, providerNS, observed); err != nil {
			return fmt.Errorf("%w (resolver %s)", err, server)
		}
	}
	if successes == 0 {
		return fmt.Errorf("child delegation for %s could not be established", mdns.Fqdn(domain))
	}
	return nil
}

// DNSClientResolver implements DNSResolver using UDP sockets.
type DNSClientResolver struct {
	Timeout time.Duration
}

// Lookup queries the target DNS server. Maps to upstream DNSClientResolver.Lookup().
func (r DNSClientResolver) Lookup(ctx context.Context, server, name string, qtype uint16) (DNSLookupResult, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := &mdns.Client{Net: "udp", Timeout: timeout}
	msg := new(mdns.Msg)
	msg.SetQuestion(mdns.Fqdn(name), qtype)
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return DNSLookupResult{}, err
	}
	if resp == nil {
		return DNSLookupResult{}, fmt.Errorf("empty DNS response received")
	}
	return DNSLookupResult{RCode: resp.Rcode, Answers: len(resp.Answer)}, nil
}

func requirePublicDNSAnswers(ctx context.Context, resolver DNSResolver, resolvers []string, name string, qtype uint16) error {
	var details []string
	for _, server := range resolvers {
		result, err := resolver.Lookup(ctx, server, name, qtype)
		if err != nil {
			details = append(details, fmt.Sprintf("%s %s @%s failed: %v", mdns.TypeToString[qtype], mdns.Fqdn(name), server, err))
			continue
		}
		if result.RCode != mdns.RcodeSuccess {
			details = append(details, fmt.Sprintf("%s %s @%s returned %s", mdns.TypeToString[qtype], mdns.Fqdn(name), server, mdns.RcodeToString[result.RCode]))
			continue
		}
		if result.Answers == 0 {
			details = append(details, fmt.Sprintf("%s %s @%s returned no answers", mdns.TypeToString[qtype], mdns.Fqdn(name), server))
			continue
		}
		return nil
	}
	return errors.New(strings.Join(details, "; "))
}

func requireChallengeSOAReachable(ctx context.Context, resolver DNSResolver, resolvers []string, name string) error {
	var details []string
	for _, server := range resolvers {
		result, err := resolver.Lookup(ctx, server, name, mdns.TypeSOA)
		if err != nil {
			details = append(details, fmt.Sprintf("SOA %s @%s failed: %v", mdns.Fqdn(name), server, err))
			continue
		}
		if result.RCode == mdns.RcodeSuccess || result.RCode == mdns.RcodeNameError {
			return nil
		}
		details = append(details, fmt.Sprintf("SOA %s @%s returned %s", mdns.Fqdn(name), server, mdns.RcodeToString[result.RCode]))
	}
	return errors.New(strings.Join(details, "; "))
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}
