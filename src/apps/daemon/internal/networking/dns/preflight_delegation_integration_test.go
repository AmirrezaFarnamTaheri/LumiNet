package dns

import (
	"context"
	"errors"
	"testing"

	mdns "github.com/miekg/dns"
)

type integrationDNSResolver struct{}

func (integrationDNSResolver) Lookup(context.Context, string, string, uint16) (DNSLookupResult, error) {
	return DNSLookupResult{RCode: mdns.RcodeSuccess, Answers: 1}, nil
}

type integrationNSResolver struct {
	answers map[string][]string
	errs    map[string]error
}

func (r integrationNSResolver) LookupNS(_ context.Context, server, name string) ([]string, error) {
	key := server + "|" + normalizeDelegationName(name)
	if err := r.errs[key]; err != nil {
		return nil, err
	}
	return append([]string(nil), r.answers[key]...), nil
}

func TestPreflightRequiresProviderDelegationAndRejectsDelegatedChild(t *testing.T) {
	zoneChecker := &delegationZoneChecker{zones: map[string]*Zone{
		"example.com": {ID: "z", Name: "example.com", Status: "active", NameServers: []string{"a.ns.example", "b.ns.example"}},
	}}
	resolvers := []string{"r1:53", "r2:53"}
	base := map[string][]string{
		"r1:53|example.com": {"a.ns.example.", "b.ns.example."},
		"r2:53|example.com": {"b.ns.example", "a.ns.example"},
	}

	t.Run("matching parent and undelegated child pass", func(t *testing.T) {
		checker := PreflightChecker{Resolver: integrationDNSResolver{}, DelegationResolver: integrationNSResolver{answers: base, errs: map[string]error{}}}
		if err := checker.Check(context.Background(), PreflightInput{Domain: "api.example.com", ZoneChecker: zoneChecker, Resolvers: resolvers}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("parent delegation mismatch fails", func(t *testing.T) {
		answers := map[string][]string{}
		for k, v := range base {
			answers[k] = append([]string(nil), v...)
		}
		answers["r2:53|example.com"] = []string{"ns1.other.net", "ns2.other.net"}
		checker := PreflightChecker{Resolver: integrationDNSResolver{}, DelegationResolver: integrationNSResolver{answers: answers, errs: map[string]error{}}}
		if err := checker.Check(context.Background(), PreflightInput{Domain: "api.example.com", ZoneChecker: zoneChecker, Resolvers: resolvers}); err == nil {
			t.Fatal("mismatched public parent delegation accepted")
		}
	})

	t.Run("independently delegated child fails", func(t *testing.T) {
		answers := map[string][]string{}
		for k, v := range base {
			answers[k] = append([]string(nil), v...)
		}
		answers["r1:53|api.example.com"] = []string{"child1.other.net", "child2.other.net"}
		checker := PreflightChecker{Resolver: integrationDNSResolver{}, DelegationResolver: integrationNSResolver{answers: answers, errs: map[string]error{}}}
		if err := checker.Check(context.Background(), PreflightInput{Domain: "api.example.com", ZoneChecker: zoneChecker, Resolvers: resolvers}); err == nil {
			t.Fatal("independently delegated child accepted")
		}
	})

	t.Run("no delegation evidence fails closed", func(t *testing.T) {
		errs := map[string]error{
			"r1:53|example.com": errors.New("timeout"),
			"r2:53|example.com": errors.New("timeout"),
		}
		checker := PreflightChecker{Resolver: integrationDNSResolver{}, DelegationResolver: integrationNSResolver{answers: map[string][]string{}, errs: errs}}
		if err := checker.Check(context.Background(), PreflightInput{Domain: "api.example.com", ZoneChecker: zoneChecker, Resolvers: resolvers}); err == nil {
			t.Fatal("preflight accepted without public delegation evidence")
		}
	})
}
