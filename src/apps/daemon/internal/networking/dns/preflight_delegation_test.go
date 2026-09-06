package dns

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type delegationZoneChecker struct {
	zones map[string]*Zone
	calls []string
}

func (c *delegationZoneChecker) GetZoneByName(_ context.Context, name string) (*Zone, error) {
	c.calls = append(c.calls, name)
	if z := c.zones[name]; z != nil {
		copy := *z
		return &copy, nil
	}
	return nil, errors.New("not found")
}

func TestResolveManagedZoneWalksToParent(t *testing.T) {
	checker := &delegationZoneChecker{zones: map[string]*Zone{
		"example.com": {ID: "z", Name: "example.com", Status: "active", NameServers: []string{"A.NS.EXAMPLE.", "b.ns.example"}},
	}}
	zone, err := resolveManagedZone(context.Background(), checker, "api.eu.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if zone.Name != "example.com" {
		t.Fatalf("zone=%q", zone.Name)
	}
	want := []string{"api.eu.example.com", "eu.example.com", "example.com"}
	if !reflect.DeepEqual(checker.calls, want) {
		t.Fatalf("calls=%v want=%v", checker.calls, want)
	}
}

func TestNameserverSetsRequireExactNormalizedEquality(t *testing.T) {
	if !nameServerSetsEqual([]string{"B.NS.EXAMPLE.", "a.ns.example"}, []string{"a.ns.example.", "b.ns.example."}) {
		t.Fatal("case/trailing-dot normalized sets should match")
	}
	if nameServerSetsEqual([]string{"a.ns.example", "b.ns.example"}, []string{"a.ns.example"}) {
		t.Fatal("subset must not count as exact delegation match")
	}
	if nameServerSetsEqual([]string{"a.ns.example", "a.ns.example"}, []string{"a.ns.example"}) {
		t.Fatal("duplicate provider nameservers must not silently collapse into equality")
	}
}

func TestDelegationResolverListIsBoundedAndNormalized(t *testing.T) {
	got, err := normalizePreflightResolvers([]string{" 8.8.8.8:53 ", "1.1.1.1:53", "1.1.1.1:53"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"8.8.8.8:53", "1.1.1.1:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("resolvers=%v want=%v", got, want)
	}
	many := make([]string, maxPreflightResolvers+1)
	for i := range many {
		many[i] = "127.0.0.1:53"
	}
	if _, err := normalizePreflightResolvers(many); err == nil {
		t.Fatal("over-bound resolver list accepted")
	}
}

func TestDelegatedChildRequiresManagedNameserversWhenNSPresent(t *testing.T) {
	provider := []string{"a.ns.example", "b.ns.example"}
	if err := validateChildDelegation("api.example.com", "example.com", provider, nil); err != nil {
		t.Fatalf("non-delegated child rejected: %v", err)
	}
	if err := validateChildDelegation("api.example.com", "example.com", provider, []string{"a.ns.example", "b.ns.example"}); err != nil {
		t.Fatalf("managed child delegation rejected: %v", err)
	}
	if err := validateChildDelegation("api.example.com", "example.com", provider, []string{"ns1.other.net", "ns2.other.net"}); err == nil {
		t.Fatal("independently delegated child accepted")
	}
}
