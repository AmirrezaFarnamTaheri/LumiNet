package provider

import (
	"net/netip"
	"testing"
	"time"
)

func TestSnapshotLongestPrefixAndPriority(t *testing.T) {
	corpus := Corpus{SchemaVersion: 1, CorpusID: "test", GeneratorVersion: "test", Checksum: "test", Providers: []Manifest{
		{ProviderID: "broad", Priority: 100, IPv4Prefixes: []string{"192.0.2.0/24"}},
		{ProviderID: "specific", Priority: 1, IPv4Prefixes: []string{"192.0.2.0/25"}},
	}}
	snapshot, err := BuildSnapshot(corpus)
	if err != nil {
		t.Fatal(err)
	}
	match, ok := snapshot.Lookup(netip.MustParseAddr("192.0.2.10"))
	if !ok || match.ProviderID != "specific" {
		t.Fatalf("match=%+v ok=%v", match, ok)
	}
}

func TestStoreStatusPreservesMetadataAndStaleness(t *testing.T) {
	corpus := Corpus{SchemaVersion: 1, CorpusID: "test", GeneratorVersion: "gen", Checksum: "sum", StaleAfter: "2020-01-01T00:00:00Z", Providers: []Manifest{{ProviderID: "p", IPv4Prefixes: []string{"192.0.2.0/24"}}}}
	snapshot, err := BuildSnapshot(corpus)
	if err != nil {
		t.Fatal(err)
	}
	var store Store
	store.Store(snapshot)
	status, ok := store.Status(time.Now())
	if !ok || !status.Stale || status.Checksum != "sum" || status.GeneratorVersion != "gen" {
		t.Fatalf("status=%+v ok=%v", status, ok)
	}
}

func TestParseRejectsDuplicateProvider(t *testing.T) {
	_, err := Parse([]byte(`{"schema_version":1,"corpus_id":"x","generator_version":"x","checksum":"x","providers":[{"provider_id":"p","ipv4_prefixes":["192.0.2.0/24"]},{"provider_id":"p","ipv4_prefixes":["198.51.100.0/24"]}]}`))
	if err == nil {
		t.Fatal("duplicate provider must be rejected")
	}
}

func TestBuiltinCorpusIsValidAndLookupReady(t *testing.T) {
	snapshot, err := BuildSnapshot(BuiltinCorpus())
	if err != nil {
		t.Fatal(err)
	}
	match, ok := snapshot.Lookup(netip.MustParseAddr("104.16.2.3"))
	if !ok || match.ProviderID != "cloudflare" {
		t.Fatalf("match=%+v ok=%v", match, ok)
	}
}

func TestServiceActivatesBuiltinAndReportsStaleMetadata(t *testing.T) {
	var service Service
	if err := service.InitializeBuiltin(); err != nil {
		t.Fatal(err)
	}
	status, ok := service.Status(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC))
	if !ok || !status.Stale || status.SchemaVersion != 1 || status.FetchedAt == "" || status.GeneratedAt == "" {
		t.Fatalf("status=%+v ok=%v", status, ok)
	}
	match, ok := service.Lookup(netip.MustParseAddr("104.16.2.3"))
	if !ok || match.ProviderID != "cloudflare" {
		t.Fatalf("match=%+v ok=%v", match, ok)
	}
}

func TestActivateWithStatusReportsPublishedSnapshot(t *testing.T) {
	corpus := Corpus{
		SchemaVersion:    1,
		CorpusID:         "activation-status",
		GeneratorVersion: "test",
		Checksum:         "sum",
		StaleAfter:       "2020-01-01T00:00:00Z",
		Providers:        []Manifest{{ProviderID: "provider", IPv4Prefixes: []string{"198.51.100.0/24"}}},
	}
	var service Service
	status, err := service.ActivateWithStatus(corpus, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if status.CorpusID != corpus.CorpusID || !status.Stale || status.Checksum != corpus.Checksum {
		t.Fatalf("status=%+v", status)
	}
}

func TestSnapshotPrefixIndexPreservesPriorityForIdenticalPrefix(t *testing.T) {
	corpus := Corpus{SchemaVersion: 1, CorpusID: "priority", GeneratorVersion: "test", Checksum: "test", Providers: []Manifest{
		{ProviderID: "first", Priority: 10, IPv4Prefixes: []string{"203.0.113.0/24"}},
		{ProviderID: "winner", Priority: 20, IPv4Prefixes: []string{"203.0.113.0/24"}},
		{ProviderID: "last-same-priority", Priority: 20, IPv4Prefixes: []string{"203.0.113.0/24"}},
	}}
	snapshot, err := BuildSnapshot(corpus)
	if err != nil {
		t.Fatal(err)
	}
	match, ok := snapshot.Lookup(netip.MustParseAddr("203.0.113.7"))
	if !ok || match.ProviderID != "winner" {
		t.Fatalf("match=%+v ok=%v, want first highest-priority provider", match, ok)
	}
}

func TestSnapshotPrefixIndexHandlesIPv6LongestPrefix(t *testing.T) {
	corpus := Corpus{SchemaVersion: 1, CorpusID: "v6", GeneratorVersion: "test", Checksum: "test", Providers: []Manifest{
		{ProviderID: "broad", Priority: 100, IPv6Prefixes: []string{"2001:db8::/32"}},
		{ProviderID: "specific", Priority: 1, IPv6Prefixes: []string{"2001:db8:abcd::/48"}},
	}}
	snapshot, err := BuildSnapshot(corpus)
	if err != nil {
		t.Fatal(err)
	}
	match, ok := snapshot.Lookup(netip.MustParseAddr("2001:db8:abcd::1234"))
	if !ok || match.ProviderID != "specific" || match.Prefix.Bits() != 48 {
		t.Fatalf("match=%+v ok=%v, want /48 specific provider", match, ok)
	}
}

func TestSnapshotPrefixIndexMatchesReferenceLinearLookup(t *testing.T) {
	corpus := Corpus{SchemaVersion: 1, CorpusID: "differential", GeneratorVersion: "test", Checksum: "test", Providers: []Manifest{
		{ProviderID: "default-v4", Priority: 1, IPv4Prefixes: []string{"0.0.0.0/0"}},
		{ProviderID: "net8", Priority: 2, IPv4Prefixes: []string{"10.0.0.0/8"}},
		{ProviderID: "net16", Priority: 1, IPv4Prefixes: []string{"10.42.0.0/16"}},
		{ProviderID: "default-v6", Priority: 1, IPv6Prefixes: []string{"::/0"}},
		{ProviderID: "v6-48", Priority: 1, IPv6Prefixes: []string{"2001:db8:beef::/48"}},
	}}
	snapshot, err := BuildSnapshot(corpus)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"8.8.8.8", "10.1.2.3", "10.42.9.9", "2001:4860::8888", "2001:db8:beef::1"} {
		addr := netip.MustParseAddr(raw)
		indexed, indexedOK := snapshot.Lookup(addr)
		var linear Match
		linearOK := false
		for _, candidate := range snapshot.records {
			if candidate.prefix.Contains(addr) {
				m := candidate.manifest
				linear = Match{ProviderID: m.ProviderID, DisplayName: m.DisplayName, Prefix: candidate.prefix, Confidence: m.Confidence, Priority: m.Priority, CorpusID: snapshot.CorpusID, SourceURL: m.SourceURL, SourceLicense: m.SourceLicense}
				linearOK = true
				break
			}
		}
		if indexedOK != linearOK || indexed != linear {
			t.Fatalf("addr=%s indexed=(%+v,%v) linear=(%+v,%v)", addr, indexed, indexedOK, linear, linearOK)
		}
	}
}
