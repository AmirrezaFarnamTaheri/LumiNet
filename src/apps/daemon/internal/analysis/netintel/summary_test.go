package netintel

import (
	"net/netip"
	"testing"
	"time"

	canonicalprovider "github.com/maybeknott/luminet/internal/analysis/provider"
	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
	"github.com/maybeknott/luminet/internal/platform/system"
)

func TestBuildTruthfulCrossPlaneSummary(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	flows := []flowregistry.Snapshot{
		{ID: "f1", Owner: "relay", Protocol: "vless", Destination: "1.1.1.1:443", UploadBytes: 10, DownloadBytes: 20, NetworkEpoch: 2, State: flowregistry.StateActive},
		{ID: "f2", Owner: "socks", Protocol: "socks5", Destination: "example.com:443", UploadBytes: 3, DownloadBytes: 4, NetworkEpoch: 1, State: flowregistry.StateClosing},
		{ID: "f3", Owner: "relay", Protocol: "vless", Destination: "203.0.113.1:443", NetworkEpoch: 0, State: flowregistry.StateActive},
	}
	coverage := []flowregistry.OwnerCoverage{
		{Owner: "relay", Visible: true, Closeable: true, ByteCounters: true, DestinationMetadata: true},
		{Owner: "runtimecore-tor", Visible: false, Notes: []string{"per-flow visibility unavailable"}},
		{Owner: "socks", Visible: true, Closeable: true, ByteCounters: true, DestinationMetadata: true},
	}
	network := system.NetworkMonitorStatus{
		Current: system.NetworkSnapshot{Revision: 2, CapturedAt: now.Add(-time.Second), Interfaces: []system.InterfaceState{{Index: 1, Name: "eth0"}}, DefaultIPv4Interface: "eth0", DefaultIPv4LocalIP: "10.0.0.2"},
		History: []system.NetworkChange{{Revision: 2, Kinds: []string{"default_ipv4"}}},
	}
	lookup := func(addr netip.Addr) (canonicalprovider.Match, bool) {
		if addr.String() == "1.1.1.1" {
			return canonicalprovider.Match{ProviderID: "cloudflare", DisplayName: "Cloudflare"}, true
		}
		return canonicalprovider.Match{}, false
	}
	out := Build(now, flows, coverage, flowregistry.Stats{Active: 2, Closing: 1, UploadBytes: 13, DownloadBytes: 24}, network, lookup, canonicalprovider.Status{CorpusID: "builtin", Stale: true}, true)
	if out.CoverageComplete || out.CoverageModel != CoverageModel {
		t.Fatalf("coverage truth lost: %+v", out)
	}
	if out.PreHandoffFlows != 1 || out.UnknownEpochFlows != 1 {
		t.Fatalf("epoch counts: %+v", out)
	}
	if out.UnattributedFlows != 2 || out.DistinctProviders != 1 || out.DistinctProtocols != 2 {
		t.Fatalf("attribution/protocol counts: %+v", out)
	}
	if !out.ProviderCorpusStale || out.ProviderCorpusID != "builtin" {
		t.Fatalf("corpus freshness: %+v", out)
	}
	if len(out.Owners) != 3 || out.Owners[0].Owner != "relay" || out.Owners[1].Owner != "runtimecore-tor" || out.Owners[2].Owner != "socks" {
		t.Fatalf("owner sort: %+v", out.Owners)
	}
	if len(out.Providers) != 1 || out.Providers[0].Flows != 1 || out.Providers[0].UploadBytes != 10 {
		t.Fatalf("providers: %+v", out.Providers)
	}
}

func TestBuildIsDeterministicAndDoesNotInventProviderTruth(t *testing.T) {
	flow := flowregistry.Snapshot{ID: "f", Owner: "o", Protocol: "tcp", Destination: "example.com:443", State: flowregistry.StateActive}
	coverage := []flowregistry.OwnerCoverage{{Owner: "o", Visible: true}}
	out := Build(time.Unix(1, 0), []flowregistry.Snapshot{flow}, coverage, flowregistry.Stats{Active: 1}, system.NetworkMonitorStatus{}, nil, canonicalprovider.Status{}, false)
	if out.ProviderCorpusReady || out.ProviderCorpusStale || out.DistinctProviders != 0 || out.UnattributedFlows != 1 {
		t.Fatalf("invented provider truth: %+v", out)
	}
	if out.NetworkRevision != 0 || out.PreHandoffFlows != 0 || out.UnknownEpochFlows != 1 {
		t.Fatalf("invented epoch truth: %+v", out)
	}
}
