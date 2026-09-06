// Package netintel derives a bounded, read-only operational network summary
// from LumiNet's existing authoritative observation planes. It owns no socket,
// route, DNS, firewall, or runtime mutation authority.
package netintel

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	canonicalprovider "github.com/maybeknott/luminet/internal/analysis/provider"
	"github.com/maybeknott/luminet/internal/foundation/flowregistry"
	"github.com/maybeknott/luminet/internal/platform/system"
)

const CoverageModel = "participating-runtime-owners-only"

type ProviderSummary struct {
	ProviderID    string `json:"provider_id"`
	DisplayName   string `json:"display_name"`
	Flows         int    `json:"flows"`
	UploadBytes   uint64 `json:"upload_bytes"`
	DownloadBytes uint64 `json:"download_bytes"`
}

type OwnerSummary struct {
	Owner               string   `json:"owner"`
	Visible             bool     `json:"visible"`
	Closeable           bool     `json:"closeable"`
	ByteCounters        bool     `json:"byte_counters"`
	ProcessAttribution  bool     `json:"process_attribution"`
	DestinationMetadata bool     `json:"destination_metadata"`
	Active              int      `json:"active"`
	Closing             int      `json:"closing"`
	PreHandoff          int      `json:"pre_handoff"`
	UnknownEpoch        int      `json:"unknown_epoch"`
	UploadBytes         uint64   `json:"upload_bytes"`
	DownloadBytes       uint64   `json:"download_bytes"`
	Notes               []string `json:"notes,omitempty"`
}

type Summary struct {
	GeneratedAt          time.Time         `json:"generated_at"`
	CoverageComplete     bool              `json:"coverage_complete"`
	CoverageModel        string            `json:"coverage_model"`
	NetworkRevision      uint64            `json:"network_revision"`
	NetworkCapturedAt    time.Time         `json:"network_captured_at"`
	DefaultIPv4Interface string            `json:"default_ipv4_interface,omitempty"`
	DefaultIPv4LocalIP   string            `json:"default_ipv4_local_ip,omitempty"`
	DefaultIPv6Interface string            `json:"default_ipv6_interface,omitempty"`
	DefaultIPv6LocalIP   string            `json:"default_ipv6_local_ip,omitempty"`
	ActiveInterfaces     int               `json:"active_interfaces"`
	RetainedHandoffs     int               `json:"retained_handoffs"`
	LatestHandoffKinds   []string          `json:"latest_handoff_kinds,omitempty"`
	ActiveFlows          int               `json:"active_flows"`
	ClosingFlows         int               `json:"closing_flows"`
	PreHandoffFlows      int               `json:"pre_handoff_flows"`
	UnknownEpochFlows    int               `json:"unknown_epoch_flows"`
	UnattributedFlows    int               `json:"unattributed_flows"`
	UploadBytes          uint64            `json:"upload_bytes"`
	DownloadBytes        uint64            `json:"download_bytes"`
	DistinctProtocols    int               `json:"distinct_protocols"`
	DistinctProviders    int               `json:"distinct_providers"`
	ProviderCorpusReady  bool              `json:"provider_corpus_ready"`
	ProviderCorpusID     string            `json:"provider_corpus_id,omitempty"`
	ProviderCorpusStale  bool              `json:"provider_corpus_stale"`
	Owners               []OwnerSummary    `json:"owners"`
	Providers            []ProviderSummary `json:"providers"`
}

type providerAggregate struct {
	ProviderSummary
}

// Build constructs a deterministic summary from immutable observation inputs.
// lookup MUST be local and side-effect free; callers should pass the activated
// provider-prefix corpus lookup, never a network-backed geolocation function.
func Build(
	now time.Time,
	flows []flowregistry.Snapshot,
	coverage []flowregistry.OwnerCoverage,
	stats flowregistry.Stats,
	networkStatus system.NetworkMonitorStatus,
	lookup func(netip.Addr) (canonicalprovider.Match, bool),
	providerStatus canonicalprovider.Status,
	providerReady bool,
) Summary {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	currentRevision := networkStatus.Current.Revision
	out := Summary{
		GeneratedAt:          now.UTC(),
		CoverageComplete:     false,
		CoverageModel:        CoverageModel,
		NetworkRevision:      currentRevision,
		NetworkCapturedAt:    networkStatus.Current.CapturedAt,
		DefaultIPv4Interface: networkStatus.Current.DefaultIPv4Interface,
		DefaultIPv4LocalIP:   networkStatus.Current.DefaultIPv4LocalIP,
		DefaultIPv6Interface: networkStatus.Current.DefaultIPv6Interface,
		DefaultIPv6LocalIP:   networkStatus.Current.DefaultIPv6LocalIP,
		ActiveInterfaces:     len(networkStatus.Current.Interfaces),
		RetainedHandoffs:     len(networkStatus.History),
		ActiveFlows:          stats.Active,
		ClosingFlows:         stats.Closing,
		UploadBytes:          stats.UploadBytes,
		DownloadBytes:        stats.DownloadBytes,
		ProviderCorpusReady:  providerReady,
		ProviderCorpusID:     providerStatus.CorpusID,
		ProviderCorpusStale:  providerReady && providerStatus.Stale,
	}
	if len(networkStatus.History) > 0 {
		last := networkStatus.History[len(networkStatus.History)-1]
		out.LatestHandoffKinds = append([]string(nil), last.Kinds...)
	}

	ownerIndex := make(map[string]*OwnerSummary, len(coverage))
	for _, c := range coverage {
		entry := &OwnerSummary{
			Owner: c.Owner, Visible: c.Visible, Closeable: c.Closeable,
			ByteCounters: c.ByteCounters, ProcessAttribution: c.ProcessAttribution,
			DestinationMetadata: c.DestinationMetadata, Notes: append([]string(nil), c.Notes...),
		}
		ownerIndex[c.Owner] = entry
	}
	protocols := make(map[string]struct{})
	providerIndex := make(map[string]*providerAggregate)

	for _, flow := range flows {
		owner := ownerIndex[flow.Owner]
		if owner == nil {
			// This should not occur because the registry enforces coverage before
			// registration, but keeping the summary total preserves truth if an
			// imported snapshot is inconsistent.
			owner = &OwnerSummary{Owner: flow.Owner, Notes: []string{"flow snapshot lacked matching owner coverage declaration"}}
			ownerIndex[flow.Owner] = owner
		}
		switch flow.State {
		case flowregistry.StateClosing:
			owner.Closing++
		default:
			owner.Active++
		}
		owner.UploadBytes += flow.UploadBytes
		owner.DownloadBytes += flow.DownloadBytes
		if flow.NetworkEpoch == 0 {
			owner.UnknownEpoch++
			out.UnknownEpochFlows++
		} else if currentRevision > 0 && flow.NetworkEpoch < currentRevision {
			owner.PreHandoff++
			out.PreHandoffFlows++
		}
		if protocol := strings.ToLower(strings.TrimSpace(flow.Protocol)); protocol != "" {
			protocols[protocol] = struct{}{}
		}

		addr, ok := destinationIP(flow.Destination)
		if !ok || lookup == nil {
			out.UnattributedFlows++
			continue
		}
		match, found := lookup(addr)
		if !found {
			out.UnattributedFlows++
			continue
		}
		key := match.ProviderID
		if key == "" {
			key = match.DisplayName
		}
		agg := providerIndex[key]
		if agg == nil {
			agg = &providerAggregate{ProviderSummary: ProviderSummary{ProviderID: match.ProviderID, DisplayName: match.DisplayName}}
			providerIndex[key] = agg
		}
		agg.Flows++
		agg.UploadBytes += flow.UploadBytes
		agg.DownloadBytes += flow.DownloadBytes
	}
	out.DistinctProtocols = len(protocols)

	out.Owners = make([]OwnerSummary, 0, len(ownerIndex))
	for _, owner := range ownerIndex {
		copyOwner := *owner
		copyOwner.Notes = append([]string(nil), owner.Notes...)
		out.Owners = append(out.Owners, copyOwner)
	}
	sort.Slice(out.Owners, func(i, j int) bool { return out.Owners[i].Owner < out.Owners[j].Owner })

	out.Providers = make([]ProviderSummary, 0, len(providerIndex))
	for _, provider := range providerIndex {
		out.Providers = append(out.Providers, provider.ProviderSummary)
	}
	sort.Slice(out.Providers, func(i, j int) bool {
		if out.Providers[i].Flows != out.Providers[j].Flows {
			return out.Providers[i].Flows > out.Providers[j].Flows
		}
		if out.Providers[i].DisplayName != out.Providers[j].DisplayName {
			return out.Providers[i].DisplayName < out.Providers[j].DisplayName
		}
		return out.Providers[i].ProviderID < out.Providers[j].ProviderID
	})
	out.DistinctProviders = len(out.Providers)
	return out
}

func destinationIP(destination string) (netip.Addr, bool) {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return netip.Addr{}, false
	}
	host := destination
	if splitHost, _, err := net.SplitHostPort(destination); err == nil {
		host = splitHost
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	addr, err := netip.ParseAddr(host)
	return addr, err == nil
}
