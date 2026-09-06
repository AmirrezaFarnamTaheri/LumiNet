package proxy

import (
	"net/netip"
	"time"

	canonicalprovider "github.com/maybeknott/luminet/internal/provider"
)

// Provider corpus types remain available from proxy for compatibility. Their
// implementation and validation are owned by internal/provider.
type ProviderCorpus = canonicalprovider.Corpus
type ProviderManifest = canonicalprovider.Manifest
type ProviderMatch = canonicalprovider.Match
type ProviderSnapshot = canonicalprovider.Snapshot
type ProviderCorpusStatus = canonicalprovider.Status
type ProviderCorpusStore = canonicalprovider.Store

// Historical mutable prefix-index names remain aliases to the single canonical
// compatibility implementation in internal/provider. Provider corpus authority
// continues to use immutable provider.Snapshot values.
type RadixNode = canonicalprovider.PrefixNode
type CorporateNetworkIndex = canonicalprovider.PrefixIndex
type ProviderObservation = canonicalprovider.Observation

// ParseProviderCorpus delegates corpus decoding and validation to the canonical package.
func ParseProviderCorpus(data []byte) (ProviderCorpus, error) { return canonicalprovider.Parse(data) }

// BuildProviderSnapshot delegates snapshot construction to the canonical package.
func BuildProviderSnapshot(corpus ProviderCorpus) (*ProviderSnapshot, error) {
	return canonicalprovider.BuildSnapshot(corpus)
}

// UpdateProviderCorpusRegistry retains the old proxy activation API while
// delegating corpus ownership to the canonical provider service.
func UpdateProviderCorpusRegistry(corpus ProviderCorpus) error {
	return canonicalprovider.DefaultService.Activate(corpus)
}

// InitBuiltinProviderCorpus retains the old startup API for proxy consumers.
func InitBuiltinProviderCorpus() error {
	return canonicalprovider.DefaultService.InitializeBuiltin()
}

// GetProviderCorpusStoreStatus returns status from the canonical service.
func GetProviderCorpusStoreStatus() (ProviderCorpusStatus, bool) {
	return canonicalprovider.DefaultService.Status(time.Now())
}

// ObserveProvider reads the canonical snapshot through the historical proxy API.
func ObserveProvider(ip string) ProviderObservation {
	return canonicalprovider.DefaultService.Observe(ip)
}

// MatchRadixClassification retains the historical name while reading the
// canonical longest-prefix and priority-ordered snapshot.
func MatchRadixClassification(ip netip.Addr) (string, bool) {
	match, ok := canonicalprovider.DefaultService.Lookup(ip)
	if !ok {
		return "", false
	}
	return match.ProviderID, true
}

// BuiltinProviderCorpus exposes the canonical built-in corpus through the
// historical proxy API.
func BuiltinProviderCorpus() ProviderCorpus { return canonicalprovider.BuiltinCorpus() }
