// Package provider owns provider-prefix corpus contracts and lookup semantics.
package provider

import "net/netip"

// Corpus is the versioned, provenance-carrying provider prefix registry.
type Corpus struct {
	SchemaVersion    int        `json:"schema_version"`
	CorpusID         string     `json:"corpus_id"`
	GeneratorVersion string     `json:"generator_version"`
	GeneratedAt      string     `json:"generated_at"`
	FetchedAt        string     `json:"fetched_at"`
	StaleAfter       string     `json:"stale_after"`
	Checksum         string     `json:"checksum"`
	Providers        []Manifest `json:"providers"`
}

// Manifest preserves a provider's prefix and provenance details.
type Manifest struct {
	ProviderID    string   `json:"provider_id"`
	DisplayName   string   `json:"display_name"`
	SourceURL     string   `json:"source_url"`
	SourceLicense string   `json:"source_license"`
	SourceKind    string   `json:"source_kind"`
	Confidence    string   `json:"confidence"`
	Priority      int      `json:"priority"`
	IPv4Prefixes  []string `json:"ipv4_prefixes"`
	IPv6Prefixes  []string `json:"ipv6_prefixes"`
	ASNTags       []string `json:"asn_tags,omitempty"`
	RegionTags    []string `json:"region_tags,omitempty"`
}

// Match is the public result of a longest-prefix lookup.
type Match struct {
	ProviderID    string
	DisplayName   string
	Prefix        netip.Prefix
	Confidence    string
	Priority      int
	CorpusID      string
	SourceURL     string
	SourceLicense string
}
