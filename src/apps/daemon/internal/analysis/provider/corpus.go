package provider

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"
)

type record struct {
	prefix   netip.Prefix
	manifest Manifest
}

// Snapshot is an immutable, priority-ordered lookup view of a validated corpus.
type Snapshot struct {
	CorpusID         string
	GeneratorVersion string
	GeneratedAt      string
	FetchedAt        string
	StaleAfter       string
	Checksum         string
	records          []record
	ipv4Index        [33]map[netip.Addr]record
	ipv6Index        [129]map[netip.Addr]record
}

// Status describes the currently active corpus and whether its declared
// freshness deadline has elapsed.
type Status struct {
	SchemaVersion    int    `json:"schema_version"`
	CorpusID         string `json:"corpus_id"`
	GeneratorVersion string `json:"generator_version"`
	GeneratedAt      string `json:"generated_at"`
	FetchedAt        string `json:"fetched_at"`
	StaleAfter       string `json:"stale_after"`
	Checksum         string `json:"checksum"`
	Stale            bool   `json:"stale"`
}

// Store atomically publishes immutable corpus snapshots.
type Store struct{ value atomic.Value }

func (s *Store) Store(snapshot *Snapshot) { s.value.Store(snapshot) }

func (s *Store) Lookup(addr netip.Addr) (Match, bool) {
	value := s.value.Load()
	if value == nil {
		return Match{}, false
	}
	snapshot, ok := value.(*Snapshot)
	if !ok {
		return Match{}, false
	}
	return snapshot.Lookup(addr)
}

// Status reports the current snapshot without treating stale metadata as fresh.
func (s *Store) Status(now time.Time) (Status, bool) {
	value := s.value.Load()
	if value == nil {
		return Status{}, false
	}
	snapshot, ok := value.(*Snapshot)
	if !ok || snapshot == nil {
		return Status{}, false
	}
	return snapshot.statusAt(now), true
}

// Service owns activation of validated provider corpora for a process.
// Its zero value is ready to use.
type Service struct{ store Store }

// DefaultService is the process-wide provider corpus service used by the
// daemon and compatibility adapters.
var DefaultService Service

// Activate validates and atomically publishes corpus as the active snapshot.
func (s *Service) Activate(corpus Corpus) error {
	_, err := s.ActivateWithStatus(corpus, time.Now())
	return err
}

// ActivateWithStatus validates and publishes corpus, returning status for the
// exact snapshot that was activated. Callers that report activation results
// should use this instead of loading status again after publication.
func (s *Service) ActivateWithStatus(corpus Corpus, now time.Time) (Status, error) {
	snapshot, err := BuildSnapshot(corpus)
	if err != nil {
		return Status{}, err
	}
	s.store.Store(snapshot)
	return snapshot.statusAt(now), nil
}

// InitializeBuiltin activates the built-in fallback corpus.
func (s *Service) InitializeBuiltin() error {
	return s.Activate(BuiltinCorpus())
}

// Lookup queries the currently active corpus.
func (s *Service) Lookup(addr netip.Addr) (Match, bool) {
	return s.store.Lookup(addr)
}

// Status reports metadata and freshness for the currently active corpus.
func (s *Service) Status(now time.Time) (Status, bool) {
	return s.store.Status(now)
}

func BuildSnapshot(corpus Corpus) (*Snapshot, error) {
	if err := Validate(corpus); err != nil {
		return nil, err
	}
	snapshot := &Snapshot{CorpusID: corpus.CorpusID, GeneratorVersion: corpus.GeneratorVersion, GeneratedAt: corpus.GeneratedAt, FetchedAt: corpus.FetchedAt, StaleAfter: corpus.StaleAfter, Checksum: corpus.Checksum}
	for _, manifest := range corpus.Providers {
		for _, raw := range append(append([]string{}, manifest.IPv4Prefixes...), manifest.IPv6Prefixes...) {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, err
			}
			snapshot.records = append(snapshot.records, record{prefix: prefix.Masked(), manifest: manifest})
		}
	}
	sort.SliceStable(snapshot.records, func(i, j int) bool {
		if snapshot.records[i].prefix.Bits() != snapshot.records[j].prefix.Bits() {
			return snapshot.records[i].prefix.Bits() > snapshot.records[j].prefix.Bits()
		}
		return snapshot.records[i].manifest.Priority > snapshot.records[j].manifest.Priority
	})
	for _, record := range snapshot.records {
		snapshot.indexRecord(record)
	}
	return snapshot, nil
}

func (s *Snapshot) indexRecord(candidate record) {
	bits := candidate.prefix.Bits()
	key := candidate.prefix.Masked().Addr()
	var bucket *map[netip.Addr]record
	if candidate.prefix.Addr().Is4() {
		bucket = &s.ipv4Index[bits]
	} else {
		bucket = &s.ipv6Index[bits]
	}
	if *bucket == nil {
		*bucket = make(map[netip.Addr]record)
	}
	current, exists := (*bucket)[key]
	// Stable corpus order remains the tie-breaker when priorities are equal,
	// matching the previous sorted linear scan exactly.
	if !exists || candidate.manifest.Priority > current.manifest.Priority {
		(*bucket)[key] = candidate
	}
}

func (s *Snapshot) Lookup(addr netip.Addr) (Match, bool) {
	if s == nil || !addr.IsValid() {
		return Match{}, false
	}
	var candidate record
	var ok bool
	if addr.Is4() {
		candidate, ok = lookupPrefixIndex(addr, s.ipv4Index[:], 32)
	} else {
		candidate, ok = lookupPrefixIndex(addr, s.ipv6Index[:], 128)
	}
	if !ok {
		return Match{}, false
	}
	m := candidate.manifest
	return Match{ProviderID: m.ProviderID, DisplayName: m.DisplayName, Prefix: candidate.prefix, Confidence: m.Confidence, Priority: m.Priority, CorpusID: s.CorpusID, SourceURL: m.SourceURL, SourceLicense: m.SourceLicense}, true
}

func lookupPrefixIndex(addr netip.Addr, buckets []map[netip.Addr]record, maxBits int) (record, bool) {
	for bits := maxBits; bits >= 0; bits-- {
		bucket := buckets[bits]
		if len(bucket) == 0 {
			continue
		}
		prefix, err := addr.Prefix(bits)
		if err != nil {
			continue
		}
		if candidate, ok := bucket[prefix.Masked().Addr()]; ok {
			return candidate, true
		}
	}
	return record{}, false
}

func (s *Snapshot) statusAt(now time.Time) Status {
	status := Status{SchemaVersion: 1, CorpusID: s.CorpusID, GeneratorVersion: s.GeneratorVersion, GeneratedAt: s.GeneratedAt, FetchedAt: s.FetchedAt, StaleAfter: s.StaleAfter, Checksum: s.Checksum}
	if s.StaleAfter != "" {
		if staleAfter, err := time.Parse(time.RFC3339, s.StaleAfter); err == nil && now.After(staleAfter) {
			status.Stale = true
		}
	}
	return status
}

// Parse decodes a corpus and enforces the stable v1 contract.
func Parse(data []byte) (Corpus, error) {
	var corpus Corpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		return Corpus{}, err
	}
	if err := Validate(corpus); err != nil {
		return Corpus{}, err
	}
	return corpus, nil
}

// Validate rejects malformed or ambiguous corpus records before activation.
func Validate(corpus Corpus) error {
	if corpus.SchemaVersion != 1 {
		return fmt.Errorf("unsupported provider corpus schema_version %d", corpus.SchemaVersion)
	}
	if corpus.CorpusID == "" || corpus.Checksum == "" || corpus.GeneratorVersion == "" {
		return fmt.Errorf("provider corpus missing identity fields")
	}
	seen := make(map[string]struct{}, len(corpus.Providers))
	for _, provider := range corpus.Providers {
		if provider.ProviderID == "" {
			return fmt.Errorf("provider missing provider_id")
		}
		if _, exists := seen[provider.ProviderID]; exists {
			return fmt.Errorf("duplicate provider_id %q", provider.ProviderID)
		}
		seen[provider.ProviderID] = struct{}{}
		prefixes := append(append([]string{}, provider.IPv4Prefixes...), provider.IPv6Prefixes...)
		if len(prefixes) == 0 {
			return fmt.Errorf("provider %q has no prefixes", provider.ProviderID)
		}
		for _, raw := range prefixes {
			if _, err := netip.ParsePrefix(raw); err != nil {
				return fmt.Errorf("provider %q invalid prefix %q: %w", provider.ProviderID, raw, err)
			}
		}
	}
	return nil
}
