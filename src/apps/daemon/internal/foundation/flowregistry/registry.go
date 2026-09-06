package flowregistry

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultMaxFlows   = 4096
	MaxOwnerLen       = 64
	MaxEndpointLen    = 512
	MaxLabelLen       = 128
	MaxChainEntries   = 32
	MaxCoverageNotes  = 16
	MaxBulkCloseFlows = 256
)

var (
	ErrNotFound         = errors.New("flow not found")
	ErrNotCloseable     = errors.New("flow is not closeable")
	ErrClosing          = errors.New("flow is already closing")
	ErrCapacity         = errors.New("flow registry capacity reached")
	ErrOwnerUndeclared  = errors.New("flow owner coverage is undeclared")
	ErrCoverageMismatch = errors.New("flow metadata exceeds declared owner coverage")
)

type State string

const (
	StateActive  State = "active"
	StateClosing State = "closing"
)

// Descriptor is immutable identifying metadata supplied by the runtime owner.
// Empty optional fields mean unknown; they are never synthesized by the registry.
type Descriptor struct {
	Owner        string            `json:"owner"`
	Network      string            `json:"network,omitempty"`
	Protocol     string            `json:"protocol,omitempty"`
	Source       string            `json:"source,omitempty"`
	Destination  string            `json:"destination,omitempty"`
	Host         string            `json:"host,omitempty"`
	Process      string            `json:"process,omitempty"`
	ProcessPath  string            `json:"process_path,omitempty"`
	Rule         string            `json:"rule,omitempty"`
	RulePayload  string            `json:"rule_payload,omitempty"`
	Chain        []string          `json:"chain,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	StartedAt    time.Time         `json:"started_at"`
	NetworkEpoch uint64            `json:"network_epoch,omitempty"`
}

// Snapshot is a read-only point-in-time view. Traffic counters are monotonic
// for the lifetime of one flow and LastActivityAt advances only on observed I/O.
type Snapshot struct {
	ID             string            `json:"id"`
	Owner          string            `json:"owner"`
	Network        string            `json:"network,omitempty"`
	Protocol       string            `json:"protocol,omitempty"`
	Source         string            `json:"source,omitempty"`
	Destination    string            `json:"destination,omitempty"`
	Host           string            `json:"host,omitempty"`
	Process        string            `json:"process,omitempty"`
	ProcessPath    string            `json:"process_path,omitempty"`
	Rule           string            `json:"rule,omitempty"`
	RulePayload    string            `json:"rule_payload,omitempty"`
	Chain          []string          `json:"chain,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	StartedAt      time.Time         `json:"started_at"`
	LastActivityAt time.Time         `json:"last_activity_at"`
	UploadBytes    uint64            `json:"upload_bytes"`
	DownloadBytes  uint64            `json:"download_bytes"`
	NetworkEpoch   uint64            `json:"network_epoch,omitempty"`
	State          State             `json:"state"`
	Closeable      bool              `json:"closeable"`
}

// OwnerCoverage declares what an owner actually publishes. It is capability
// truth for the registry, not a promise about unregistered external runtimes.
type OwnerCoverage struct {
	Owner               string   `json:"owner"`
	Visible             bool     `json:"visible"`
	Closeable           bool     `json:"closeable"`
	ByteCounters        bool     `json:"byte_counters"`
	ProcessAttribution  bool     `json:"process_attribution"`
	DestinationMetadata bool     `json:"destination_metadata"`
	Notes               []string `json:"notes,omitempty"`
}

// Stats summarizes only flows actually registered by participating owners.
// It must not be interpreted as host-wide connection truth.
type Stats struct {
	Active        int    `json:"active"`
	Closing       int    `json:"closing"`
	Capacity      int    `json:"capacity"`
	UploadBytes   uint64 `json:"upload_bytes"`
	DownloadBytes uint64 `json:"download_bytes"`
}

type CloseFunc func(context.Context) error

type entry struct {
	desc           Descriptor
	closeFn        CloseFunc
	upload         atomic.Uint64
	download       atomic.Uint64
	lastActivityNS atomic.Int64
	state          State
	generation     uint64
}

type Registry struct {
	mu         sync.RWMutex
	maxFlows   int
	nextID     atomic.Uint64
	generation uint64
	flows      map[string]*entry
	coverage   map[string]OwnerCoverage
}

func New(maxFlows int) *Registry {
	if maxFlows <= 0 {
		maxFlows = DefaultMaxFlows
	}
	return &Registry{
		maxFlows: maxFlows,
		flows:    make(map[string]*entry),
		coverage: make(map[string]OwnerCoverage),
	}
}

var defaultRegistry = New(DefaultMaxFlows)

func Default() *Registry { return defaultRegistry }

func validateText(name, value string, max int, required bool) error {
	value = strings.TrimSpace(value)
	if required && value == "" {
		return fmt.Errorf("%s is required", name)
	}
	if len(value) > max {
		return fmt.Errorf("%s exceeds %d bytes", name, max)
	}
	return nil
}

func normalizeDescriptor(d Descriptor) (Descriptor, error) {
	d.Owner = strings.TrimSpace(d.Owner)
	d.Network = strings.ToLower(strings.TrimSpace(d.Network))
	d.Protocol = strings.TrimSpace(d.Protocol)
	d.Source = strings.TrimSpace(d.Source)
	d.Destination = strings.TrimSpace(d.Destination)
	d.Host = strings.TrimSpace(d.Host)
	d.Process = strings.TrimSpace(d.Process)
	d.ProcessPath = strings.TrimSpace(d.ProcessPath)
	d.Rule = strings.TrimSpace(d.Rule)
	d.RulePayload = strings.TrimSpace(d.RulePayload)
	if err := validateText("owner", d.Owner, MaxOwnerLen, true); err != nil {
		return Descriptor{}, err
	}
	for name, value := range map[string]string{
		"network": d.Network, "protocol": d.Protocol, "source": d.Source,
		"destination": d.Destination, "host": d.Host, "process": d.Process,
		"process_path": d.ProcessPath, "rule": d.Rule, "rule_payload": d.RulePayload,
	} {
		max := MaxEndpointLen
		if name == "network" || name == "protocol" || name == "process" || name == "rule" {
			max = MaxLabelLen
		}
		if err := validateText(name, value, max, false); err != nil {
			return Descriptor{}, err
		}
	}
	if len(d.Chain) > MaxChainEntries {
		return Descriptor{}, fmt.Errorf("chain exceeds %d entries", MaxChainEntries)
	}
	d.Chain = append([]string(nil), d.Chain...)
	for i := range d.Chain {
		d.Chain[i] = strings.TrimSpace(d.Chain[i])
		if err := validateText("chain entry", d.Chain[i], MaxLabelLen, false); err != nil {
			return Descriptor{}, err
		}
	}
	if len(d.Labels) > MaxChainEntries {
		return Descriptor{}, fmt.Errorf("labels exceed %d entries", MaxChainEntries)
	}
	if d.Labels != nil {
		labels := make(map[string]string, len(d.Labels))
		for k, v := range d.Labels {
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if err := validateText("label key", k, MaxLabelLen, true); err != nil {
				return Descriptor{}, err
			}
			if err := validateText("label value", v, MaxEndpointLen, false); err != nil {
				return Descriptor{}, err
			}
			labels[k] = v
		}
		d.Labels = labels
	}
	if d.StartedAt.IsZero() {
		d.StartedAt = time.Now().UTC()
	} else {
		d.StartedAt = d.StartedAt.UTC()
	}
	return d, nil
}

func (r *Registry) DeclareOwner(c OwnerCoverage) error {
	c.Owner = strings.TrimSpace(c.Owner)
	if err := validateText("owner", c.Owner, MaxOwnerLen, true); err != nil {
		return err
	}
	if len(c.Notes) > MaxCoverageNotes {
		return fmt.Errorf("coverage notes exceed %d entries", MaxCoverageNotes)
	}
	c.Notes = append([]string(nil), c.Notes...)
	for i := range c.Notes {
		c.Notes[i] = strings.TrimSpace(c.Notes[i])
		if err := validateText("coverage note", c.Notes[i], MaxEndpointLen, false); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.coverage[c.Owner]; ok && coverageEqual(existing, c) {
		return nil
	}
	// Coverage is a truth contract. A live owner may refine its declaration only
	// when every already-published flow still satisfies the new declaration.
	// This prevents a UI/API from being told that metadata or close authority is
	// absent while live records still expose it.
	for _, e := range r.flows {
		if e.desc.Owner != c.Owner {
			continue
		}
		if err := validateCoverageForEntry(c, e); err != nil {
			return err
		}
	}
	r.coverage[c.Owner] = c
	return nil
}

func coverageEqual(a, b OwnerCoverage) bool {
	if a.Owner != b.Owner || a.Visible != b.Visible || a.Closeable != b.Closeable ||
		a.ByteCounters != b.ByteCounters || a.ProcessAttribution != b.ProcessAttribution ||
		a.DestinationMetadata != b.DestinationMetadata || len(a.Notes) != len(b.Notes) {
		return false
	}
	for i := range a.Notes {
		if a.Notes[i] != b.Notes[i] {
			return false
		}
	}
	return true
}

func validateCoverage(c OwnerCoverage, d Descriptor, closeFn CloseFunc, upload, download uint64) error {
	if !c.Visible {
		return fmt.Errorf("%w: owner %q is declared non-visible", ErrCoverageMismatch, d.Owner)
	}
	if closeFn != nil && !c.Closeable {
		return fmt.Errorf("%w: owner %q did not declare close authority", ErrCoverageMismatch, d.Owner)
	}
	if (d.Process != "" || d.ProcessPath != "") && !c.ProcessAttribution {
		return fmt.Errorf("%w: owner %q did not declare process attribution", ErrCoverageMismatch, d.Owner)
	}
	if (d.Destination != "" || d.Host != "") && !c.DestinationMetadata {
		return fmt.Errorf("%w: owner %q did not declare destination metadata", ErrCoverageMismatch, d.Owner)
	}
	if (upload != 0 || download != 0) && !c.ByteCounters {
		return fmt.Errorf("%w: owner %q did not declare byte counters", ErrCoverageMismatch, d.Owner)
	}
	return nil
}

func validateCoverageForEntry(c OwnerCoverage, e *entry) error {
	if e == nil {
		return nil
	}
	return validateCoverage(c, e.desc, e.closeFn, e.upload.Load(), e.download.Load())
}

func (r *Registry) Coverage() []OwnerCoverage {
	r.mu.RLock()
	out := make([]OwnerCoverage, 0, len(r.coverage))
	for _, c := range r.coverage {
		c.Notes = append([]string(nil), c.Notes...)
		out = append(out, c)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Owner < out[j].Owner })
	return out
}

type Handle struct {
	registry   *Registry
	id         string
	generation uint64
	ended      atomic.Bool
}

func (r *Registry) Register(d Descriptor, closeFn CloseFunc) (*Handle, error) {
	norm, err := normalizeDescriptor(d)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	coverage, ok := r.coverage[norm.Owner]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrOwnerUndeclared, norm.Owner)
	}
	if err := validateCoverage(coverage, norm, closeFn, 0, 0); err != nil {
		return nil, err
	}
	if len(r.flows) >= r.maxFlows {
		return nil, ErrCapacity
	}
	r.generation++
	gen := r.generation
	id := fmt.Sprintf("flow-%016x", r.nextID.Add(1))
	e := &entry{desc: norm, closeFn: closeFn, state: StateActive, generation: gen}
	e.lastActivityNS.Store(norm.StartedAt.UnixNano())
	r.flows[id] = e
	return &Handle{registry: r, id: id, generation: gen}, nil
}

func (h *Handle) ID() string {
	if h == nil {
		return ""
	}
	return h.id
}

func (h *Handle) AddUpload(n uint64)   { h.add(n, true) }
func (h *Handle) AddDownload(n uint64) { h.add(n, false) }

func (h *Handle) add(n uint64, upload bool) {
	if h == nil || h.registry == nil || h.ended.Load() || n == 0 {
		return
	}
	h.registry.mu.RLock()
	e := h.registry.flows[h.id]
	if e == nil || e.generation != h.generation {
		h.registry.mu.RUnlock()
		return
	}
	if upload {
		e.upload.Add(n)
	} else {
		e.download.Add(n)
	}
	e.lastActivityNS.Store(time.Now().UTC().UnixNano())
	h.registry.mu.RUnlock()
}

// End removes a flow after its owner has finished teardown. It is idempotent.
func (h *Handle) End() {
	if h == nil || h.registry == nil || !h.ended.CompareAndSwap(false, true) {
		return
	}
	h.registry.mu.Lock()
	if e := h.registry.flows[h.id]; e != nil && e.generation == h.generation {
		delete(h.registry.flows, h.id)
	}
	h.registry.mu.Unlock()
}

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func snapshotOf(id string, e *entry) Snapshot {
	last := time.Unix(0, e.lastActivityNS.Load()).UTC()
	return Snapshot{
		ID: id, Owner: e.desc.Owner, Network: e.desc.Network, Protocol: e.desc.Protocol,
		Source: e.desc.Source, Destination: e.desc.Destination, Host: e.desc.Host,
		Process: e.desc.Process, ProcessPath: e.desc.ProcessPath, Rule: e.desc.Rule,
		RulePayload: e.desc.RulePayload, Chain: append([]string(nil), e.desc.Chain...),
		Labels: cloneMap(e.desc.Labels), StartedAt: e.desc.StartedAt, LastActivityAt: last,
		UploadBytes: e.upload.Load(), DownloadBytes: e.download.Load(), NetworkEpoch: e.desc.NetworkEpoch,
		State: e.state, Closeable: e.closeFn != nil,
	}
}

func (r *Registry) Stats() Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	stats := Stats{Capacity: r.maxFlows}
	for _, e := range r.flows {
		switch e.state {
		case StateClosing:
			stats.Closing++
		default:
			stats.Active++
		}
		stats.UploadBytes += e.upload.Load()
		stats.DownloadBytes += e.download.Load()
	}
	return stats
}

func (r *Registry) Snapshot() []Snapshot {
	r.mu.RLock()
	out := make([]Snapshot, 0, len(r.flows))
	for id, e := range r.flows {
		out = append(out, snapshotOf(id, e))
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].StartedAt.Before(out[j].StartedAt)
	})
	return out
}

func (r *Registry) Get(id string) (Snapshot, bool) {
	r.mu.RLock()
	e := r.flows[id]
	if e == nil {
		r.mu.RUnlock()
		return Snapshot{}, false
	}
	s := snapshotOf(id, e)
	r.mu.RUnlock()
	return s, true
}

// Close requests teardown from the owner callback. The callback executes
// outside the registry lock. A failed close restores active state if the same
// flow is still registered; a successful close removes it immediately.
func (r *Registry) Close(ctx context.Context, id string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	r.mu.Lock()
	e := r.flows[id]
	if e == nil {
		r.mu.Unlock()
		return ErrNotFound
	}
	if e.closeFn == nil {
		r.mu.Unlock()
		return ErrNotCloseable
	}
	if e.state == StateClosing {
		r.mu.Unlock()
		return ErrClosing
	}
	e.state = StateClosing
	closeFn, gen := e.closeFn, e.generation
	r.mu.Unlock()

	err := closeFn(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.flows[id]
	if current == nil || current.generation != gen {
		return err
	}
	if err != nil {
		current.state = StateActive
		return err
	}
	delete(r.flows, id)
	return nil
}

// CloseIDs closes an explicit bounded set. It intentionally has no implicit
// "all" mode; bulk-all semantics belong at the authenticated adapter where
// an operation-specific confirmation can be required.
func (r *Registry) CloseIDs(ctx context.Context, ids []string) (map[string]error, error) {
	if len(ids) > MaxBulkCloseFlows {
		return nil, fmt.Errorf("bulk close exceeds %d flows", MaxBulkCloseFlows)
	}
	result := make(map[string]error, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result[id] = r.Close(ctx, id)
	}
	return result, nil
}
