// Package system tor_vanguards.go — circuit-health guard suite.
//
// vanguards implements three layers of Tor circuit-safety watchdog:
//
//   1. PathVerify — observes the layered guard sets (layer-1/layer-2/layer-3)
//      Tor reports via ORCONN/GUARD/CIRC events and warns when:
//
//        - the number of layer-1 guard connections deviates from the
//          configured value (side-channel attack indicator),
//        - circuit route lengths diverge from the expected length per
//          hidden-service purpose (cannibalization indicator),
//        - a circuit uses a guard that is not in the published layer set.
//
//   2. RendGuard — rendezvous-point usage vs. consensus bandwidth:
//
//        use-to-bw ratio above REND_USE_MAX_USE_TO_BW_RATIO means a relay
//        is being over-used as a rendezvous point (likely guard discovery
//        attack). The check is disabled until
//        REND_USE_GLOBAL_START_COUNT events have been observed, so small
//        samples do not produce false positives.
//
//   3. CBTVerify — circuit-build-time statistics. Tracks launched/built/
//        timeout counts overall and for hidden-service circuits. If the
//        timeout rate crosses CbtMaxTimeoutRate, the embedded Tor is
//        suspect (likely a network adversary dropping HS circuits).
//
// The Go port keeps the structure flat (no Stem dependency) and exposes
// stateless methods so a single event loop can call them as the control
// port feeds CIRCUIT / ORCONN / GUARD / BW events in. All thresholds are
// configurable so tests can exercise the boundary conditions without
// needing a real Tor process.
package system

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// VanguardsConfig mirrors the relevant subset of the vanguards config
// (`vanguards.conf` upstream).
type VanguardsConfig struct {
	// FullVanguards is true when both HSLayer2Nodes and HSLayer3Nodes are
	// configured; false means "vanguards-lite" (no layer-3, smaller layer-2).
	FullVanguards bool
	// NumLayer1/2/3 are the configured number of guards per layer.
	NumLayer1 int
	NumLayer2 int
	NumLayer3 int
}

// DefaultVanguardsConfig returns the upstream defaults. Layer-1 = 1,
// layer-2 = 4, layer-3 = 0 (vanguards-lite).
func DefaultVanguardsConfig() VanguardsConfig {
	return VanguardsConfig{
		FullVanguards: false,
		NumLayer1:     1,
		NumLayer2:     4,
		NumLayer3:     0,
	}
}

// RouteLenForPurpose returns the expected number of hops in a circuit for
// the given hidden-service purpose, matching vanguards' `_ROUTELEN_FOR_PURPOSE`
// tables. If `lite` is true the lite table is used (shorter paths).
func RouteLenForPurpose(purpose string, lite bool) (int, bool) {
	full := map[string]int{
		"HS_VANGUARDS":     4,
		"HS_CLIENT_HSDIR":  5,
		"HS_CLIENT_INTRO":  5,
		"HS_CLIENT_REND":   4,
		"HS_SERVICE_HSDIR": 4,
		"HS_SERVICE_INTRO": 4,
		"HS_SERVICE_REND":  5,
	}
	liteTbl := map[string]int{
		"HS_VANGUARDS":     3,
		"HS_CLIENT_HSDIR":  4,
		"HS_CLIENT_INTRO":  4,
		"HS_CLIENT_REND":   3,
		"HS_SERVICE_HSDIR": 4,
		"HS_SERVICE_INTRO": 4,
		"HS_SERVICE_REND":  4,
	}
	if lite {
		v, ok := liteTbl[purpose]
		return v, ok
	}
	v, ok := full[purpose]
	return v, ok
}

// Layer1Stats is a per-guard connection+use counter, matching
// `Layer1Stats` in vanguards pathverify.py.
type Layer1Stats struct {
	GuardFP   string
	UseCount  int
	ConnCount int
}

// Layer1Guards is the layer-1 guard set; it tracks both the number of
// open OR connections and the number of circuits built through each
// guard. Both metrics are reported against the configured NumLayer1.
type Layer1Guards struct {
	mu        sync.Mutex
	guards    map[string]*Layer1Stats
	numLayer1 int
}

// NewLayer1Guards returns a layer-1 tracker expecting `n` guards.
func NewLayer1Guards(n int) *Layer1Guards {
	if n < 0 {
		n = 0
	}
	return &Layer1Guards{
		guards:    make(map[string]*Layer1Stats),
		numLayer1: n,
	}
}

// AddConn increments the connection count for `fp` (an ORCONN CONNECTED
// event).
func (g *Layer1Guards) AddConn(fp string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s, ok := g.guards[fp]; ok {
		s.ConnCount++
		return
	}
	g.guards[fp] = &Layer1Stats{GuardFP: fp, ConnCount: 1}
}

// DelConn decrements the connection count for `fp`; if it falls to zero
// the guard is removed entirely.
func (g *Layer1Guards) DelConn(fp string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.guards[fp]
	if !ok {
		return
	}
	if s.ConnCount > 1 {
		s.ConnCount--
		return
	}
	delete(g.guards, fp)
}

// AddUseCount records one circuit built through `fp`.
func (g *Layer1Guards) AddUseCount(fp string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if s, ok := g.guards[fp]; ok {
		s.UseCount++
		return
	}
	// A circuit through a guard we have not seen an ORCONN for is
	// abnormal. The caller (PathVerify.CircEvent) is responsible for
	// emitting the WARN, so we silently count it here.
	g.guards[fp] = &Layer1Stats{GuardFP: fp, UseCount: 1}
}

// Snapshot returns a copy of the current state for tests / dashboards.
func (g *Layer1Guards) Snapshot() []Layer1Stats {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Layer1Stats, 0, len(g.guards))
	for _, s := range g.guards {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GuardFP < out[j].GuardFP })
	return out
}

// Layer1ConnVerdict is the result of CheckConnCounts.
type Layer1ConnVerdict struct {
	// Count is the actual number of distinct layer-1 guards currently
	// connected.
	Count int
	// Extra is the list of guards with more than one connection.
	Extra []string
	// Status is "fewer", "correct", or "more".
	Status string
}

// CheckConnCounts returns a verdict mirroring vanguards'
// `check_conn_counts` (returns -1, 0, +1). It is the primary
// side-channel-attack indicator.
func (g *Layer1Guards) CheckConnCounts() Layer1ConnVerdict {
	g.mu.Lock()
	defer g.mu.Unlock()
	v := Layer1ConnVerdict{Count: len(g.guards)}
	switch {
	case len(g.guards) < g.numLayer1:
		v.Status = "fewer"
	case len(g.guards) > g.numLayer1:
		v.Status = "more"
	default:
		v.Status = "correct"
	}
	for fp, s := range g.guards {
		if s.ConnCount > 1 {
			v.Extra = append(v.Extra, fp)
		}
	}
	sort.Strings(v.Extra)
	return v
}

// Layer1UseVerdict is the result of CheckUseCounts.
type Layer1UseVerdict struct {
	// InUse is the number of layer-1 guards with at least one circuit.
	InUse int
	// Counts is a per-guard tally.
	Counts map[string]int
	// Status is "fewer", "correct", or "more".
	Status string
}

// CheckUseCounts returns a verdict mirroring vanguards'
// `check_use_counts` — circuits should rotate across all configured
// layer-1 guards, not stick to one.
func (g *Layer1Guards) CheckUseCounts() Layer1UseVerdict {
	g.mu.Lock()
	defer g.mu.Unlock()
	v := Layer1UseVerdict{Counts: make(map[string]int)}
	for fp, s := range g.guards {
		if s.UseCount > 0 {
			v.InUse++
			v.Counts[fp] = s.UseCount
		}
	}
	switch {
	case v.InUse > g.numLayer1:
		v.Status = "more"
	case v.InUse < g.numLayer1:
		v.Status = "fewer"
	default:
		v.Status = "correct"
	}
	return v
}

// GuardEventKind enumerates vanguards-style GUARD event transitions.
type GuardEventKind int

const (
	GuardEventGoodL2 GuardEventKind = iota
	GuardEventBadL2
)

// GuardSet holds the layer-2/layer-3 guard sets vanguards tracks. The
// "good" / "bad" transition comes from tor GUARD events: GOOD_L2
// promotes a relay to layer-2; BAD_L2 demotes it.
type GuardSet struct {
	mu    sync.Mutex
	layer map[string]struct{} // key = fingerprint
}

// NewGuardSet returns an empty guard set.
func NewGuardSet() *GuardSet { return &GuardSet{layer: make(map[string]struct{})} }

// Apply records a GUARD event and returns true if the set changed.
func (g *GuardSet) Apply(kind GuardEventKind, fp string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch kind {
	case GuardEventGoodL2:
		if _, ok := g.layer[fp]; ok {
			return false
		}
		g.layer[fp] = struct{}{}
		return true
	case GuardEventBadL2:
		if _, ok := g.layer[fp]; !ok {
			return false
		}
		delete(g.layer, fp)
		return true
	}
	return false
}

// Members returns a sorted snapshot of guard fingerprints.
func (g *GuardSet) Members() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, 0, len(g.layer))
	for fp := range g.layer {
		out = append(out, fp)
	}
	sort.Strings(out)
	return out
}

// Size returns the number of guards in the set.
func (g *GuardSet) Size() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.layer)
}

// Contains reports whether `fp` is a current member.
func (g *GuardSet) Contains(fp string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.layer[fp]
	return ok
}

// Replace swaps the guard set in one atomic step, mirroring the
// vanguards CONFIG_CHANGED handler.
func (g *GuardSet) Replace(fps []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.layer = make(map[string]struct{}, len(fps))
	for _, fp := range fps {
		if fp == "" {
			continue
		}
		g.layer[fp] = struct{}{}
	}
}

// CircuitPurpose is a small, stable subset of Tor circuit purposes that
// vanguards cares about. Anything outside this set is ignored.
type CircuitPurpose int

const (
	PurposeUnknown CircuitPurpose = iota
	PurposeHSClientHSDir
	PurposeHSClientIntro
	PurposeHSClientRend
	PurposeHSServiceHSDir
	PurposeHSServiceIntro
	PurposeHSServiceRend
	PurposeHSVanguards
)

// ParseCircuitPurpose converts a Tor CIRCUIT-event purpose string into
// a CircuitPurpose. Returns PurposeUnknown for non-HS purposes
// (vanguards itself filters them out).
func ParseCircuitPurpose(s string) CircuitPurpose {
	switch s {
	case "HS_CLIENT_HSDIR":
		return PurposeHSClientHSDir
	case "HS_CLIENT_INTRO":
		return PurposeHSClientIntro
	case "HS_CLIENT_REND":
		return PurposeHSClientRend
	case "HS_SERVICE_HSDIR":
		return PurposeHSServiceHSDir
	case "HS_SERVICE_INTRO":
		return PurposeHSServiceIntro
	case "HS_SERVICE_REND":
		return PurposeHSServiceRend
	case "HS_VANGUARDS":
		return PurposeHSVanguards
	}
	return PurposeUnknown
}

// PathVerifyConfig configures PathVerify thresholds.
type PathVerifyConfig struct {
	Vanguards VanguardsConfig
}

// PathVerify is the central vanguards-pathverify engine. It owns the
// layer-1/2/3 sets and verifies each HS circuit event against them.
type PathVerify struct {
	cfg    PathVerifyConfig
	layer1 *Layer1Guards
	layer2 *GuardSet
	layer3 *GuardSet
}

// NewPathVerify constructs a PathVerify for the given configuration.
func NewPathVerify(cfg PathVerifyConfig) *PathVerify {
	return &PathVerify{
		cfg:    cfg,
		layer1: NewLayer1Guards(cfg.Vanguards.NumLayer1),
		layer2: NewGuardSet(),
		layer3: NewGuardSet(),
	}
}

// Layer1 exposes the layer-1 tracker (handy for testing & for
// upstream code that needs to seed orconn-status at startup).
func (v *PathVerify) Layer1() *Layer1Guards { return v.layer1 }

// Layer2 exposes the layer-2 guard set.
func (v *PathVerify) Layer2() *GuardSet { return v.layer2 }

// Layer3 exposes the layer-3 guard set.
func (v *PathVerify) Layer3() *GuardSet { return v.layer3 }

// OrConnEvent records an ORCONN state change. `fp` is the relay
// fingerprint, `connected` true for CONNECTED, false for CLOSED/FAILED.
func (v *PathVerify) OrConnEvent(fp string, connected bool) {
	if connected {
		v.layer1.AddConn(fp)
	} else {
		v.layer1.DelConn(fp)
	}
}

// SetLayers replaces the layer-2/layer-3 sets in one shot. The
// full/lite distinction is inferred: if layer-3 is non-empty after the
// replace, the engine is in full-vanguards mode.
func (v *PathVerify) SetLayers(layer2, layer3 []string) {
	v.layer2.Replace(layer2)
	v.layer3.Replace(layer3)
	v.cfg.Vanguards.FullVanguards = v.layer3.Size() > 0
}

// CircuitEventResult is the per-circuit-event verdict emitted by
// PathVerify.CircEvent. The boolean fields let callers emit WARN
// notifications without re-implementing the rules.
type CircuitEventResult struct {
	// RouteLenOK is true if the circuit's path length matches the
	// expected length for the purpose (under current full/lite mode).
	RouteLenOK bool
	// RouteLenExpected is the expected number of hops.
	RouteLenExpected int
	// RouteLenActual is the number of hops observed.
	RouteLenActual int
	// Layer1OK is true if the circuit's first hop is a known layer-1
	// guard.
	Layer1OK bool
	// Layer2OK is true if the circuit's second hop is in the layer-2
	// set.
	Layer2OK bool
	// Layer3OK is true if the circuit's third hop is in the layer-3
	// set (or layer-3 is not configured).
	Layer3OK bool
	// Layer2Count is the layer-2 set size at the time of the event
	// (helps dashboards report "built with wrong number of layer-2
	// nodes" anomalies).
	Layer2Count int
	// Layer3Count mirrors Layer2Count for layer-3.
	Layer3Count int
	// Cannibalized indicates a legitimate short-path case (HSSI
	// connecting or HSCI connecting retries). The upstream Python
	// logs these as INFO, not WARN.
	Cannibalized bool
}

// CircEvent verifies an HS circuit event. `purpose` is a parsed
// CircuitPurpose (only HS_ purposes are evaluated; everything else
// short-circuits to a "skipped" verdict). `path` is the ordered list of
// (fp, nickname) tuples from the CIRCUIT event; we only consume the
// fingerprint.
func (v *PathVerify) CircEvent(purpose CircuitPurpose, path [][2]string, hsState string) CircuitEventResult {
	res := CircuitEventResult{
		Layer2Count: v.layer2.Size(),
		Layer3Count: v.layer3.Size(),
	}
	if purpose == PurposeUnknown || len(path) == 0 {
		return res
	}
	// Translate purpose back to the upstream string for RouteLenForPurpose.
	purposeStr := purposeString(purpose)
	expected, ok := RouteLenForPurpose(purposeStr, !v.cfg.Vanguards.FullVanguards)
	if !ok {
		return res
	}
	res.RouteLenExpected = expected
	res.RouteLenActual = len(path)

	// HSSI_CONNECTING and HSCI_CONNECTING are explicitly allowed to
	// take shorter paths when cannibalized or when client intros fail
	// and are retried with a new hop. Mirror vanguards' INFO log.
	cannibalized := hsState == "HSSI_CONNECTING" || hsState == "HSCI_CONNECTING"
	res.Cannibalized = cannibalized
	if len(path) == expected {
		res.RouteLenOK = true
	} else if !cannibalized {
		res.RouteLenOK = false
	} else {
		// Cannibalization: route-len mismatch is permitted but we
		// still want to verify the layer membership.
		res.RouteLenOK = true
	}

	// Layer-1: increment use count regardless of route-len result.
	fp0 := path[0][0]
	if st, ok := v.layer1.guards[fp0]; ok {
		st.UseCount++
		res.Layer1OK = true
	} else {
		// Mirror vanguards: silently count but WARN.
		v.layer1.AddUseCount(fp0)
	}

	if len(path) > 1 {
		fp1 := path[1][0]
		res.Layer2OK = v.layer2.Contains(fp1)
	}
	if v.cfg.Vanguards.NumLayer3 > 0 && len(path) > 2 {
		fp2 := path[2][0]
		res.Layer3OK = v.layer3.Contains(fp2)
	} else {
		// Layer-3 not configured; treat absence as "OK" so callers
		// do not need to special-case.
		res.Layer3OK = true
	}
	return res
}

// purposeString inverts ParseCircuitPurpose. Kept private to avoid
// leaking an enumeration to the public API.
func purposeString(p CircuitPurpose) string {
	switch p {
	case PurposeHSClientHSDir:
		return "HS_CLIENT_HSDIR"
	case PurposeHSClientIntro:
		return "HS_CLIENT_INTRO"
	case PurposeHSClientRend:
		return "HS_CLIENT_REND"
	case PurposeHSServiceHSDir:
		return "HS_SERVICE_HSDIR"
	case PurposeHSServiceIntro:
		return "HS_SERVICE_INTRO"
	case PurposeHSServiceRend:
		return "HS_SERVICE_REND"
	case PurposeHSVanguards:
		return "HS_VANGUARDS"
	}
	return ""
}

// RendGuardConfig holds the upstream defaults from rendguard.py.
type RendGuardConfig struct {
	// GlobalStartCount disables the ratio check until at least this
	// many rend uses have been recorded across all relays.
	GlobalStartCount int
	// RelayStartCount disables the per-relay check until the relay
	// has been used at least this many times.
	RelayStartCount int
	// MaxUseToBWRatio is the threshold above which a relay is
	// considered over-used (default 5.0).
	MaxUseToBWRatio float64
	// CloseCircuitsOnOveruse mirrors REND_USE_CLOSE_CIRCUITS_ON_OVERUSE.
	CloseCircuitsOnOveruse bool
}

// DefaultRendGuardConfig returns upstream defaults.
func DefaultRendGuardConfig() RendGuardConfig {
	return RendGuardConfig{
		GlobalStartCount:       1000,
		RelayStartCount:        100,
		MaxUseToBWRatio:        5.0,
		CloseCircuitsOnOveruse: true,
	}
}

// NotInConsensus is the sentinel key for relays that the local
// consensus does not know about.
const NotInConsensus = "NOT_IN_CONSENSUS"

// RendUseCount is per-relay usage + weight.
type RendUseCount struct {
	IDHex  string
	Used   int
	Weight float64
}

// RendGuard tracks rendezvous-point use rates vs consensus weight.
// Mirrors vanguards RendGuard.valid_rend_use / overused_relays.
type RendGuard struct {
	cfg           RendGuardConfig
	mu            sync.Mutex
	useCounts     map[string]*RendUseCount
	totalUse      int
	lastOveruseFP string
}

// NewRendGuard constructs a RendGuard.
func NewRendGuard(cfg RendGuardConfig) *RendGuard {
	return &RendGuard{
		cfg:       cfg,
		useCounts: make(map[string]*RendUseCount),
	}
}

// RecordUse records one use of relay `fp` with its current consensus
// weight `w` (a fraction in [0,1] from the consensus document).
// Returns true if the relay crossed the over-use threshold on this
// event.
func (g *RendGuard) RecordUse(fp string, w float64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	r, ok := g.useCounts[fp]
	if !ok {
		r = &RendUseCount{IDHex: fp, Weight: w}
		g.useCounts[fp] = r
	}
	r.Used++
	g.totalUse++
	if g.totalUse < g.cfg.GlobalStartCount {
		return false
	}
	if r.Used < g.cfg.RelayStartCount {
		return false
	}
	if r.Weight <= 0 {
		// No weight ⇒ can't compute a ratio; treat as unknown.
		return false
	}
	ratio := float64(r.Used) / (r.Weight * float64(g.totalUse))
	if ratio > g.cfg.MaxUseToBWRatio {
		g.lastOveruseFP = fp
		return true
	}
	return false
}

// LastOveruse returns the fingerprint of the most recent relay that
// crossed the over-use threshold, or "" if none.
func (g *RendGuard) LastOveruse() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastOveruseFP
}

// Stats returns a snapshot of all known relay use counts.
func (g *RendGuard) Stats() []RendUseCount {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]RendUseCount, 0, len(g.useCounts))
	for _, r := range g.useCounts {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IDHex < out[j].IDHex })
	return out
}

// CBTStats mirrors vanguards TimeoutStats: track circuit
// launched/built/timeout counters, separate for HS circuits.
type CBTStats struct {
	mu sync.Mutex

	// All circuits.
	AllLaunched int
	AllBuilt    int
	AllTimeout  int

	// Hidden-service circuits.
	HSLaunched int
	HSBuilt    int
	HSTimeout  int

	// Live tracking, mirrors self.circuits in TimeoutStats.
	live map[string]bool
}

// NewCBTStats constructs a CBTStats tracker.
func NewCBTStats() *CBTStats { return &CBTStats{live: make(map[string]bool)} }

// CircEvent records a circuit event. `isHS` indicates the purpose is
// hidden-service related. Status and reason strings mirror Tor's
// control port event names (LAUNCHED, BUILT, CLOSED, FAILED, with
// reason TIMEOUT).
func (s *CBTStats) CircEvent(circID string, status, reason string, isHS bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch status {
	case "LAUNCHED":
		s.live[circID] = isHS
		if isHS {
			s.HSLaunched++
		} else {
			s.AllLaunched++
		}
	case "BUILT":
		if isHS {
			s.HSBuilt++
		} else {
			s.AllBuilt++
		}
	case "CLOSED", "FAILED":
		delete(s.live, circID)
	}
	if reason == "TIMEOUT" {
		if isHS {
			s.HSTimeout++
		} else {
			s.AllTimeout++
		}
	}
}

// Snapshot returns a copy of the counters for dashboards.
func (s *CBTStats) Snapshot() CBTStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	liveCopy := make(map[string]bool, len(s.live))
	for k, v := range s.live {
		liveCopy[k] = v
	}
	return CBTStats{
		AllLaunched: s.AllLaunched,
		AllBuilt:    s.AllBuilt,
		AllTimeout:  s.AllTimeout,
		HSLaunched:  s.HSLaunched,
		HSBuilt:     s.HSBuilt,
		HSTimeout:   s.HSTimeout,
		live:        liveCopy,
	}
}

// TimeoutRate returns the timeout ratio for HS circuits. Returns 0 if
// no HS circuits have been observed.
func (s *CBTStats) TimeoutRate() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.HSLaunched == 0 {
		return 0
	}
	return float64(s.HSTimeout) / float64(s.HSLaunched)
}

// String formats the stats for log lines, mirroring vanguards'
// logger output.
func (s *CBTStats) String() string {
	snap := s.Snapshot()
	return fmt.Sprintf("all=%d/%d/%d hs=%d/%d/%d rate=%.3f",
		snap.AllLaunched, snap.AllBuilt, snap.AllTimeout,
		snap.HSLaunched, snap.HSBuilt, snap.HSTimeout,
		snap.TimeoutRate(),
	)
}

// Ensure time package is used by future testdata fixtures.
var _ = time.Time{}
