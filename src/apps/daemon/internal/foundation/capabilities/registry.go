package capabilities

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
)

type Maturity string

const (
	MaturityStable       Maturity = "stable"
	MaturityBeta         Maturity = "beta"
	MaturityExperimental Maturity = "experimental"
	MaturityInternal     Maturity = "internal"
	MaturityUnavailable  Maturity = "unavailable"
)

type CapabilityID string

const (
	CapDNSControl        CapabilityID = "dns_control"
	CapProxyControl      CapabilityID = "proxy_control"
	CapCapture           CapabilityID = "raw_capture"
	CapDiagnostics       CapabilityID = "diagnostics"
	CapRoutingPlugins    CapabilityID = "routing_plugins"
	CapActiveProbes      CapabilityID = "active_probes"
	CapFlowObservability CapabilityID = "flow_observability"
	CapNetworkState      CapabilityID = "network_state"
	CapProfileConversion CapabilityID = "profile_conversion"
)

type Capability struct {
	ID                CapabilityID `json:"id"`
	Name              string       `json:"name"`
	Description       string       `json:"description"`
	Maturity          Maturity     `json:"maturity"`
	Platforms         []string     `json:"platforms"`
	Workflow          WorkflowID   `json:"workflow"`
	UnavailableReason string       `json:"unavailable_reason,omitempty"`
}

type Registry struct {
	mu           sync.RWMutex
	capabilities map[CapabilityID]Capability
}

func NewRegistry() *Registry {
	r := &Registry{
		capabilities: make(map[CapabilityID]Capability),
	}
	r.registerDefaults()
	return r
}

func (r *Registry) registerDefaults() {
	r.capabilities[CapDNSControl] = Capability{
		ID:          CapDNSControl,
		Name:        "DNS Interception & Control",
		Description: "Mutates and overrides system resolver policies and DNS routing paths.",
		Maturity:    MaturityBeta,
		Platforms:   []string{"windows", "linux", "darwin"},
		Workflow:    WorkflowOperateLumiNet,
	}
	r.capabilities[CapProxyControl] = Capability{
		ID:          CapProxyControl,
		Name:        "Proxy Egress Management",
		Description: "Runs external sing-box and xray cores, routes application traffic.",
		Maturity:    MaturityStable,
		Platforms:   []string{"windows", "linux", "darwin", "android", "ios"},
		Workflow:    WorkflowOperateLumiNet,
	}
	r.capabilities[CapCapture] = Capability{
		ID:                CapCapture,
		Name:              "Raw Packet Capture & Injection",
		Description:       "Reserved for a host-verified packet capture implementation; it is not exposed by the current server runtime.",
		Maturity:          MaturityUnavailable,
		Platforms:         []string{"windows", "linux"},
		Workflow:          WorkflowDiagnoseNetwork,
		UnavailableReason: "no host-verified capture backend is initialized",
	}
	r.capabilities[CapDiagnostics] = Capability{
		ID:          CapDiagnostics,
		Name:        "Network Diagnostics",
		Description: "Performs baseline network scans, ping tests, captive portal detection, and path tracing.",
		Maturity:    MaturityStable,
		Platforms:   []string{"windows", "linux", "darwin", "android", "ios"},
		Workflow:    WorkflowDiagnoseNetwork,
	}
	r.capabilities[CapRoutingPlugins] = Capability{
		ID:          CapRoutingPlugins,
		Name:        "Routing Adapter Configuration Validation",
		Description: "Validates redacted routing-adapter configuration and readiness metadata; it does not load or execute third-party extensions.",
		Maturity:    MaturityBeta,
		Platforms:   []string{"windows", "linux", "darwin"},
		Workflow:    WorkflowOperateLumiNet,
	}
	r.capabilities[CapActiveProbes] = Capability{
		ID:                CapActiveProbes,
		Name:              "Active Probe Reflection",
		Description:       "Reserved for a reviewed active-probe implementation; no active reflection service is exposed by the current server runtime.",
		Maturity:          MaturityUnavailable,
		Platforms:         []string{"windows", "linux", "darwin"},
		Workflow:          WorkflowScanTargets,
		UnavailableReason: "no reviewed active-probe service is initialized",
	}
	r.capabilities[CapFlowObservability] = Capability{
		ID:          CapFlowObservability,
		Name:        "Cross-Runtime Flow Observability",
		Description: "Publishes owner-declared live flow metadata, byte counters, network epochs, and owner-authorized teardown without claiming coverage for unregistered runtimes.",
		Maturity:    MaturityBeta,
		Platforms:   []string{"all"},
		Workflow:    WorkflowOperateLumiNet,
	}
	r.capabilities[CapNetworkState] = Capability{
		ID:          CapNetworkState,
		Name:        "Passive Network State",
		Description: "Observes interface and inferred default-egress changes as a monotonic network epoch without acquiring routes, radios, or host-network authority.",
		Maturity:    MaturityBeta,
		Platforms:   []string{"all"},
		Workflow:    WorkflowDiagnoseNetwork,
	}
	r.capabilities[CapProfileConversion] = Capability{
		ID:          CapProfileConversion,
		Name:        "Loss-Aware Profile Conversion",
		Description: "Converts locally supplied canonical proxy content into multiple client/runtime representations with explicit unsupported/lossy evidence instead of silent field dropping.",
		Maturity:    MaturityBeta,
		Platforms:   []string{"all"},
		Workflow:    WorkflowOperateLumiNet,
	}
}

func (r *Registry) All() []Capability {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make([]Capability, 0, len(r.capabilities))
	for _, cap := range r.capabilities {
		res = append(res, cap)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].ID < res[j].ID })
	return res
}

// SetMaturity changes the availability state of a registered capability. It is
// intended for startup wiring to mark a feature unavailable when its service
// initialization fails.
func (r *Registry) SetMaturity(id CapabilityID, maturity Maturity) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	capability, exists := r.capabilities[id]
	if !exists {
		return fmt.Errorf("unknown capability: %s", id)
	}
	capability.Maturity = maturity
	r.capabilities[id] = capability
	return nil
}

func (r *Registry) IsPermitted(id CapabilityID) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cap, exists := r.capabilities[id]
	if !exists {
		return false, fmt.Errorf("unknown capability: %s", id)
	}
	if cap.Maturity == MaturityUnavailable {
		return false, nil
	}

	// Platform check
	currentOS := runtime.GOOS
	platformMatch := false
	for _, p := range cap.Platforms {
		if p == currentOS || p == "all" {
			platformMatch = true
			break
		}
	}
	if !platformMatch {
		return false, fmt.Errorf("capability %s is not supported on target platform: %s", id, currentOS)
	}
	return true, nil
}
