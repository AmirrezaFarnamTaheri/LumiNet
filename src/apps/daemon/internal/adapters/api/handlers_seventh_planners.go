package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
	dnsplan "github.com/maybeknott/luminet/internal/networking/dns"
	"github.com/maybeknott/luminet/internal/networking/dnstunnel"
	"github.com/maybeknott/luminet/internal/networking/kcppolicy"
)

// PlanMeshRoutes derives least-hop or latency-first paths from an operator
// supplied peer graph. It is read-only and does not modify host routes.
func (s *Server) PlanMeshRoutes(c *gin.Context) {
	var req diagnostics.MeshRouteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildMeshRoutePlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanEndpointPool ranks relay/proxy endpoints from observed success, latency,
// quota and recency evidence. It returns dispatch advice only.
func (s *Server) PlanEndpointPool(c *gin.Context) {
	var req struct {
		Endpoints          []diagnostics.EndpointPoolObservation `json:"endpoints"`
		Scope              string                                `json:"scope,omitempty"`
		PreviousSuccessful string                                `json:"previous_successful,omitempty"`
		Strategy           string                                `json:"strategy,omitempty"`
		AsOf               time.Time                             `json:"as_of,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildEndpointPoolPlanWithOptions(req.Endpoints, diagnostics.EndpointPoolOptions{
		Scope:              req.Scope,
		PreviousSuccessful: req.PreviousSuccessful,
		Strategy:           req.Strategy,
		AsOf:               req.AsOf,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanKCPPolicy resolves the same bounded KCP intent consumed by the real
// dialer/listener runtime. It is read-only and never opens a socket.
func (s *Server) PlanKCPPolicy(c *gin.Context) {
	var req kcppolicy.Input
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	policy, err := kcppolicy.Resolve(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, policy)
}

// PlanDNSTunnel estimates payload/framing characteristics for a DNS-tunnel
// profile without opening sockets or creating a tunnel.
func (s *Server) PlanDNSTunnel(c *gin.Context) {
	var req dnstunnel.PlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := dnstunnel.BuildPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanTransportTruth classifies operator-supplied connection evidence without
// dialing, mutating routes, or changing an active runtime. Handshake evidence
// is deliberately weaker than sustained in-tunnel payload evidence.
func (s *Server) PlanTransportTruth(c *gin.Context) {
	var req diagnostics.TransportTruthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildTransportTruthPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanDNSTransportIntegrity compares operator-supplied UDP/TCP DNS evidence.
// It is read-only: differing answer sets are not promoted to poisoning unless
// the caller supplies independent poisoning/injection evidence.
func (s *Server) PlanDNSTransportIntegrity(c *gin.Context) {
	var req diagnostics.DNSTransportIntegrityRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildDNSTransportIntegrityPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanDoHResolverPool validates resolver evidence and derives bounded fallback
// order. It never contacts or installs a resolver.
func (s *Server) PlanDoHResolverPool(c *gin.Context) {
	var req dnsplan.ResolverPoolPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := dnsplan.BuildResolverPoolPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanL7Signatures validates a bounded offline signature set. It does not
// inspect traffic and cannot install classifiers.
func (s *Server) PlanL7Signatures(c *gin.Context) {
	var req struct {
		Signatures []diagnostics.L7SignatureCandidate `json:"signatures"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildL7SignaturePlan(req.Signatures)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanTrafficProfile analyzes a bounded declarative traffic profile. Executable
// actions/plugins are not part of the contract.
func (s *Server) PlanTrafficProfile(c *gin.Context) {
	var req diagnostics.TrafficProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildTrafficProfilePlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanRoutingCorpus audits caller-supplied routing evidence. It fetches no
// mutable donor data and installs no policy.
func (s *Server) PlanRoutingCorpus(c *gin.Context) {
	var req struct {
		Files []diagnostics.RoutingCorpusFile `json:"files"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildRoutingCorpusPlan(req.Files)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanSNIPaths derives a bounded active/reserve/drain pool from caller-supplied
// reachability, strict-TLS, first-response, health, capacity, and path-MTU
// evidence. It does not dial or mutate packet-routing state.
func (s *Server) PlanSNIPaths(c *gin.Context) {
	var req diagnostics.SNIPathPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildSNIPathPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanSNIGateway validates the ordering and rollback preconditions for a
// DNS/TLS-router/HTTP-redirect gateway composition without changing host
// services, listeners, routes, or DNS configuration.
func (s *Server) PlanSNIGateway(c *gin.Context) {
	var req diagnostics.SNIGatewayPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildSNIGatewayPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanRelayInspection evaluates relay/MITM design evidence. The contract is
// deliberately non-executing: it opens no listeners and permits no payload
// mutation or script execution.
func (s *Server) PlanRelayInspection(c *gin.Context) {
	var req diagnostics.RelayInspectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildRelayInspectionPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanArtifactAdmission inspects only caller-supplied bounded artifact metadata
// and optional bytes. It can quarantine secret-bearing/digest-mismatched input
// without returning secret content or fetching remote URLs.
func (s *Server) PlanArtifactAdmission(c *gin.Context) {
	var req diagnostics.ArtifactAdmissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildArtifactAdmissionPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanDNSResolutionPolicy validates transport/fallback/cache/strategy/ECS
// policy without becoming a DNS runtime or contacting any resolver.
func (s *Server) PlanDNSResolutionPolicy(c *gin.Context) {
	var req diagnostics.DNSResolutionPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildDNSResolutionPolicyPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanMultiplexPolicy validates bounded session/stream/padding/bandwidth policy
// while leaving the existing runtime SMUX owner unchanged.
func (s *Server) PlanMultiplexPolicy(c *gin.Context) {
	var req diagnostics.MultiplexPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildMultiplexPolicyPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanRoutingArtifacts validates immutable routing-artifact provenance and
// digests. It neither downloads nor installs a rule database.
func (s *Server) PlanRoutingArtifacts(c *gin.Context) {
	var req struct {
		Artifacts []diagnostics.RoutingArtifactCandidate `json:"artifacts"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildRoutingArtifactPlan(req.Artifacts)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanNetworkWorkflow validates a bounded declarative init/trigger/cleanup graph.
// It never opens sockets, runs containers, or creates tunnels.
func (s *Server) PlanNetworkWorkflow(c *gin.Context) {
	var req struct {
		Actions []diagnostics.NetworkWorkflowAction `json:"actions"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildNetworkWorkflowPlan(req.Actions)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanWireGuardDevicePolicy validates peer/AllowedIP/replay/anti-abuse policy
// without generating keys, opening a WireGuard device, or installing routes.
func (s *Server) PlanWireGuardDevicePolicy(c *gin.Context) {
	var req diagnostics.WireGuardDevicePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildWireGuardDevicePolicyPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// GetConvergencePresets exposes credential-free planning presets only.
func (s *Server) GetConvergencePresets(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"kcp_intents":              []string{"legacy", "balanced", "latency", "throughput", "loss-recovery", "cpu-efficient"},
		"resolver_pool":            dnsplan.ResolverPoolPresets(),
		"traffic_profiles":         diagnostics.TrafficBehaviorPresets(),
		"routing_policies":         diagnostics.RoutingPolicyPresets(),
		"policy_group_modes":       []string{"manual-select", "latency-auto", "fallback", "load-balance"},
		"gateway_presets":          []string{"reverse-tls-relay", "websocket-edge", "managed-edge-tunnel"},
		"dns_strategies":           []string{"as-is", "prefer-ipv4", "prefer-ipv6", "ipv4-only", "ipv6-only"},
		"dns_transports":           []string{"udp", "tcp", "tls", "https", "quic", "http3", "local", "rcode", "hosts"},
		"mux_protocols":            []string{"smux", "yamux", "h2mux"},
		"routing_formats":          []string{"srs", "json", "mmdb", "dat", "txt", "text", "binary"},
		"dns_filter_intents":       []string{"balanced", "privacy", "security", "family", "anti-bypass"},
		"config_fallback_statuses": []string{"supported", "unsupported", "invalid", "error"},
		"scan_load_profiles":       []string{"conservative", "balanced", "high-throughput"},
		"planner_categories": map[string][]string{
			"transport":  {"kcp", "traffic", "muxPolicy", "dtlsPolicy", "ptLifecycle", "naivePolicy", "stegoScheme", "multipathTransport", "trafficShaper"},
			"dns":        {"doh", "dnsPolicy", "dnsResolverCampaign", "dnsTunnelDeployment", "dnsRefiner", "dnsBlocklistAudit", "dnscryptResolver", "dnsInterceptSafety", "dnscryptTopology", "dnsFilterPreset"},
			"tor":        {"torBridgeSelect", "torBootstrap", "torExitScan", "mobileTorLifecycle", "torDescriptorEvidence", "torConsensusEvidence"},
			"evidence":   {"censorshipEvidence", "securityPosture", "endpointLocation", "evidenceChain", "evidenceReceiptTopology", "apiTraceSchema"},
			"operations": {"scanLoadPolicy", "mobileConnectionReadiness", "configFallback", "processProxyRules"},
		},
		"read_only": true,
	})
}

// PlanTLSFingerprintPolicy orders bounded TLS fingerprint trials using caller-
// supplied capability evidence. It never dials, weakens TLS trust, or mutates
// the live TLS client configuration.
func (s *Server) PlanTLSFingerprintPolicy(c *gin.Context) {
	var req diagnostics.TLSFingerprintPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildTLSFingerprintPolicyPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanServiceIncidentPolicy derives a monitor incident/notification/persistence
// transition without writing monitor state or sending notifications.
func (s *Server) PlanServiceIncidentPolicy(c *gin.Context) {
	var req diagnostics.ServiceIncidentPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildServiceIncidentPolicyPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanQueueBackpressure evaluates bounded queue admission, batching, eviction,
// export-failure restoration, and framing evidence without touching live queues.
func (s *Server) PlanQueueBackpressure(c *gin.Context) {
	var req diagnostics.QueueBackpressurePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildQueueBackpressurePolicyPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}
