package api

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/capabilities"
	"github.com/maybeknott/luminet/internal/native/bridge"
)

// setupSystemRoutes registers /api/system/* endpoints.
func (s *Server) setupSystemRoutes(rg *gin.RouterGroup) {
	sys := rg.Group("/system")

	// General
	sys.GET("/status", s.GetSystemStatus)
	sys.GET("/ping", s.HandleSystemPing)
	sys.GET("/traffic", s.GetSystemTraffic)
	sys.POST("/traffic/reset", s.ResetSystemTraffic)

	// Cross-runtime observability. Coverage is owner-declared and intentionally
	// partial rather than inferred from UI state.
	sys.GET("/flows", capabilities.GuardRoute(s.capabilities, capabilities.CapFlowObservability), s.GetSystemFlows)
	sys.GET("/flows/:id", capabilities.GuardRoute(s.capabilities, capabilities.CapFlowObservability), s.GetSystemFlow)
	sys.DELETE("/flows/:id", capabilities.GuardRoute(s.capabilities, capabilities.CapFlowObservability), s.CloseSystemFlow)
	sys.POST("/flows/close", capabilities.GuardRoute(s.capabilities, capabilities.CapFlowObservability), s.CloseSystemFlows)
	sys.GET("/network-state", capabilities.GuardRoute(s.capabilities, capabilities.CapNetworkState), s.GetSystemNetworkState)
	sys.GET("/network-intelligence", capabilities.GuardRoute(s.capabilities, capabilities.CapNetworkState), s.GetSystemNetworkIntelligence)

	// Read-only host mutation preview. Apply authority remains with the existing
	// DNS/NCSI/proxy/TUN endpoints and system.ApplyHostNetwork.
	sys.POST("/host-network/plan", s.PlanHostNetwork)

	// DNS
	sys.GET("/dns", capabilities.GuardRoute(s.capabilities, capabilities.CapDNSControl), s.GetDnsStatus)
	sys.POST("/dns", capabilities.GuardRoute(s.capabilities, capabilities.CapDNSControl), s.SetDns)
	sys.DELETE("/dns", capabilities.GuardRoute(s.capabilities, capabilities.CapDNSControl), s.ClearDns)

	// Proxy
	sys.GET("/proxy", capabilities.GuardRoute(s.capabilities, capabilities.CapProxyControl), s.GetProxyStatus)
	sys.POST("/proxy", capabilities.GuardRoute(s.capabilities, capabilities.CapProxyControl), s.SetProxy)
	sys.DELETE("/proxy", capabilities.GuardRoute(s.capabilities, capabilities.CapProxyControl), s.ClearProxy)
	sys.GET("/proxy.pac", s.GetProxyPAC)

	// DDNS
	sys.GET("/ddns", s.GetDdnsStatus)
	sys.POST("/ddns", s.SetDdnsConfig)
	sys.POST("/ddns/force", s.ForceDdns)

	// Profiles
	sys.GET("/profiles", s.GetProfiles)
	sys.POST("/profiles/:name/apply", s.ApplyProfile)

	// Startup
	sys.GET("/startup", s.GetStartupStatus)
	sys.POST("/startup", s.SetStartup)

	// Settings
	sys.GET("/settings", s.GetSystemSettings)
	sys.POST("/settings", s.SetSystemSettings)

	// Evasion Tunnel
	sys.GET("/evasion-tunnel", capabilities.GuardRoute(s.capabilities, capabilities.CapProxyControl), s.GetEvasionTunnelStatus)
	sys.POST("/evasion-tunnel", capabilities.GuardRoute(s.capabilities, capabilities.CapProxyControl), s.SetEvasionTunnel)
	sys.GET("/evasion-tunnel/logs", capabilities.GuardRoute(s.capabilities, capabilities.CapProxyControl), s.GetEvasionTunnelLogs)

	// TUN Router
	sys.GET("/tun-router", s.GetTunRouterStatus)
	sys.POST("/tun-router", s.SetTunRouter)

	// Advanced Bypass Engines (Tor & Psiphon)
	sys.GET("/engines", capabilities.GuardRoute(s.capabilities, capabilities.CapProxyControl), s.GetEnginesStatus)
	sys.POST("/engines", capabilities.GuardRoute(s.capabilities, capabilities.CapProxyControl), s.ControlEngine)
	sys.POST("/engines/tor/identity", capabilities.GuardRoute(s.capabilities, capabilities.CapProxyControl), s.RotateTorIdentity)
	sys.POST("/tor/probe", capabilities.GuardRoute(s.capabilities, capabilities.CapProxyControl), s.ProbeOnionService)
	sys.POST("/tor/bridges/probe", capabilities.GuardRoute(s.capabilities, capabilities.CapProxyControl), s.ProbeTorBridges)
	sys.POST("/tor/exit-check", capabilities.GuardRoute(s.capabilities, capabilities.CapProxyControl), s.CheckTorExitNode)

	// NCSI Fix
	sys.GET("/ncsi", s.GetSystemNCSI)
	sys.POST("/ncsi", s.SetSystemNCSI)
	sys.POST("/ncsi/reset", s.ResetSystemNCSI)

	// Provisioning & Deploy (Session 9)
	sys.POST("/provision/vps", s.StartVpsProvision)
	sys.POST("/provision/worker", s.StartEdgeDeploy)
	sys.POST("/provision/templates/vless-devcontainer", s.GenerateVLESSDevcontainer)

	// Advanced Circumvention & Refactor Handlers
	sys.POST("/sni-spoofing", s.HandleSNISpoofing)
	sys.POST("/dpi-desync", s.HandleDPIDesync)
	sys.POST("/cdn-discover", s.HandleCDNDiscover)
	sys.POST("/cloudflare-deploy", s.HandleCloudflareDeploy)
	sys.POST("/gdrive-tunnel", s.HandleGDriveTunnel)
	sys.GET("/master-telemetry", s.HandleMasterTelemetry)
	sys.POST("/subscription-parse", s.HandleSubscriptionParse)
	sys.GET("/vpn-state", s.HandleVPNState)
	sys.POST("/doh-blocklist", s.HandleDoHBlocklist)
	sys.POST("/antibot-inspect", s.HandleAntiBotInspect)
	sys.POST("/warp-noise", s.HandleWarpNoise)
	sys.POST("/warp-register", s.HandleWarpRegister)
	sys.POST("/warp-scan", s.HandleWarpScan)
	sys.POST("/geosite-match", s.HandleGeoSiteMatch)
	sys.GET("/device-profile", s.HandleGetDeviceProfile)
	sys.POST("/device-profile", s.HandleSetDeviceProfile)
	sys.POST("/smart-dns", s.HandleSmartDNS)
	sys.POST("/cdn-fronting", s.HandleCDNFronting)
	sys.POST("/clean-ip-probe", s.HandleCleanIPProbe)
	sys.POST("/iperf", s.RunIperfProbe)
	sys.POST("/stun-mapping", s.ProbeNATMapping)
	sys.POST("/ip-security", s.HandleIPSecurity)
	sys.POST("/port-preflight", s.PreflightLocalPort)
	sys.POST("/mesh-route-plan", s.PlanMeshRoutes)
	sys.POST("/endpoint-pool-plan", s.PlanEndpointPool)
	sys.POST("/kcp-policy-plan", s.PlanKCPPolicy)
	sys.POST("/doh-resolver-pool-plan", s.PlanDoHResolverPool)
	sys.POST("/l7-signature-plan", s.PlanL7Signatures)
	sys.POST("/traffic-profile-plan", s.PlanTrafficProfile)
	sys.POST("/routing-corpus-plan", s.PlanRoutingCorpus)
	sys.POST("/sni-path-plan", s.PlanSNIPaths)
	sys.POST("/sni-gateway-plan", s.PlanSNIGateway)
	sys.POST("/relay-inspection-plan", s.PlanRelayInspection)
	sys.POST("/artifact-admission-plan", s.PlanArtifactAdmission)
	sys.POST("/dns-resolution-policy-plan", s.PlanDNSResolutionPolicy)
	sys.POST("/multiplex-policy-plan", s.PlanMultiplexPolicy)
	sys.POST("/routing-artifact-plan", s.PlanRoutingArtifacts)
	sys.POST("/tls-fingerprint-policy-plan", s.PlanTLSFingerprintPolicy)
	sys.POST("/service-incident-policy-plan", s.PlanServiceIncidentPolicy)
	sys.POST("/queue-backpressure-plan", s.PlanQueueBackpressure)
	sys.POST("/network-workflow-plan", s.PlanNetworkWorkflow)
	sys.POST("/wireguard-device-policy-plan", s.PlanWireGuardDevicePolicy)
	sys.POST("/wireguard-index-translation-plan", s.PlanWireGuardIndexTranslation)
	sys.POST("/local-ruleset-plan", s.PlanLocalRuleSet)
	sys.POST("/routing-policy-group-plan", s.PlanRoutingPolicyGroup)
	sys.POST("/tunnel-safety-plan", s.PlanTunnelSafety)
	sys.POST("/split-tunnel-plan", s.PlanSplitTunnel)
	sys.POST("/relay-constraint-plan", s.PlanRelayConstraints)
	sys.POST("/update-rollout-plan", s.PlanUpdateRollout)
	sys.POST("/tls-interception-evidence-plan", s.PlanTLSInterceptionEvidence)
	sys.POST("/tor-bridge-selection-plan", s.PlanTorBridgeSelection)
	sys.POST("/tor-bootstrap-evidence-plan", s.PlanTorBootstrapEvidence)
	sys.POST("/censorship-measurement-plan", s.PlanCensorshipMeasurement)
	sys.POST("/dtls-session-policy-plan", s.PlanDTLSSessionPolicy)
	sys.POST("/phantom-pool-plan", s.PlanPhantomPool)
	sys.POST("/flow-filter-plan", s.PlanFlowFilter)
	sys.POST("/pluggable-transport-plan", s.PlanPluggableTransport)
	sys.POST("/circumvention-fallback-plan", s.PlanCircumventionFallback)
	sys.POST("/naive-proxy-policy-plan", s.PlanNaiveProxyPolicy)
	sys.POST("/stego-scheme-plan", s.PlanStegoScheme)
	sys.POST("/multipath-transport-plan", s.PlanMultipathTransport)
	sys.POST("/dns-resolver-campaign-plan", s.PlanDNSResolverCampaign)
	sys.POST("/outline-access-plan", s.PlanOutlineAccess)
	sys.POST("/dns-tunnel-deployment-plan", s.PlanDNSTunnelDeployment)
	sys.POST("/dns-refiner-plan", s.PlanDNSRefiner)
	sys.POST("/https-upgrade-ruleset-plan", s.PlanHTTPSUpgradeRuleset)
	sys.POST("/tor-exit-scan-plan", s.PlanTorExitScan)
	sys.POST("/mobile-tor-lifecycle-plan", s.PlanMobileTorLifecycle)
	sys.POST("/security-posture-plan", s.PlanSecurityPosture)
	sys.POST("/traffic-shaper-plan", s.PlanTrafficShaper)
	sys.POST("/endpoint-location-evidence-plan", s.PlanEndpointLocationEvidence)
	sys.POST("/dns-blocklist-corpus-plan", s.PlanDNSBlocklistCorpus)
	sys.POST("/api-trace-schema-plan", s.PlanAPITraceSchema)
	sys.POST("/tor-descriptor-evidence-plan", s.PlanTorDescriptorEvidence)
	sys.POST("/process-proxy-rule-plan", s.PlanProcessProxyRules)
	sys.POST("/evidence-chain-plan", s.PlanEvidenceChain)
	sys.POST("/dnscrypt-resolver-policy-plan", s.PlanDNSCryptResolverPolicy)
	sys.POST("/scan-load-policy-plan", s.PlanScanLoadPolicy)
	sys.POST("/mobile-connection-readiness-plan", s.PlanMobileConnectionReadiness)
	sys.POST("/config-fallback-plan", s.PlanConfigFallback)
	sys.POST("/dns-intercept-safety-plan", s.PlanDNSInterceptSafety)
	sys.POST("/tor-consensus-evidence-plan", s.PlanTorConsensusEvidence)
	sys.POST("/dnscrypt-topology-plan", s.PlanDNSCryptTopology)
	sys.POST("/evidence-receipt-topology-plan", s.PlanEvidenceReceiptTopology)
	sys.POST("/dns-filter-preset-plan", s.PlanDNSFilterPreset)
	sys.POST("/network-evidence-bundle-plan", s.PlanNetworkEvidenceBundle)
	// Post-refactor-236 bounded evidence/policy surfaces.
	sys.POST("/clienthello-evidence-plan", s.PlanClientHelloEvidence)
	sys.POST("/encrypted-dns-policy-plan", s.PlanEncryptedDNSPolicy)
	sys.POST("/tor-lab-relay-plan", s.PlanTorLabRelay)
	sys.POST("/proxy-chain-safety-plan", s.PlanProxyChainSafety)
	sys.POST("/transport-replay-plan", s.PlanTransportReplay)
	sys.POST("/secret-refresh-policy-plan", s.PlanSecretRefreshPolicy)
	sys.POST("/reality-admission-plan", s.PlanRealityAdmission)
	sys.POST("/service-recovery-policy-plan", s.PlanServiceRecoveryPolicy)
	sys.POST("/network-trust-bundle-plan", s.PlanNetworkTrustBundle)
	sys.POST("/tailnet-transaction-plan", s.PlanTailnetTransaction)
	sys.POST("/browser-proxy-handoff-plan", s.PlanBrowserProxyHandoff)
	sys.POST("/worker-affinity-plan", s.PlanWorkerAffinity)
	sys.POST("/websocket-readiness-plan", s.PlanWebSocketReadiness)
	sys.POST("/gateway-composition-plan", s.PlanGatewayComposition)
	sys.POST("/sni-decoy-handshake-plan", s.PlanSNIDecoyHandshake)
	sys.GET("/convergence-presets", s.GetConvergencePresets)
	sys.POST("/peer-discovery-plan", s.PlanPeerDiscovery)
	sys.POST("/dns-tunnel-plan", s.PlanDNSTunnel)
	sys.POST("/transport-truth-plan", s.PlanTransportTruth)
	sys.POST("/dns-transport-integrity-plan", s.PlanDNSTransportIntegrity)

	// Per-App Proxy
	sys.GET("/per-app-proxy", s.GetPerAppProxyConfig)
	sys.POST("/per-app-proxy", s.SetPerAppProxyConfig)
	sys.POST("/per-app-proxy/packages", s.AddPerAppProxyPackage)
	sys.DELETE("/per-app-proxy/packages/:name", s.RemovePerAppProxyPackage)

	// Safety Policy
	sys.GET("/safety-policy", s.GetSafetyPolicy)
	sys.POST("/safety-policy", s.SetSafetyPolicy)
	sys.GET("/safety-policy/audit", s.AuditSafetyPolicy)

	// Tailscale
	sys.GET("/tailscale", s.GetTailscaleStatus)
	sys.POST("/tailscale", s.ConfigureTailscale)

	// Tarpit
	sys.GET("/tarpit", s.GetTarpitStatus)

	// Uptime Stats
	sys.GET("/uptime/stats", s.GetUptimeStats)

	// Signed update admission. This is a verification/planning surface only; it
	// deliberately owns no download or installation mutation.
	sys.POST("/update/discover", s.DiscoverSignedUpdate)
	sys.POST("/update/plan", s.PlanSignedUpdate)
	sys.POST("/update/stage", s.StageSignedUpdate)

	// Diagnostic Doctor & P2P Cognitive Stack
	doctor := sys.Group("/doctor")
	{
		doctor.GET("/diagnose", s.HandleCensorshipDiagnose)
		doctor.GET("/trust", s.HandleGetTrustScores)
		doctor.POST("/rate", s.HandleSubmitNodeRating)
		doctor.POST("/path-bonding", s.HandleEstablishPathBonding)
	}
}

func (s *Server) newDoctorHandler() *DoctorHandler {
	return NewDoctorHandler(
		NewChecker("SQLite Connection", func(ctx context.Context) CheckResult {
			if s.store == nil || s.store.Conn() == nil {
				return CheckResult{OK: false, Message: "database unavailable"}
			}
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			var one int
			if err := s.store.Conn().QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
				return CheckResult{OK: false, Message: "database readiness query failed"}
			}
			return CheckResult{OK: true, Message: "database ready"}
		}),
		NewChecker("LumiCore ABI", func(context.Context) CheckResult {
			version, err := bridge.NegotiateVersion()
			if err != nil {
				return CheckResult{OK: false, Message: "degraded: native core ABI unavailable"}
			}
			return CheckResult{OK: true, Message: "native core " + version}
		}),
	)
}
