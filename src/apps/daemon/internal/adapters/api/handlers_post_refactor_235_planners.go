package api

import (
	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
)

func (s *Server) PlanScanLoadPolicy(c *gin.Context) {
	bind234(c, func(r diagnostics.ScanLoadPolicyRequest) (any, error) { return diagnostics.BuildScanLoadPolicyPlan(r) })
}
func (s *Server) PlanMobileConnectionReadiness(c *gin.Context) {
	bind234(c, func(r diagnostics.MobileConnectionReadinessRequest) (any, error) {
		return diagnostics.BuildMobileConnectionReadinessPlan(r)
	})
}
func (s *Server) PlanConfigFallback(c *gin.Context) {
	bind234(c, func(r diagnostics.ConfigFallbackRequest) (any, error) { return diagnostics.BuildConfigFallbackPlan(r) })
}
func (s *Server) PlanDNSInterceptSafety(c *gin.Context) {
	bind234(c, func(r diagnostics.DNSInterceptSafetyRequest) (any, error) {
		return diagnostics.BuildDNSInterceptSafetyPlan(r)
	})
}
func (s *Server) PlanTorConsensusEvidence(c *gin.Context) {
	bind234(c, func(r diagnostics.TorConsensusEvidenceRequest) (any, error) {
		return diagnostics.BuildTorConsensusEvidencePlan(r)
	})
}
func (s *Server) PlanDNSCryptTopology(c *gin.Context) {
	bind234(c, func(r diagnostics.DNSCryptTopologyRequest) (any, error) {
		return diagnostics.BuildDNSCryptTopologyPlan(r)
	})
}
func (s *Server) PlanEvidenceReceiptTopology(c *gin.Context) {
	bind234(c, func(r diagnostics.EvidenceReceiptRequest) (any, error) {
		return diagnostics.BuildEvidenceReceiptTopologyPlan(r)
	})
}
func (s *Server) PlanDNSFilterPreset(c *gin.Context) {
	bind234(c, func(r diagnostics.DNSFilterPresetRequest) (any, error) {
		return diagnostics.BuildDNSFilterPresetPlan(r)
	})
}

func (s *Server) PlanNetworkEvidenceBundle(c *gin.Context) {
	bind234(c, func(r diagnostics.NetworkEvidenceBundleRequest) (any, error) {
		return diagnostics.BuildNetworkEvidenceBundlePlan(r)
	})
}
