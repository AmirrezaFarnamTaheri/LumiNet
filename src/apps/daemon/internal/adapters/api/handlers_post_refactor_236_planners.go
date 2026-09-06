package api

import (
	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
)

func (s *Server) PlanClientHelloEvidence(c *gin.Context) {
	bind234(c, func(r diagnostics.ClientHelloEvidenceRequest) (any, error) {
		return diagnostics.BuildClientHelloEvidencePlan(r)
	})
}
func (s *Server) PlanEncryptedDNSPolicy(c *gin.Context) {
	bind234(c, func(r diagnostics.EncryptedDNSPolicyRequest) (any, error) {
		return diagnostics.BuildEncryptedDNSPolicyPlan(r)
	})
}
func (s *Server) PlanTorLabRelay(c *gin.Context) {
	bind234(c, func(r diagnostics.TorLabRelayRequest) (any, error) { return diagnostics.BuildTorLabRelayPlan(r) })
}
func (s *Server) PlanProxyChainSafety(c *gin.Context) {
	bind234(c, func(r diagnostics.ProxyChainSafetyRequest) (any, error) {
		return diagnostics.BuildProxyChainSafetyPlan(r)
	})
}
func (s *Server) PlanTransportReplay(c *gin.Context) {
	bind234(c, func(r diagnostics.TransportReplayRequest) (any, error) {
		return diagnostics.BuildTransportReplayPlan(r)
	})
}
func (s *Server) PlanSecretRefreshPolicy(c *gin.Context) {
	bind234(c, func(r diagnostics.SecretRefreshPolicyRequest) (any, error) {
		return diagnostics.BuildSecretRefreshPolicyPlan(r)
	})
}
func (s *Server) PlanRealityAdmission(c *gin.Context) {
	bind234(c, func(r diagnostics.RealityAdmissionRequest) (any, error) {
		return diagnostics.BuildRealityAdmissionPlan(r)
	})
}
func (s *Server) PlanServiceRecoveryPolicy(c *gin.Context) {
	bind234(c, func(r diagnostics.ServiceRecoveryPolicyRequest) (any, error) {
		return diagnostics.BuildServiceRecoveryPolicyPlan(r)
	})
}
func (s *Server) PlanNetworkTrustBundle(c *gin.Context) {
	bind234(c, func(r diagnostics.NetworkTrustBundleRequest) (any, error) {
		return diagnostics.BuildNetworkTrustBundlePlan(r)
	})
}
