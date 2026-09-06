package api

import (
	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
	"net/http"
)

func bind234[T any](c *gin.Context, build func(T) (any, error)) {
	var req T
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	v, err := build(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, v)
}
func (s *Server) PlanDNSBlocklistCorpus(c *gin.Context) {
	bind234(c, func(r diagnostics.DNSBlocklistCorpusRequest) (any, error) {
		return diagnostics.BuildDNSBlocklistCorpusPlan(r)
	})
}
func (s *Server) PlanAPITraceSchema(c *gin.Context) {
	bind234(c, func(r diagnostics.APITraceSchemaRequest) (any, error) { return diagnostics.BuildAPITraceSchemaPlan(r) })
}
func (s *Server) PlanTorDescriptorEvidence(c *gin.Context) {
	bind234(c, func(r diagnostics.TorDescriptorEvidenceRequest) (any, error) {
		return diagnostics.BuildTorDescriptorEvidencePlan(r)
	})
}
func (s *Server) PlanProcessProxyRules(c *gin.Context) {
	bind234(c, func(r diagnostics.ProcessProxyRuleRequest) (any, error) {
		return diagnostics.BuildProcessProxyRulePlan(r)
	})
}
func (s *Server) PlanEvidenceChain(c *gin.Context) {
	bind234(c, func(r diagnostics.EvidenceChainRequest) (any, error) { return diagnostics.BuildEvidenceChainPlan(r) })
}
func (s *Server) PlanDNSCryptResolverPolicy(c *gin.Context) {
	bind234(c, func(r diagnostics.DNSCryptResolverPolicyRequest) (any, error) {
		return diagnostics.BuildDNSCryptResolverPolicyPlan(r)
	})
}
