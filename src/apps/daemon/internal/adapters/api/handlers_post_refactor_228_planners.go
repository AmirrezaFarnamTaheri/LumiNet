package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
)

// PlanRoutingPolicyGroup converts common proxy-group intent into a bounded,
// caller-evidence-only dispatch preview. It performs no latency probe and
// installs no routing policy.
func (s *Server) PlanRoutingPolicyGroup(c *gin.Context) {
	var req diagnostics.RoutingPolicyGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildRoutingPolicyGroupPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanWireGuardIndexTranslation validates receiver-index translation and
// restart revalidation invariants without rewriting a packet or restoring a
// mapping into the live WireGuard owner.
func (s *Server) PlanWireGuardIndexTranslation(c *gin.Context) {
	var req diagnostics.WireGuardIndexTranslationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildWireGuardIndexTranslationPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}
