package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
)

// PlanTunnelSafety exposes desired-vs-observed tunnel protection truth and
// fail-closed recovery semantics. It never mutates host networking.
func (s *Server) PlanTunnelSafety(c *gin.Context) {
	var req diagnostics.TunnelSafetyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildTunnelSafetyPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanSplitTunnel normalizes per-app/process/path routing intent and produces a
// deterministic backup identity without claiming runtime enforcement.
func (s *Server) PlanSplitTunnel(c *gin.Context) {
	var req diagnostics.SplitTunnelPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildSplitTunnelPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanRelayConstraints filters caller-supplied relay metadata by explicit
// eligibility constraints. Quality/health scoring remains owned elsewhere.
func (s *Server) PlanRelayConstraints(c *gin.Context) {
	var req diagnostics.RelayConstraintPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildRelayConstraintPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanUpdateRollout models deterministic staged rollout and signed-metadata
// high-water semantics. It neither downloads nor installs an update.
func (s *Server) PlanUpdateRollout(c *gin.Context) {
	var req diagnostics.UpdateRolloutPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildUpdateRolloutPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanTLSInterceptionEvidence evaluates caller-supplied TLS mismatch and
// security-regression evidence. It performs no capture, handshake, or lookup
// against a mutable fingerprint database and cannot identify a MITM product.
func (s *Server) PlanTLSInterceptionEvidence(c *gin.Context) {
	var req diagnostics.TLSInterceptionEvidenceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildTLSInterceptionEvidencePlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}
