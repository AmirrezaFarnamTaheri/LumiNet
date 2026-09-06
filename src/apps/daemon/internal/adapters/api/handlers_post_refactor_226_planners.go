package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
)

// PlanLocalRuleSet normalizes caller-supplied local rule text. It fetches no
// URL and installs no routing or filtering policy.
func (s *Server) PlanLocalRuleSet(c *gin.Context) {
	var req diagnostics.LocalRuleSetPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildLocalRuleSetPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanTailnetTransaction models Tailnet validation/CAS semantics without
// accepting credentials or issuing an API request.
func (s *Server) PlanTailnetTransaction(c *gin.Context) {
	var req diagnostics.TailnetTransactionPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildTailnetTransactionPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanBrowserProxyHandoff validates profile/native-message/loopback proxy
// evidence. It does not register a native host or change browser settings.
func (s *Server) PlanBrowserProxyHandoff(c *gin.Context) {
	var req diagnostics.BrowserProxyHandoffPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildBrowserProxyHandoffPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanWorkerAffinity derives deterministic affinity/spillover/backoff evidence.
// It starts and restarts no process.
func (s *Server) PlanWorkerAffinity(c *gin.Context) {
	var req diagnostics.WorkerAffinityPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildWorkerAffinityPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanWebSocketReadiness evaluates caller-supplied 101/TLS evidence and never
// opens a TCP or WebSocket connection.
func (s *Server) PlanWebSocketReadiness(c *gin.Context) {
	var req diagnostics.WebSocketReadinessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildWebSocketReadinessPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}

// PlanGatewayComposition validates dependency/start/rollback/recovery ordering
// without downloading binaries or writing service-manager configuration.
func (s *Server) PlanGatewayComposition(c *gin.Context) {
	var req diagnostics.GatewayCompositionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildGatewayCompositionPlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}
