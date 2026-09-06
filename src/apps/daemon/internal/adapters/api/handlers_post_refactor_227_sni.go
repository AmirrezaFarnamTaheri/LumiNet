package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
)

// PlanSNIDecoyHandshake evaluates caller-supplied TCP handshake evidence for
// an out-of-window SNI decoy. It captures no packets and injects no traffic.
func (s *Server) PlanSNIDecoyHandshake(c *gin.Context) {
	var req diagnostics.SNIDecoyHandshakePlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	plan, err := diagnostics.BuildSNIDecoyHandshakePlan(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, plan)
}
