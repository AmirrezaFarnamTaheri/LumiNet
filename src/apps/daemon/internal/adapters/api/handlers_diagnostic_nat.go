package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
)

type stunMappingProbeRequest struct {
	Primary   string `json:"primary" binding:"required"`
	Secondary string `json:"secondary,omitempty"`
	TimeoutMs int    `json:"timeout_ms,omitempty"`
	Attempts  int    `json:"attempts,omitempty"`
}

// ProbeNATMapping exposes a bounded read-only STUN mapping diagnostic. It
// reports only directly observed mapping behavior and refuses non-public
// destinations, including a non-public OTHER-ADDRESS returned by a server.
func (s *Server) ProbeNATMapping(c *gin.Context) {
	var req stunMappingProbeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := diagnostics.ProbeSTUNMapping(c.Request.Context(), diagnostics.STUNMappingProbeRequest{
		Primary:   req.Primary,
		Secondary: req.Secondary,
		Timeout:   time.Duration(req.TimeoutMs) * time.Millisecond,
		Attempts:  req.Attempts,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "STUN_MAPPING_PROBE_FAILED", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}
