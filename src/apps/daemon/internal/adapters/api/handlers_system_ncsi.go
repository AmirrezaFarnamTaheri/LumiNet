package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/platform/system"
)

// GetSystemNCSI handles GET /api/system/ncsi — returns current NCSI parameters.
func (s *Server) GetSystemNCSI(c *gin.Context) {
	config, err := system.GetNCSIConfig()
	if err != nil {
		writePlatformFeatureError(c, err)
		return
	}
	c.JSON(http.StatusOK, config)
}

// SetSystemNCSI handles POST /api/system/ncsi — updates NCSI parameters.
func (s *Server) SetSystemNCSI(c *gin.Context) {
	var req system.NCSIConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	if err := system.ApplyHostNetwork(ctx, system.HostNetworkChange{
		Kind: system.HostNetworkChangeNCSI,
		NCSI: &req,
	}); err != nil {
		writePlatformFeatureError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "applied"})
}

// ResetSystemNCSI handles POST /api/system/ncsi/reset — resets NCSI to Microsoft defaults.
func (s *Server) ResetSystemNCSI(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	defaults := system.DefaultNCSIConfig()
	if err := system.ApplyHostNetwork(ctx, system.HostNetworkChange{
		Kind: system.HostNetworkChangeNCSI,
		NCSI: &defaults,
	}); err != nil {
		writePlatformFeatureError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "reset"})
}
