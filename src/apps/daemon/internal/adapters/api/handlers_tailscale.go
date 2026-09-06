package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const embeddedTailscaleUnsupported = "embedded Tailscale runtime is not available"

// GetTailscaleStatus handles GET /api/system/tailscale.
// The route is retained for compatibility, but the daemon does not ship a real
// embedded Tailscale runtime. Report that explicitly instead of exposing the
// experimental mock adapter as running product state.
func (s *Server) GetTailscaleStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"supported":   false,
		"running":     false,
		"udp_blocked": false,
		"hostname":    "",
		"assigned_ip": "",
		"reason":      embeddedTailscaleUnsupported,
	})
}

// ConfigureTailscale handles POST /api/system/tailscale.
func (s *Server) ConfigureTailscale(c *gin.Context) {
	var req struct {
		Running    bool   `json:"running"`
		UDPBlocked bool   `json:"udp_blocked"`
		AuthKey    string `json:"auth_key"`
		Hostname   string `json:"hostname"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// A stop with no configuration is an idempotent compatibility operation.
	// Any request that would require an embedded runtime or persist runtime
	// configuration is rejected rather than pretending the mock adapter applied it.
	if req.Running || req.UDPBlocked || req.AuthKey != "" || req.Hostname != "" {
		c.JSON(http.StatusNotImplemented, gin.H{
			"supported": false,
			"running":   false,
			"error":     embeddedTailscaleUnsupported,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":        true,
		"supported": false,
		"running":   false,
	})
}
