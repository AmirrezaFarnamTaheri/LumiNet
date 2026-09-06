package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const perAppRoutingUnsupported = "per-app routing policy is not enforced by the active packet or process routing runtime"

// PerAppProxyConfig preserves the compatibility response shape while exposing
// capability truth. Configuration is intentionally empty while enforcement is
// unavailable; mutating routes fail closed instead of persisting inert state.
type PerAppProxyConfig struct {
	Mode      string   `json:"mode"`
	Packages  []string `json:"packages"`
	Supported bool     `json:"supported"`
	Enforced  bool     `json:"enforced"`
	Reason    string   `json:"reason"`
}

func unavailablePerAppProxyConfig() PerAppProxyConfig {
	return PerAppProxyConfig{
		Mode:      "off",
		Packages:  []string{},
		Supported: false,
		Enforced:  false,
		Reason:    perAppRoutingUnsupported,
	}
}

// GetPerAppProxyConfig handles GET /api/system/per-app-proxy.
func (s *Server) GetPerAppProxyConfig(c *gin.Context) {
	c.JSON(http.StatusOK, unavailablePerAppProxyConfig())
}

func rejectPerAppProxyMutation(c *gin.Context) {
	response := unavailablePerAppProxyConfig()
	c.JSON(http.StatusNotImplemented, gin.H{
		"mode":      response.Mode,
		"packages":  response.Packages,
		"supported": response.Supported,
		"enforced":  response.Enforced,
		"reason":    response.Reason,
		"error":     perAppRoutingUnsupported,
	})
}

// SetPerAppProxyConfig handles POST /api/system/per-app-proxy.
func (s *Server) SetPerAppProxyConfig(c *gin.Context) { rejectPerAppProxyMutation(c) }

// AddPerAppProxyPackage handles POST /api/system/per-app-proxy/packages.
func (s *Server) AddPerAppProxyPackage(c *gin.Context) { rejectPerAppProxyMutation(c) }

// RemovePerAppProxyPackage handles DELETE /api/system/per-app-proxy/packages/:name.
func (s *Server) RemovePerAppProxyPackage(c *gin.Context) { rejectPerAppProxyMutation(c) }
