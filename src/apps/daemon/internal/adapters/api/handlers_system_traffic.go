package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/foundation/trafficstats"
)

// GetSystemTraffic handles GET /api/system/traffic — returns global evasion traffic statistics.
func (s *Server) GetSystemTraffic(c *gin.Context) {
	upBytes, downBytes := trafficstats.GetEvasionTrafficStats()
	c.JSON(http.StatusOK, gin.H{
		"upload_bytes":   upBytes,
		"download_bytes": downBytes,
	})
}

// ResetSystemTraffic handles POST /api/system/traffic/reset — resets evasion traffic statistics.
func (s *Server) ResetSystemTraffic(c *gin.Context) {
	trafficstats.ResetEvasionTrafficStats()
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": "Traffic counters reset successfully.",
	})
}
