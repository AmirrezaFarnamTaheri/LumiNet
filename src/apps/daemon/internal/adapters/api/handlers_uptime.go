package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/scanner"
)

// GetUptimeStats handles GET /api/system/uptime/stats
func (s *Server) GetUptimeStats(c *gin.Context) {
	monitor := scanner.GetUptimeMonitor()
	stats := monitor.GetUptimeStats()
	c.JSON(http.StatusOK, stats)
}
