package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/platform/system"
)

const (
	defaultNetworkHistoryResponse = 16
	maxNetworkHistoryResponse     = 64
)

// GetSystemNetworkState handles GET /api/system/network-state. If the daemon
// monitor has not yet established an epoch (for example in an isolated API
// test), one bounded passive capture is attempted. Capture failures remain in
// LastError while the last known-good snapshot is preserved.
func (s *Server) GetSystemNetworkState(c *gin.Context) {
	history := defaultNetworkHistoryResponse
	if raw := strings.TrimSpace(c.Query("history")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 0 || v > maxNetworkHistoryResponse {
			c.JSON(http.StatusBadRequest, gin.H{"error": "history must be between 0 and 64"})
			return
		}
		history = v
	}
	monitor := system.GetNetworkMonitor()
	if monitor.Snapshot().Revision == 0 {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		_, _ = monitor.Refresh(ctx)
		cancel()
	}
	c.JSON(http.StatusOK, monitor.Status(history))
}
