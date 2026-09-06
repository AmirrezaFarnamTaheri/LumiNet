package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
)

type iperfProbeRequest struct {
	Address                string `json:"address" binding:"required"`
	Protocol               string `json:"protocol"`
	DurationSecs           int    `json:"duration_secs,omitempty"`
	OmitSecs               int    `json:"omit_secs,omitempty"`
	Parallel               int    `json:"parallel,omitempty"`
	Reverse                bool   `json:"reverse,omitempty"`
	Bidirectional          bool   `json:"bidirectional,omitempty"`
	UDPBitrateMbps         int    `json:"udp_bitrate_mbps,omitempty"`
	AuthorizationConfirmed bool   `json:"authorization_confirmed"`
}

// RunIperfProbe runs the real iperf3 control/data protocol against a public
// iperf3 server. It never substitutes a raw socket flood for protocol success.
func (s *Server) RunIperfProbe(c *gin.Context) {
	var req iperfProbeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !req.AuthorizationConfirmed {
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "IPERF_AUTHORIZATION_REQUIRED",
			"message": "active throughput tests require per-operation authorization confirmation",
		})
		return
	}
	protocol := req.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	duration := time.Duration(req.DurationSecs) * time.Second
	if duration <= 0 {
		duration = 5 * time.Second
	}
	probe := diagnostics.NewIperfProbe(req.Address, protocol, duration)
	probe.Omit = time.Duration(req.OmitSecs) * time.Second
	probe.Parallel = req.Parallel
	probe.Reverse = req.Reverse
	probe.Bidirectional = req.Bidirectional
	probe.UDPBitrateMbps = req.UDPBitrateMbps
	ctx, cancel := context.WithTimeout(c.Request.Context(), 75*time.Second)
	defer cancel()
	result, err := probe.Run(ctx)
	if err != nil {
		status := http.StatusBadGateway
		errMsg := err.Error()
		if strings.Contains(errMsg, "executable unavailable") {
			status = http.StatusNotImplemented
		} else if isIperfBadRequest(errMsg) {
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"error": "IPERF_PROBE_FAILED", "message": errMsg})
		return
	}
	c.JSON(http.StatusOK, result)
}

func isIperfBadRequest(msg string) bool {
	badRequestTokens := []string{
		"unsupported protocol",
		"must be",
		"refused",
		"mutually exclusive",
		"required",
		"invalid",
	}
	for _, token := range badRequestTokens {
		if strings.Contains(msg, token) {
			return true
		}
	}
	return false
}
