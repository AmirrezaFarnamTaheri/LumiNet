package api

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/analysis/diagnostics"
	dnsresolver "github.com/maybeknott/luminet/internal/networking/dns"
	"github.com/maybeknott/luminet/internal/runtime/runtimecore"
)

type onionProbeRequest struct {
	URL          string   `json:"url" binding:"required"`
	SOCKSProxies []string `json:"socks_proxies,omitempty"`
	TimeoutSecs  int      `json:"timeout_secs,omitempty"`
}

// ProbeOnionService runs a bounded HTTP reachability probe through a stable
// SOCKS5 endpoint. When no proxy list is supplied it uses the active Tor
// engine's local SOCKS port.
func (s *Server) ProbeOnionService(c *gin.Context) {
	var req onionProbeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.SOCKSProxies) > 16 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "too many SOCKS proxies: max 16"})
		return
	}
	if len(req.SOCKSProxies) == 0 {
		status, err := runtimecore.DefaultManager().Status(runtimecore.EngineTor)
		if err != nil || !status.Running {
			c.JSON(http.StatusConflict, gin.H{"error": "TOR_NOT_RUNNING", "message": "start the Tor runtime engine or provide an explicit SOCKS proxy"})
			return
		}
		req.SOCKSProxies = []string{formatLoopbackPort(status.SocksPort)}
	}
	timeout := time.Duration(req.TimeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), timeout+2*time.Second)
	defer cancel()
	result, err := diagnostics.ProbeOnion(ctx, req.URL, req.SOCKSProxies, timeout)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "ONION_PROBE_FAILED", "message": err.Error(), "result": result})
		return
	}
	c.JSON(http.StatusOK, result)
}

type torExitCheckRequest struct {
	IP     string `json:"ip" binding:"required"`
	ViaTor bool   `json:"via_tor,omitempty"`
}

type encryptedDNSELResolver struct {
	resolver *dnsresolver.Resolver
}

func (r encryptedDNSELResolver) LookupHost(ctx context.Context, name string) ([]string, error) {
	ips, err := r.resolver.LookupEncryptedA(ctx, name)
	if err != nil {
		return nil, err
	}
	answers := make([]string, 0, len(ips))
	for _, ip := range ips {
		if parsed := net.ParseIP(ip.String()); parsed != nil {
			answers = append(answers, parsed.String())
		}
	}
	return answers, nil
}

// CheckTorExitNode exposes a bounded read-only Tor DNSEL diagnostic. Resolver
// outages remain an explicit unknown state rather than a false non-exit result.
func (s *Server) CheckTorExitNode(c *gin.Context) {
	var req torExitCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 4*time.Second)
	defer cancel()
	resolver := dnsresolver.NewResolver("", "")
	if req.ViaTor {
		status, statusErr := runtimecore.DefaultManager().Status(runtimecore.EngineTor)
		if statusErr != nil || !status.Running {
			c.JSON(http.StatusConflict, gin.H{"error": "TOR_NOT_RUNNING", "message": "start the Tor runtime engine or set via_tor=false"})
			return
		}
		resolver.ProxyURL = "socks5://" + formatLoopbackPort(status.SocksPort)
	}
	result, err := diagnostics.CheckTorExit(ctx, req.IP, encryptedDNSELResolver{resolver: resolver})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOR_DNSEL_INVALID_INPUT", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func formatLoopbackPort(port int) string { return "127.0.0.1:" + strconv.Itoa(port) }

type torBridgeProbeRequest struct {
	Bridges   []string `json:"bridges" binding:"required"`
	Workers   int      `json:"workers,omitempty"`
	TimeoutMs int      `json:"timeout_ms,omitempty"`
}

// ProbeTorBridges exposes a bounded, read-only bridge reachability diagnostic.
// Remote bridge material can select only public destinations; fronted
// transports are checked through their declared public front/broker rather
// than documentation-placeholder bridge addresses.
func (s *Server) ProbeTorBridges(c *gin.Context) {
	var req torBridgeProbeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Bridges) == 0 || len(req.Bridges) > diagnostics.MaxTorBridgeProbeLines {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bridges must contain between 1 and 64 entries"})
		return
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	// Overall request lifetime remains bounded independently of the per-probe
	// timeout and requested worker count.
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()
	results, err := diagnostics.ProbeTorBridges(ctx, req.Bridges, req.Workers, timeout)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "TOR_BRIDGE_PROBE_INVALID", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": results, "count": len(results)})
}
