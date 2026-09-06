package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/runtime/runtimecore"
)

// GetEnginesStatus handles GET /api/system/engines — lists the long-lived
// runtime engines owned by runtimecore, including system-tunnel engines.
func (s *Server) GetEnginesStatus(c *gin.Context) {
	manager := runtimecore.DefaultManager()
	tor, _ := manager.Status(runtimecore.EngineTor)
	psiphon, _ := manager.Status(runtimecore.EnginePsiphon)
	sstp, _ := manager.Status(runtimecore.EngineSSTP)
	ikev2, _ := manager.Status(runtimecore.EngineIKEv2)
	torCapability := runtimecore.ProbeEngine(runtimecore.EngineTor)
	psiphonCapability := runtimecore.ProbeEngine(runtimecore.EnginePsiphon)
	sstpCapability := runtimecore.ProbeEngine(runtimecore.EngineSSTP)
	ikev2Capability := runtimecore.ProbeEngine(runtimecore.EngineIKEv2)
	c.JSON(http.StatusOK, gin.H{
		"engines": []gin.H{
			{
				"id": "tor", "name": "Tor Network (Onion Client)",
				"description": "Route SOCKS5 connections through the decentralized Tor network for anonymity and censorship bypass.",
				"running":     tor.Running, "socks_port": tor.SocksPort, "available": torCapability.Available,
				"binary_path": torCapability.BinaryPath, "availability_reason": torCapability.Reason, "mode": torCapability.Mode,
			},
			{
				"id": "psiphon", "name": "Psiphon Client Core",
				"description": "Establish a secure tunnel utilizing Psiphon's network-aware transport protocols to bypass strict DPI censorship.",
				"running":     psiphon.Running, "socks_port": psiphon.SocksPort, "available": psiphonCapability.Available,
				"binary_path": psiphonCapability.BinaryPath, "availability_reason": psiphonCapability.Reason, "mode": psiphonCapability.Mode,
			},
			{
				"id": "sstp", "name": "SSTP System Tunnel",
				"description": "Launch the external sstpc/pppd stack for SSTP VPN profiles on systems where sstpc is installed.",
				"running":     sstp.Running, "socks_port": 0, "mode": sstp.Mode, "available": sstpCapability.Available,
				"binary_path": sstpCapability.BinaryPath, "availability_reason": sstpCapability.Reason,
			},
			{
				"id": "ikev2", "name": "IKEv2 / strongSwan System Tunnel",
				"description": "Launch strongSwan charon-cmd for non-interactive IKEv2 public-key profiles with explicit certificate/private-key paths.",
				"running":     ikev2.Running, "socks_port": 0, "mode": ikev2.Mode, "available": ikev2Capability.Available,
				"binary_path": ikev2Capability.BinaryPath, "availability_reason": ikev2Capability.Reason,
			},
		},
	})
}

// ControlEngine handles POST /api/system/engines — starts/stops Tor or Psiphon.
func (s *Server) ControlEngine(c *gin.Context) {
	var req struct {
		Engine           string   `json:"engine"`
		Action           string   `json:"action"`
		SocksPort        int      `json:"socks_port,omitempty"`
		UpstreamProxy    string   `json:"upstream_proxy,omitempty"`
		Server           string   `json:"server,omitempty"`
		Username         string   `json:"username,omitempty"`
		Password         string   `json:"password,omitempty"`
		CACert           string   `json:"ca_cert,omitempty"`
		AllowCertWarning bool     `json:"allow_cert_warning,omitempty"`
		PPPOptions       []string `json:"ppp_options,omitempty"`
		Identity         string   `json:"identity,omitempty"`
		RemoteIdentity   string   `json:"remote_identity,omitempty"`
		Certificate      string   `json:"certificate,omitempty"`
		PrivateKey       string   `json:"private_key,omitempty"`
		LocalTS          string   `json:"local_ts,omitempty"`
		RemoteTS         string   `json:"remote_ts,omitempty"`
		IKEProposals     []string `json:"ike_proposals,omitempty"`
		ESPProposals     []string `json:"esp_proposals,omitempty"`
		Bridges          []string `json:"bridges,omitempty"`
		TransportPlugins []struct {
			Name       string   `json:"name"`
			Executable string   `json:"executable"`
			Args       []string `json:"args,omitempty"`
		} `json:"transport_plugins,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	manager := runtimecore.DefaultManager()
	kind := runtimecore.Engine(req.Engine)
	switch req.Action {
	case "stop":
		before, err := manager.Status(kind)
		if err != nil {
			writeRuntimeCoreError(c, err)
			return
		}
		if _, err := manager.Stop(kind); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		status := "stopped"
		if !before.Running {
			status = "already_stopped"
		}
		c.JSON(http.StatusOK, gin.H{"status": status, "engine": req.Engine})
	case "start":
		plugins := make([]runtimecore.TorTransportPlugin, len(req.TransportPlugins))
		for i, plugin := range req.TransportPlugins {
			plugins[i] = runtimecore.TorTransportPlugin{Name: plugin.Name, Executable: plugin.Executable, Args: append([]string(nil), plugin.Args...)}
		}
		status, err := manager.Start(runtimecore.Request{
			Engine: kind, SocksPort: req.SocksPort, UpstreamProxy: req.UpstreamProxy,
			Server: req.Server, Username: req.Username, Password: req.Password, CACert: req.CACert,
			AllowCertWarning: req.AllowCertWarning, PPPOptions: req.PPPOptions,
			Identity: req.Identity, RemoteIdentity: req.RemoteIdentity,
			Certificate: req.Certificate, PrivateKey: req.PrivateKey,
			LocalTS: req.LocalTS, RemoteTS: req.RemoteTS,
			IKEProposals: req.IKEProposals, ESPProposals: req.ESPProposals,
			Bridges: req.Bridges, TransportPlugins: plugins,
		})
		if err != nil {
			writeRuntimeCoreError(c, fmt.Errorf("failed to start engine: %w", err))
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "started", "engine": req.Engine, "socks_port": status.SocksPort, "mode": status.Mode})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid action: %s", req.Action)})
	}
}

func writeRuntimeCoreError(c *gin.Context, err error) {
	if errors.Is(err, runtimecore.ErrInvalidRequest) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}

// RotateTorIdentity handles POST /api/system/engines/tor/identity. It requests
// a fresh Tor circuit identity without restarting the Tor process.
func (s *Server) RotateTorIdentity(c *gin.Context) {
	if err := runtimecore.DefaultManager().RotateTorIdentity(); err != nil {
		writeRuntimeCoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "rotation_requested",
		"engine": "tor",
		"note":   "Tor controls NEWNYM rate limiting; existing streams may keep their current circuits",
	})
}
