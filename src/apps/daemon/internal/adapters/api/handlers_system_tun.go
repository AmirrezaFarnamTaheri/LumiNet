package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/maybeknott/luminet/internal/platform/system"
)

type TunRouterStatusResponse struct {
	Supported                  bool   `json:"supported"`
	Running                    bool   `json:"running"`
	DeviceName                 string `json:"device_name"`
	ProxyAddr                  string `json:"proxy_addr"`
	MTU                        int    `json:"mtu"`
	DNSLeakProtectionSupported bool   `json:"dns_leak_protection_supported"`
	DNSLeakProtectionActive    bool   `json:"dns_leak_protection_active"`
}

type SetTunRouterRequest struct {
	Enabled    bool   `json:"enabled"`
	DeviceName string `json:"device_name"`
	ProxyAddr  string `json:"proxy_addr"`
}

// GetTunRouterStatus handles GET /api/system/tun-router
func (s *Server) GetTunRouterStatus(c *gin.Context) {
	mgr := system.GetTunRouterManager()
	running := mgr.IsRunning()
	dev, proxy, mtu := mgr.GetDeviceDetails()

	dnsSupported, dnsActive := mgr.DNSProtectionStatus()
	c.JSON(http.StatusOK, TunRouterStatusResponse{
		Supported:                  system.TunRoutingSupported(),
		Running:                    running,
		DeviceName:                 dev,
		ProxyAddr:                  proxy,
		MTU:                        mtu,
		DNSLeakProtectionSupported: dnsSupported,
		DNSLeakProtectionActive:    dnsActive,
	})
}

// SetTunRouter handles POST /api/system/tun-router
func (s *Server) SetTunRouter(c *gin.Context) {
	var req SetTunRouterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mgr := system.GetTunRouterManager()
	// Setup WebSocket log forwarder on demand
	mgr.SetOnLog(func(msg string) {
		s.hub.BroadcastSystemEvent("evasion_log", msg)
	})

	if req.Enabled {
		if req.DeviceName == "" {
			req.DeviceName = "wintun0"
		}
		if req.ProxyAddr == "" {
			req.ProxyAddr = "127.0.0.1:10888" // default SOCKS5 evasion port
		}

		err := system.ApplyHostNetwork(c.Request.Context(), system.HostNetworkChange{
			Kind:      system.HostNetworkChangeRoute,
			RouteMode: system.HostRouteTun,
			TunDevice: req.DeviceName,
			TunProxy:  req.ProxyAddr,
		})
		if err != nil {
			writePlatformFeatureError(c, err)
			return
		}
	} else {
		err := system.ApplyHostNetwork(c.Request.Context(), system.HostNetworkChange{
			Kind:      system.HostNetworkChangeRoute,
			RouteMode: system.HostRouteDirect,
		})
		if err != nil {
			writePlatformFeatureError(c, err)
			return
		}
	}

	dev, proxy, mtu := mgr.GetDeviceDetails()
	dnsSupported, dnsActive := mgr.DNSProtectionStatus()
	c.JSON(http.StatusOK, gin.H{
		"status":                        "applied",
		"supported":                     system.TunRoutingSupported(),
		"enabled":                       mgr.IsRunning(),
		"device_name":                   dev,
		"proxy_addr":                    proxy,
		"mtu":                           mtu,
		"dns_leak_protection_supported": dnsSupported,
		"dns_leak_protection_active":    dnsActive,
	})
}
