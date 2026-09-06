// Package mobilecore owns the mobile VPN/core lifecycle while keeping the
// gobind package a transport adapter and proxy as the evasion runtime owner.
package mobilecore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/maybeknott/luminet/internal/platform/mobilehost"
	"log"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/maybeknott/luminet/internal/foundation/trafficstats"
	"github.com/maybeknott/luminet/internal/runtime/proxy"
)

const (
	coreAsset   = "v2ray.location.asset"
	coreCert    = "v2ray.location.cert"
	xudpBaseKey = "v2ray.xudp.basekey"
)

// CoreCallbackHandler receives mobile lifecycle/status callbacks.
type CoreCallbackHandler interface {
	Startup() int
	Shutdown() int
	OnEmitStatus(int, string) int
}

// CoreController owns one mobile evasion + TUN lifecycle.
type CoreController struct {
	CallbackHandler CoreCallbackHandler
	mu              sync.Mutex
	isRunning       bool
	tunFile         *os.File
	tunAdapter      *mobilehost.Tun2SocksAdapter
	lastConfig      MobileConfig
}

// NewCoreController initializes a mobile runtime controller.
func NewCoreController(callback CoreCallbackHandler) *CoreController {
	return &CoreController{CallbackHandler: callback}
}

func setEnvVariable(key, value string) {
	if err := os.Setenv(key, value); err != nil {
		log.Printf("Failed to set environment variable %s: %v", key, err)
	}
}

// InitCoreEnv configures mobile asset filesystem locations.
func InitCoreEnv(envPath, key string) {
	if envPath != "" {
		setEnvVariable(coreAsset, envPath)
		setEnvVariable(coreCert, envPath)
	}
	if key != "" {
		setEnvVariable(xudpBaseKey, key)
	}
}

// StartLoop starts the shared evasion runtime and transfers tunFd ownership to Go.
func (c *CoreController) StartLoop(configContent string, tunFd int32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var ownedTun *os.File
	if tunFd >= 0 {
		ownedTun = os.NewFile(uintptr(tunFd), "/dev/tun")
		if ownedTun == nil {
			return fmt.Errorf("take ownership of TUN fd %d", tunFd)
		}
	}

	if c.isRunning {
		if ownedTun != nil {
			_ = ownedTun.Close()
		}
		return errors.New("core is already running")
	}

	config := DefaultConfig()
	if configContent != "" {
		if err := json.Unmarshal([]byte(configContent), &config); err != nil {
			log.Printf("Direct MobileConfig unmarshal failed, trying Xray outbound extraction: %v", err)
			parseXrayOutbound(configContent, &config)
		}
	}

	manager := proxy.GetEvasionManager()
	manager.SetOnLog(func(msg string) {
		if c.CallbackHandler != nil {
			c.CallbackHandler.OnEmitStatus(1, msg)
		}
	})

	evConfig := ConfigToEvasion(config)
	if err := manager.Start(&evConfig); err != nil {
		if ownedTun != nil {
			_ = ownedTun.Close()
		}
		return err
	}

	var tunAdapter *mobilehost.Tun2SocksAdapter
	if ownedTun != nil {
		socksAddr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", config.Port))
		dnsForwarderAddr := ""
		if config.DnsForwarderEnabled {
			dnsForwarderAddr = net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", config.DnsForwarderPort))
		}
		adapter, err := mobilehost.StartTun2SocksWithDNS(
			context.Background(),
			ownedTun,
			"10.88.0.2/30",
			"10.88.0.1",
			socksAddr,
			dnsForwarderAddr,
		)
		if err != nil {
			_ = ownedTun.Close()
			manager.Stop()
			return fmt.Errorf("start mobile TUN adapter: %w", err)
		}
		tunAdapter = adapter
	}

	c.tunFile = ownedTun
	c.tunAdapter = tunAdapter
	c.lastConfig = config
	c.isRunning = true

	if c.CallbackHandler != nil {
		c.CallbackHandler.Startup()
		c.CallbackHandler.OnEmitStatus(0, "LumiNet Evasion Tunnel running successfully")
	}
	return nil
}

// StopLoop stops the shared evasion runtime and releases TUN resources.
func (c *CoreController) StopLoop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.isRunning {
		return nil
	}

	proxy.GetEvasionManager().Stop()
	if c.tunAdapter != nil {
		_ = c.tunAdapter.Close()
		c.tunAdapter = nil
		c.tunFile = nil // adapter owns device
	} else if c.tunFile != nil {
		_ = c.tunFile.Close()
		c.tunFile = nil
	}
	c.isRunning = false

	if c.CallbackHandler != nil {
		c.CallbackHandler.Shutdown()
		c.CallbackHandler.OnEmitStatus(0, "LumiNet Evasion Tunnel stopped")
	}
	return nil
}

// QueryStats returns evasion traffic statistics for the requested direction.
func (c *CoreController) QueryStats(tag, direction string) int64 {
	switch direction {
	case "upload":
		up, _ := trafficstats.GetEvasionTrafficStats()
		return int64(up)
	case "download":
		_, down := trafficstats.GetEvasionTrafficStats()
		return int64(down)
	case "total":
		up, down := trafficstats.GetEvasionTrafficStats()
		return int64(up + down)
	}
	return 0
}

// QueryAllOutboundTrafficStats returns all evasion counters as JSON.
func (c *CoreController) QueryAllOutboundTrafficStats() string {
	up, down := trafficstats.GetEvasionTrafficStats()
	data, _ := json.Marshal(map[string]uint64{"upload": up, "download": down, "total": up + down})
	return string(data)
}

// GetLocationSpoofConfig returns the last mobile location/sensor configuration as JSON.
func (c *CoreController) GetLocationSpoofConfig() string {
	c.mu.Lock()
	cfg := c.lastConfig
	c.mu.Unlock()
	data, _ := json.Marshal(map[string]interface{}{
		"fake_location_enabled":   cfg.FakeLocationEnabled,
		"fake_location_latitude":  cfg.FakeLocationLatitude,
		"fake_location_longitude": cfg.FakeLocationLongitude,
		"fake_location_altitude":  cfg.FakeLocationAltitude,
		"fake_location_accuracy":  cfg.FakeLocationAccuracy,
		"fake_location_speed":     cfg.FakeLocationSpeed,
		"fake_cell_tower_spoof":   cfg.FakeCellTowerSpoof,
		"fake_wifi_spoof":         cfg.FakeWifiSpoof,
	})
	return string(data)
}

// CheckVersionX returns the native binding version tag.
func CheckVersionX() string { return "LumiNet Core v1.0.0" }

func parseXrayOutbound(configJSON string, config *MobileConfig) {
	var raw struct {
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				Vnext []struct {
					Address string `json:"address"`
					Port    int    `json:"port"`
					Users   []struct {
						ID string `json:"id"`
					} `json:"users"`
				} `json:"vnext"`
				Servers []struct {
					Address  string `json:"address"`
					Port     int    `json:"port"`
					Password string `json:"password"`
				} `json:"servers"`
			} `json:"settings"`
		} `json:"outbounds"`
	}

	if err := json.Unmarshal([]byte(configJSON), &raw); err != nil || len(raw.Outbounds) == 0 {
		return
	}
	outbound := raw.Outbounds[0]
	config.RemoteProtocol = outbound.Protocol
	if len(outbound.Settings.Vnext) > 0 {
		config.RemoteAddress = outbound.Settings.Vnext[0].Address
		config.RemotePort = outbound.Settings.Vnext[0].Port
		if len(outbound.Settings.Vnext[0].Users) > 0 {
			config.RemoteUUID = outbound.Settings.Vnext[0].Users[0].ID
		}
	} else if len(outbound.Settings.Servers) > 0 {
		config.RemoteAddress = outbound.Settings.Servers[0].Address
		config.RemotePort = outbound.Settings.Servers[0].Port
		config.RemotePassword = outbound.Settings.Servers[0].Password
	}
}

// ResolveDNS exposes the runtime resolver to mobile bindings.
func ResolveDNS(host string) string { return proxy.ResolveDNS(host) }

// OptimizeMemoryForMobile reduces the Go runtime's default memory targets.
func OptimizeMemoryForMobile() {
	debug.SetGCPercent(50)
	debug.SetMemoryLimit(64 * 1024 * 1024)
}

// TriggerGC aggressively returns heap pages to the mobile host.
func TriggerGC() {
	runtime.GC()
	debug.FreeOSMemory()
}

// Status returns the redacted mobile configuration and runtime state.
func Status() (MobileConfig, bool) {
	manager := proxy.GetEvasionManager()
	return ConfigFromEvasion(manager.GetRedactedConfig()), manager.IsRunning()
}

// IsRunning reports whether the shared evasion runtime is active.
func IsRunning() bool { return proxy.GetEvasionManager().IsRunning() }
