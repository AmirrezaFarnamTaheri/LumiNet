package system

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// RoutingMode defines the routing modes for the coordinator.
type RoutingMode string

const (
	ModeDirect RoutingMode = "direct"
	ModeProxy  RoutingMode = "proxy"
	ModeTun    RoutingMode = "tun"
)

// SystemRouteCoordinator manages the active connection routing mode atomic transitions.
type SystemRouteCoordinator struct {
	mu         sync.Mutex
	activeMode RoutingMode
}

var globalRouteCoordinator *SystemRouteCoordinator
var globalCoordOnce sync.Once

// GetRouteCoordinator returns the global singleton instance.
func GetRouteCoordinator() *SystemRouteCoordinator {
	globalCoordOnce.Do(func() {
		globalRouteCoordinator = &SystemRouteCoordinator{
			activeMode: ModeDirect,
		}
		
		// Synchronize state with current managers
		mgr := GetTunRouterManager()
		if mgr.IsRunning() {
			globalRouteCoordinator.activeMode = ModeTun
		} else {
			settings, err := GetSystemProxy(context.Background())
			if err == nil && settings.Enabled {
				globalRouteCoordinator.activeMode = ModeProxy
			}
		}
	})
	return globalRouteCoordinator
}

// GetActiveMode returns the current routing mode.
func (c *SystemRouteCoordinator) GetActiveMode() RoutingMode {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activeMode
}

// TransitionToMode coordinates transitioning atomically between routing modes.
// If transitioning to TUN fails, it falls back to proxying to maintain connectivity.
func (c *SystemRouteCoordinator) TransitionToMode(ctx context.Context, targetMode RoutingMode, options ProxySettings, tunDeviceName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	slog.Info("SystemRouteCoordinator: transitioning", "from", c.activeMode, "to", targetMode)

	switch targetMode {
	case ModeTun:
		// 1. Disable WinINet system registry proxy first
		slog.Info("SystemRouteCoordinator: disabling WinINet proxy before TUN")
		if err := DisableSystemProxy(ctx); err != nil {
			return fmt.Errorf("failed to clear system proxy prior to TUN transition: %w", err)
		}

		// 2. Start Wintun adapter
		slog.Info("SystemRouteCoordinator: launching TUN", "device", tunDeviceName, "bind", options.Server)
		mgr := GetTunRouterManager()
		if err := mgr.BindTunToProxy(ctx, tunDeviceName, options.Server); err != nil {
			slog.Warn("SystemRouteCoordinator: Wintun init failed", "err", err)
			slog.Warn("SystemRouteCoordinator: falling back to WinINet SOCKS5")
			
			// Fallback: Re-enable registry proxy
			fallbackSettings := ProxySettings{
				Enabled: true,
				Server:  options.Server,
				Bypass:  options.Bypass,
			}
			if fbErr := SetSystemProxy(ctx, &fallbackSettings); fbErr != nil {
				slog.Error("SystemRouteCoordinator: fallback also failed", "err", fbErr)
			}
			
			c.activeMode = ModeProxy
			return fmt.Errorf("TUN transition failed, fell back to Proxy mode: %w", err)
		}

		c.activeMode = ModeTun

	case ModeProxy:
		// 1. Stop Wintun adapter if running
		slog.Info("SystemRouteCoordinator: stopping Wintun adapter")
		GetTunRouterManager().Stop()

		// 2. Enable WinINet system registry proxy
		slog.Info("SystemRouteCoordinator: enabling WinINet SOCKS5", "server", options.Server)
		if err := SetSystemProxy(ctx, &options); err != nil {
			return fmt.Errorf("failed to set system proxy: %w", err)
		}

		c.activeMode = ModeProxy

	case ModeDirect:
		// 1. Stop Wintun adapter
		slog.Info("SystemRouteCoordinator: stopping Wintun adapter")
		GetTunRouterManager().Stop()

		// 2. Disable system proxy
		slog.Info("SystemRouteCoordinator: disabling WinINet proxy")
		if err := DisableSystemProxy(ctx); err != nil {
			return fmt.Errorf("failed to disable system proxy: %w", err)
		}

		c.activeMode = ModeDirect

	default:
		return fmt.Errorf("unknown routing mode: %s", targetMode)
	}

	slog.Info("SystemRouteCoordinator: transition complete", "mode", targetMode)
	return nil
}

