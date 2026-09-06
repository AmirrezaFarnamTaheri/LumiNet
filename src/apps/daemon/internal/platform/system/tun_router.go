package system

import (
	"context"
	"errors"
	"fmt"
	"github.com/maybeknott/luminet/internal/platform/mobilehost"
	"io"
	"sync"
	"time"
)

// TunRouterManager owns local TUN resources. Host mutation is intentionally
// private; production callers mutate routing only through ApplyHostNetwork.
type TunRouterManager struct {
	mu            sync.Mutex
	isRunning     bool
	dnsProtected  bool
	deviceName    string
	proxyAddress  string
	mtu           int
	logs          []string
	logMu         sync.RWMutex
	onLog         func(string)
	adapter       io.Closer
	device        io.ReadWriteCloser
	lease         *tunRouteLease
	deviceFactory func(string) (io.ReadWriteCloser, error)
	planRoutes    func(context.Context, string, string) (*tunRouteLease, error)
	applyRoutes   func(context.Context, *tunRouteLease) error
	removeRoutes  func(context.Context, *tunRouteLease) error
	enableDNS     func(context.Context, string) error
	disableDNS    func(context.Context) error
	startAdapter  func(context.Context, io.ReadWriteCloser, string) (io.Closer, error)
}

var globalTunRouterManager *TunRouterManager
var globalTunOnce sync.Once

func newTunRouterManager() *TunRouterManager {
	return &TunRouterManager{
		mtu:           1400,
		deviceFactory: createTunDevice,
		planRoutes:    planTunRouteLease,
		applyRoutes:   applyTunRouteLease,
		removeRoutes:  removeTunRouteLease,
		enableDNS:     EnableDnsLeakProtection,
		disableDNS:    DisableDnsLeakProtection,
		startAdapter: func(ctx context.Context, device io.ReadWriteCloser, socksAddr string) (io.Closer, error) {
			return mobilehost.StartTun2Socks(ctx, device, "10.0.0.2/24", "10.0.0.1", socksAddr)
		},
	}
}

// GetTunRouterManager returns the single status/log owner used by the deep host-network module.
func GetTunRouterManager() *TunRouterManager {
	globalTunOnce.Do(func() { globalTunRouterManager = newTunRouterManager() })
	return globalTunRouterManager
}

// NewTunRouterManager is retained for package tests; mutation methods remain private.
func NewTunRouterManager() *TunRouterManager { return newTunRouterManager() }

func (m *TunRouterManager) startWithLease(ctx context.Context, tunDeviceName, socksAddr string, exact *tunRouteLease) (*tunRouteLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.isRunning {
		return nil, fmt.Errorf("TUN router is already running on device %s", m.deviceName)
	}
	if tunDeviceName == "" {
		return nil, fmt.Errorf("empty TUN device name")
	}
	if socksAddr == "" {
		return nil, fmt.Errorf("empty SOCKS5 proxy address")
	}
	m.clearLogsLocked()

	device, err := m.deviceFactory(tunDeviceName)
	if err != nil {
		return nil, fmt.Errorf("create TUN device %q: %w", tunDeviceName, err)
	}

	lease := exact
	if lease == nil {
		lease, err = m.planRoutes(ctx, tunDeviceName, socksAddr)
		if err != nil {
			_ = device.Close()
			return nil, fmt.Errorf("plan TUN routes: %w", err)
		}
	}
	if err := m.applyRoutes(ctx, lease); err != nil {
		_ = device.Close()
		return nil, fmt.Errorf("apply TUN routes: %w", err)
	}
	if err := m.enableDNS(ctx, tunDeviceName); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = m.disableDNS(cleanupCtx)
		m.dnsProtected = false
		_ = m.removeRoutes(cleanupCtx, lease)
		cancel()
		_ = device.Close()
		return nil, fmt.Errorf("enable DNS leak protection: %w", err)
	}
	m.dnsProtected = true
	adapter, err := m.startAdapter(ctx, device, socksAddr)
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = m.disableDNS(cleanupCtx)
		m.dnsProtected = false
		_ = m.removeRoutes(cleanupCtx, lease)
		cancel()
		_ = device.Close()
		return nil, fmt.Errorf("start userspace TUN adapter: %w", err)
	}

	m.deviceName, m.proxyAddress = tunDeviceName, socksAddr
	m.device, m.adapter, m.lease = device, adapter, cloneTunLease(lease)
	m.isRunning = true
	m.log("TUN routing active: device=%s proxy=%s", tunDeviceName, socksAddr)
	return cloneTunLease(lease), nil
}

// stopWithLease removes only the routes represented by lease. It also works in
// a fresh watchdog process where no local device resources exist.
func (m *TunRouterManager) stopWithLease(ctx context.Context, lease *tunRouteLease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	if m.adapter != nil {
		if err := m.adapter.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close TUN adapter: %w", err))
		}
		m.adapter = nil
	}
	if m.device != nil {
		if err := m.device.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close TUN device: %w", err))
		}
		m.device = nil
	}
	if m.dnsProtected {
		if err := m.disableDNS(ctx); err != nil {
			errs = append(errs, fmt.Errorf("disable DNS leak protection: %w", err))
		} else {
			m.dnsProtected = false
		}
	}
	if lease == nil {
		lease = m.lease
	}
	if lease != nil {
		if err := m.removeRoutes(ctx, lease); err != nil {
			errs = append(errs, fmt.Errorf("remove TUN routes: %w", err))
		}
	}
	if len(errs) != 0 {
		// Preserve visible ownership and the durable lease when host cleanup was incomplete.
		m.isRunning = true
		return errors.Join(errs...)
	}
	m.isRunning = false
	m.deviceName, m.proxyAddress = "", ""
	m.lease = nil
	return nil
}

func cloneTunLease(in *tunRouteLease) *tunRouteLease {
	if in == nil {
		return nil
	}
	out := *in
	out.CreatedProxyIPs = append([]string(nil), in.CreatedProxyIPs...)
	return &out
}

func (m *TunRouterManager) IsRunning() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.isRunning }
func (m *TunRouterManager) GetDeviceDetails() (string, string, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deviceName, m.proxyAddress, m.mtu
}

// DNSProtectionStatus exposes whether DNS leak protection is compiled for this
// platform and whether the active TUN session actually enabled it.
func (m *TunRouterManager) DNSProtectionStatus() (supported, active bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return DNSLeakProtectionSupported(), m.dnsProtected
}
func (m *TunRouterManager) GetLogs() []string {
	m.logMu.RLock()
	defer m.logMu.RUnlock()
	return append([]string(nil), m.logs...)
}
func (m *TunRouterManager) ClearLogs()              { m.logMu.Lock(); m.logs = nil; m.logMu.Unlock() }
func (m *TunRouterManager) clearLogsLocked()        { m.logMu.Lock(); m.logs = nil; m.logMu.Unlock() }
func (m *TunRouterManager) SetOnLog(f func(string)) { m.mu.Lock(); m.onLog = f; m.mu.Unlock() }
func (m *TunRouterManager) log(format string, args ...interface{}) {
	msg := fmt.Sprintf("[%s] ", time.Now().Format("15:04:05")) + fmt.Sprintf(format, args...)
	m.logMu.Lock()
	m.logs = append(m.logs, msg)
	if len(m.logs) > 200 {
		m.logs = m.logs[1:]
	}
	cb := m.onLog
	m.logMu.Unlock()
	if cb != nil {
		cb(msg)
	}
}
