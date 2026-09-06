package system

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"time"
)

type HostNetworkChangeKind string
type HostRouteMode string

const (
	HostNetworkChangeDNS   HostNetworkChangeKind = "dns"
	HostNetworkChangeNCSI  HostNetworkChangeKind = "ncsi"
	HostNetworkChangeRoute HostNetworkChangeKind = "route"

	HostRouteDirect HostRouteMode = "direct"
	HostRouteProxy  HostRouteMode = "proxy"
	HostRouteTun    HostRouteMode = "tun"

	hostNetworkStateVersion = 1
)

type HostNetworkChange struct {
	Kind         HostNetworkChangeKind `json:"kind"`
	DNSInterface string                `json:"dns_interface,omitempty"`
	DNSServers   []string              `json:"dns_servers,omitempty"`
	NCSI         *NCSIConfig           `json:"ncsi,omitempty"`
	RouteMode    HostRouteMode         `json:"route_mode,omitempty"`
	Proxy        ProxySettings         `json:"proxy,omitempty"`
	TunDevice    string                `json:"tun_device,omitempty"`
	TunProxy     string                `json:"tun_proxy,omitempty"`
}

// HostNetworkPlan is a read-only preview of a host-network mutation. It is
// advisory evidence only: callers must invoke ApplyHostNetwork separately,
// and the state is revalidated by the authoritative mutation owner at apply
// time.
type HostNetworkPlan struct {
	Current          HostNetworkChange `json:"current"`
	Requested        HostNetworkChange `json:"requested"`
	ChangesState     bool              `json:"changes_state"`
	RollbackOwned    bool              `json:"rollback_owned"`
	CrashRecoverable bool              `json:"crash_recoverable"`
	ApplyAuthorized  bool              `json:"apply_authorized"`
	Warnings         []string          `json:"warnings,omitempty"`
}

type tunRouteLease struct {
	DeviceName      string   `json:"device_name"`
	ProxyAddress    string   `json:"proxy_address"`
	Gateway         string   `json:"gateway,omitempty"`
	CreatedProxyIPs []string `json:"created_proxy_ips,omitempty"`
	DefaultRoute    bool     `json:"default_route,omitempty"`
}

type hostSnapshot struct {
	Proxy        *ProxySettings `json:"proxy,omitempty"`
	DNSInterface string         `json:"dns_interface,omitempty"`
	DNSServers   []string       `json:"dns_servers,omitempty"`
	NCSI         *NCSIConfig    `json:"ncsi,omitempty"`
}

type hostOperationRecord struct {
	Version  int               `json:"version"`
	Snapshot hostSnapshot      `json:"snapshot"`
	Change   HostNetworkChange `json:"change"`
}

type hostSessionRecord struct {
	Version  int               `json:"version"`
	Snapshot hostSnapshot      `json:"snapshot"`
	Active   HostNetworkChange `json:"active"`
	Lease    *tunRouteLease    `json:"lease,omitempty"`
}

type hostNetworkOps struct {
	getProxy func(context.Context) (*ProxySettings, error)
	setProxy func(context.Context, *ProxySettings) error
	getDNS   func(context.Context, string) ([]string, error)
	setDNS   func(context.Context, string, []string) error
	getNCSI  func() (*NCSIConfig, error)
	setNCSI  func(context.Context, *NCSIConfig) error
	startTun func(context.Context, string, string, *tunRouteLease) (*tunRouteLease, error)
	stopTun  func(context.Context, *tunRouteLease) error
	tunUp    func() bool
}

type hostNetworkManager struct {
	dir string
	ops hostNetworkOps
}

func defaultHostNetworkStateDir() string {
	if dir := os.Getenv("LUMINET_DATA_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".luminet"
	}
	return filepath.Join(home, ".luminet")
}

func newHostNetworkManager(dir string, ops hostNetworkOps) *hostNetworkManager {
	return &hostNetworkManager{dir: dir, ops: ops}
}

// ApplyHostNetwork is the only production mutation interface for host DNS,
// NCSI, system proxy, and daemon-owned TUN routing state.
func ApplyHostNetwork(ctx context.Context, change HostNetworkChange) error {
	return newHostNetworkManager(defaultHostNetworkStateDir(), nativeHostNetworkOps()).Apply(ctx, change)
}

// ReleaseHostNetworkRoute restores the exact pre-LumiNet route snapshot only
// when expected still identifies the daemon-owned active route. It is the
// clean-shutdown counterpart to crash recovery and never converts a session to
// a synthetic "direct" route.
func ReleaseHostNetworkRoute(ctx context.Context, expected HostNetworkChange) error {
	return newHostNetworkManager(defaultHostNetworkStateDir(), nativeHostNetworkOps()).ReleaseRoute(ctx, expected)
}

// PlanHostNetwork previews the current and requested host-network state without
// acquiring mutation authority, creating recovery files, or changing the host.
func PlanHostNetwork(ctx context.Context, change HostNetworkChange) (HostNetworkPlan, error) {
	return newHostNetworkManager(defaultHostNetworkStateDir(), nativeHostNetworkOps()).Plan(ctx, change)
}

// RecoverHostNetwork restores any interrupted persistent mutation and then the
// original pre-daemon routing state, using the exact durable TUN lease.
func RecoverHostNetwork(ctx context.Context) error {
	return RecoverHostNetworkInDir(ctx, defaultHostNetworkStateDir())
}

func RecoverHostNetworkInDir(ctx context.Context, dir string) error {
	return newHostNetworkManager(dir, nativeHostNetworkOps()).Recover(ctx)
}

func (m *hostNetworkManager) operationPath() string {
	return filepath.Join(m.dir, "host-network-operation.json")
}
func (m *hostNetworkManager) sessionPath() string {
	return filepath.Join(m.dir, "host-network-session.json")
}

func (m *hostNetworkManager) Plan(ctx context.Context, change HostNetworkChange) (HostNetworkPlan, error) {
	if err := validateHostNetworkChange(change); err != nil {
		return HostNetworkPlan{}, err
	}
	current, warnings, err := m.currentStateForPlan(ctx, change)
	if err != nil {
		return HostNetworkPlan{}, err
	}
	return HostNetworkPlan{
		Current:          current,
		Requested:        cloneHostNetworkChange(change),
		ChangesState:     !hostNetworkChangeEqual(current, change),
		RollbackOwned:    true,
		CrashRecoverable: true,
		ApplyAuthorized:  false,
		Warnings:         warnings,
	}, nil
}

func (m *hostNetworkManager) currentStateForPlan(ctx context.Context, requested HostNetworkChange) (HostNetworkChange, []string, error) {
	switch requested.Kind {
	case HostNetworkChangeDNS:
		servers, err := m.ops.getDNS(ctx, requested.DNSInterface)
		if err != nil {
			return HostNetworkChange{}, nil, fmt.Errorf("read current DNS for preview: %w", err)
		}
		return HostNetworkChange{Kind: HostNetworkChangeDNS, DNSInterface: requested.DNSInterface, DNSServers: append([]string(nil), servers...)}, nil, nil
	case HostNetworkChangeNCSI:
		ncsi, err := m.ops.getNCSI()
		if err != nil {
			return HostNetworkChange{}, nil, fmt.Errorf("read current NCSI for preview: %w", err)
		}
		return HostNetworkChange{Kind: HostNetworkChangeNCSI, NCSI: cloneNCSIConfig(ncsi)}, nil, nil
	case HostNetworkChangeRoute:
		var session hostSessionRecord
		if ok, err := readHostRecord(m.sessionPath(), &session); err != nil {
			return HostNetworkChange{}, nil, fmt.Errorf("read current route session for preview: %w", err)
		} else if ok {
			return cloneHostNetworkChange(session.Active), []string{"preview reflects the daemon-owned route session; apply revalidates live host state"}, nil
		}
		proxy, err := m.ops.getProxy(ctx)
		if err != nil {
			return HostNetworkChange{}, nil, fmt.Errorf("read current proxy for preview: %w", err)
		}
		current := HostNetworkChange{Kind: HostNetworkChangeRoute, RouteMode: HostRouteDirect}
		if proxy.Enabled {
			current.RouteMode = HostRouteProxy
			current.Proxy = *proxy
		}
		return current, []string{"preview is advisory; host state can change before apply"}, nil
	default:
		return HostNetworkChange{}, nil, fmt.Errorf("unknown host-network change kind %q", requested.Kind)
	}
}

func hostNetworkChangeEqual(a, b HostNetworkChange) bool {
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case HostNetworkChangeDNS:
		return a.DNSInterface == b.DNSInterface && slices.Equal(a.DNSServers, b.DNSServers)
	case HostNetworkChangeNCSI:
		return reflect.DeepEqual(a.NCSI, b.NCSI)
	case HostNetworkChangeRoute:
		if a.RouteMode != b.RouteMode {
			return false
		}
		switch a.RouteMode {
		case HostRouteDirect:
			return true
		case HostRouteProxy:
			return proxySettingsEqual(a.Proxy, b.Proxy)
		case HostRouteTun:
			return a.TunDevice == b.TunDevice && a.TunProxy == b.TunProxy
		}
	}
	return false
}

func proxySettingsEqual(a, b ProxySettings) bool {
	aServer, bServer := a.Server, b.Server
	if aServer == "" {
		aServer = a.HTTPServer
	}
	if bServer == "" {
		bServer = b.HTTPServer
	}
	aBypass, bBypass := a.Bypass, b.Bypass
	if aBypass == "" {
		aBypass = a.BypassList
	}
	if bBypass == "" {
		bBypass = b.BypassList
	}
	return a.Enabled == b.Enabled && aServer == bServer && aBypass == bBypass && a.PACURL == b.PACURL
}

func cloneHostNetworkChange(change HostNetworkChange) HostNetworkChange {
	out := change
	out.DNSServers = append([]string(nil), change.DNSServers...)
	out.NCSI = cloneNCSIConfig(change.NCSI)
	return out
}

func cloneNCSIConfig(config *NCSIConfig) *NCSIConfig {
	if config == nil {
		return nil
	}
	out := *config
	return &out
}

func (m *hostNetworkManager) Apply(ctx context.Context, change HostNetworkChange) error {
	if err := validateHostNetworkChange(change); err != nil {
		return err
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return fmt.Errorf("create host-network state directory: %w", err)
	}
	lock, err := acquireHostNetworkLock(m.dir)
	if err != nil {
		return err
	}
	defer lock.Release()

	if err := m.recoverOperationLocked(); err != nil {
		return fmt.Errorf("recover interrupted host-network operation: %w", err)
	}
	if change.Kind == HostNetworkChangeRoute {
		return m.applyRouteLocked(ctx, change)
	}
	return m.applyPersistentLocked(ctx, change)
}

func (m *hostNetworkManager) ReleaseRoute(_ context.Context, expected HostNetworkChange) error {
	if expected.Kind != HostNetworkChangeRoute {
		return errors.New("route release requires a route ownership value")
	}
	if err := validateHostNetworkChange(expected); err != nil {
		return err
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return fmt.Errorf("create host-network state directory: %w", err)
	}
	lock, err := acquireHostNetworkLock(m.dir)
	if err != nil {
		return err
	}
	defer lock.Release()
	if err := m.recoverOperationLocked(); err != nil {
		return fmt.Errorf("recover interrupted host-network operation before release: %w", err)
	}

	var rec hostSessionRecord
	ok, err := readHostRecord(m.sessionPath(), &rec)
	if err != nil || !ok {
		return err
	}
	if !hostNetworkChangeEqual(rec.Active, expected) {
		return fmt.Errorf("host-network route ownership mismatch: active route changed since caller acquired ownership")
	}

	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Revalidate the live state as well as the durable owner. This catches a
	// partial external takeover such as a bypass/PAC-only proxy edit.
	if err := m.verifyRoute(cleanupCtx, rec.Active); err != nil {
		return fmt.Errorf("host-network live route no longer matches owned route: %w", err)
	}
	if rec.Active.RouteMode == HostRouteTun && rec.Lease != nil {
		if err := m.ops.stopTun(cleanupCtx, rec.Lease); err != nil {
			return fmt.Errorf("stop owned TUN route: %w", err)
		}
	}
	if rec.Snapshot.Proxy == nil {
		return errors.New("host-network session is missing original proxy snapshot")
	}
	if err := m.ops.setProxy(cleanupCtx, rec.Snapshot.Proxy); err != nil {
		return fmt.Errorf("restore original proxy: %w", err)
	}
	if err := m.verifyProxy(cleanupCtx, rec.Snapshot.Proxy); err != nil {
		return fmt.Errorf("verify original proxy restore: %w", err)
	}
	if err := removeHostRecord(m.sessionPath()); err != nil {
		return fmt.Errorf("remove released host-network session: %w", err)
	}
	return nil
}

func (m *hostNetworkManager) Recover(ctx context.Context) error {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return fmt.Errorf("create host-network state directory: %w", err)
	}
	lock, err := acquireHostNetworkLock(m.dir)
	if err != nil {
		return err
	}
	defer lock.Release()

	if err := m.recoverOperationLocked(); err != nil {
		return err
	}
	var rec hostSessionRecord
	ok, err := readHostRecord(m.sessionPath(), &rec)
	if err != nil || !ok {
		return err
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if rec.Active.RouteMode == HostRouteTun && rec.Lease != nil {
		if err := m.ops.stopTun(cleanupCtx, rec.Lease); err != nil {
			return fmt.Errorf("stop active TUN during recovery: %w", err)
		}
	}
	if rec.Snapshot.Proxy != nil {
		if err := m.ops.setProxy(cleanupCtx, rec.Snapshot.Proxy); err != nil {
			return fmt.Errorf("restore original proxy: %w", err)
		}
		if err := m.verifyProxy(cleanupCtx, rec.Snapshot.Proxy); err != nil {
			return fmt.Errorf("verify original proxy restore: %w", err)
		}
	}
	if err := os.Remove(m.sessionPath()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func validateHostNetworkChange(change HostNetworkChange) error {
	switch change.Kind {
	case HostNetworkChangeDNS:
		if change.DNSInterface == "" {
			return errors.New("DNS interface is required")
		}
	case HostNetworkChangeNCSI:
		if change.NCSI == nil {
			return errors.New("NCSI configuration is required")
		}
	case HostNetworkChangeRoute:
		switch change.RouteMode {
		case HostRouteDirect:
		case HostRouteProxy:
			if !change.Proxy.Enabled || (change.Proxy.Server == "" && change.Proxy.PACURL == "") {
				return errors.New("enabled proxy settings are required")
			}
		case HostRouteTun:
			if change.TunDevice == "" || change.TunProxy == "" {
				return errors.New("TUN device and proxy address are required")
			}
		default:
			return fmt.Errorf("unknown host route mode %q", change.RouteMode)
		}
	default:
		return fmt.Errorf("unknown host-network change kind %q", change.Kind)
	}
	return nil
}

func (m *hostNetworkManager) applyPersistentLocked(ctx context.Context, change HostNetworkChange) error {
	snapshot, err := m.capturePersistentSnapshot(ctx, change)
	if err != nil {
		return err
	}
	rec := hostOperationRecord{Version: hostNetworkStateVersion, Snapshot: snapshot, Change: change}
	if err := writeHostRecord(m.operationPath(), rec); err != nil {
		return err
	}

	applyErr := m.applyPersistent(ctx, change)
	if applyErr == nil {
		applyErr = m.verifyPersistent(ctx, change)
	}
	if applyErr != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if rollbackErr := m.restorePersistent(cleanupCtx, snapshot); rollbackErr != nil {
			return errors.Join(applyErr, fmt.Errorf("rollback failed: %w", rollbackErr))
		}
		_ = os.Remove(m.operationPath())
		return applyErr
	}
	return removeHostRecord(m.operationPath())
}

func (m *hostNetworkManager) recoverOperationLocked() error {
	var rec hostOperationRecord
	ok, err := readHostRecord(m.operationPath(), &rec)
	if err != nil || !ok {
		return err
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.restorePersistent(cleanupCtx, rec.Snapshot); err != nil {
		return err
	}
	return removeHostRecord(m.operationPath())
}

func (m *hostNetworkManager) capturePersistentSnapshot(ctx context.Context, change HostNetworkChange) (hostSnapshot, error) {
	s := hostSnapshot{}
	switch change.Kind {
	case HostNetworkChangeDNS:
		servers, err := m.ops.getDNS(ctx, change.DNSInterface)
		if err != nil {
			return s, err
		}
		s.DNSInterface = change.DNSInterface
		s.DNSServers = append([]string(nil), servers...)
	case HostNetworkChangeNCSI:
		ncsi, err := m.ops.getNCSI()
		if err != nil {
			return s, err
		}
		s.NCSI = ncsi
	}
	return s, nil
}

func (m *hostNetworkManager) applyPersistent(ctx context.Context, change HostNetworkChange) error {
	switch change.Kind {
	case HostNetworkChangeDNS:
		return m.ops.setDNS(ctx, change.DNSInterface, change.DNSServers)
	case HostNetworkChangeNCSI:
		return m.ops.setNCSI(ctx, change.NCSI)
	default:
		return fmt.Errorf("unsupported persistent host-network change %q", change.Kind)
	}
}

func (m *hostNetworkManager) verifyPersistent(ctx context.Context, change HostNetworkChange) error {
	switch change.Kind {
	case HostNetworkChangeDNS:
		got, err := m.ops.getDNS(ctx, change.DNSInterface)
		if err != nil {
			return err
		}
		if !slices.Equal(got, change.DNSServers) {
			return fmt.Errorf("DNS verification mismatch: got %v want %v", got, change.DNSServers)
		}
	case HostNetworkChangeNCSI:
		got, err := m.ops.getNCSI()
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, change.NCSI) {
			return fmt.Errorf("NCSI verification mismatch")
		}
	}
	return nil
}

func (m *hostNetworkManager) restorePersistent(ctx context.Context, snapshot hostSnapshot) error {
	if snapshot.DNSInterface != "" {
		if err := m.ops.setDNS(ctx, snapshot.DNSInterface, snapshot.DNSServers); err != nil {
			return err
		}
	}
	if snapshot.NCSI != nil {
		if err := m.ops.setNCSI(ctx, snapshot.NCSI); err != nil {
			return err
		}
	}
	return nil
}

func (m *hostNetworkManager) applyRouteLocked(ctx context.Context, change HostNetworkChange) error {
	var rec hostSessionRecord
	ok, err := readHostRecord(m.sessionPath(), &rec)
	if err != nil {
		return err
	}
	if !ok {
		baseProxy, err := m.ops.getProxy(ctx)
		if err != nil {
			return fmt.Errorf("snapshot original proxy: %w", err)
		}
		active := HostNetworkChange{Kind: HostNetworkChangeRoute, RouteMode: HostRouteDirect}
		if baseProxy.Enabled {
			active.RouteMode = HostRouteProxy
			active.Proxy = *baseProxy
		}
		rec = hostSessionRecord{Version: hostNetworkStateVersion, Snapshot: hostSnapshot{Proxy: baseProxy}, Active: active}
		if err := writeHostRecord(m.sessionPath(), rec); err != nil {
			return err
		}
	}
	previous := rec

	if rec.Active.RouteMode == HostRouteTun && rec.Lease != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := m.ops.stopTun(cleanupCtx, rec.Lease)
		cancel()
		if err != nil {
			return fmt.Errorf("stop previous TUN route: %w", err)
		}
	}

	lease, applyErr := m.applyRoute(ctx, change, nil)
	if applyErr == nil {
		applyErr = m.verifyRoute(ctx, change)
	}
	if applyErr != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if change.RouteMode == HostRouteTun && lease != nil {
			_ = m.ops.stopTun(cleanupCtx, lease)
		}
		if rollbackErr := m.restoreActiveRoute(cleanupCtx, previous); rollbackErr != nil {
			return errors.Join(applyErr, fmt.Errorf("restore previous route: %w", rollbackErr))
		}
		return applyErr
	}

	rec.Active = change
	rec.Lease = lease
	if err := writeHostRecord(m.sessionPath(), rec); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = m.restoreActiveRoute(cleanupCtx, previous)
		return err
	}
	return nil
}

func (m *hostNetworkManager) applyRoute(ctx context.Context, change HostNetworkChange, exactLease *tunRouteLease) (*tunRouteLease, error) {
	switch change.RouteMode {
	case HostRouteDirect:
		return nil, m.ops.setProxy(ctx, &ProxySettings{})
	case HostRouteProxy:
		proxy := change.Proxy
		proxy.Enabled = true
		return nil, m.ops.setProxy(ctx, &proxy)
	case HostRouteTun:
		if err := m.ops.setProxy(ctx, &ProxySettings{}); err != nil {
			return nil, err
		}
		return m.ops.startTun(ctx, change.TunDevice, change.TunProxy, exactLease)
	default:
		return nil, fmt.Errorf("unknown route mode %q", change.RouteMode)
	}
}

func (m *hostNetworkManager) verifyRoute(ctx context.Context, change HostNetworkChange) error {
	switch change.RouteMode {
	case HostRouteDirect:
		got, err := m.ops.getProxy(ctx)
		if err != nil {
			return err
		}
		if got.Enabled {
			return fmt.Errorf("system proxy remains enabled")
		}
	case HostRouteProxy:
		want := change.Proxy
		want.Enabled = true
		return m.verifyProxy(ctx, &want)
	case HostRouteTun:
		if !m.ops.tunUp() {
			return fmt.Errorf("TUN route did not become active")
		}
	}
	return nil
}

func (m *hostNetworkManager) verifyProxy(ctx context.Context, want *ProxySettings) error {
	got, err := m.ops.getProxy(ctx)
	if err != nil {
		return err
	}
	if !proxySettingsEqual(*got, *want) {
		return fmt.Errorf("proxy verification mismatch: got enabled=%v server=%q bypass=%q pac=%q", got.Enabled, got.Server, got.Bypass, got.PACURL)
	}
	return nil
}

func (m *hostNetworkManager) restoreActiveRoute(ctx context.Context, rec hostSessionRecord) error {
	if rec.Active.RouteMode == HostRouteTun {
		_, err := m.applyRoute(ctx, rec.Active, rec.Lease)
		return err
	}
	_, err := m.applyRoute(ctx, rec.Active, nil)
	return err
}

func writeHostRecord(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func readHostRecord(path string, dst any) (bool, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return false, fmt.Errorf("decode %s: %w", filepath.Base(path), err)
	}
	return true, nil
}

func removeHostRecord(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
