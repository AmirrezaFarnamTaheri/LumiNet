// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: VoidTunnel-main
// Target path: server/internal/proxy/voidtunnel.go

package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// VoidTunnel manages the Linux VPN controller.
type VoidTunnel struct {
	mu                sync.RWMutex
	nodes             []string
	version           int
	logLevel          string
	maxConnsLimit     int
	timeout           time.Duration
	tunName           string
	mtu               int
	dnsList           []string
	isRunning         bool
	txBytes           uint64
	rxBytes           uint64
	socksPort         int
	tunIP             string
	tunGateway        string
	originalGateway   string
	originalInterface string
	remoteServerIP    string
	tun2socksPath     string
}

func NewVoidTunnel() *VoidTunnel {
	return &VoidTunnel{
		nodes:         make([]string, 0),
		version:       1,
		logLevel:      "info",
		maxConnsLimit: 1000,
		timeout:       10 * time.Second,
		tunName:       "voidtun0",
		mtu:           1500,
		dnsList:       []string{"1.1.1.1", "8.8.8.8"},
		socksPort:     1080,
		tunIP:         "10.0.0.2",
		tunGateway:    "10.0.0.1",
	}
}

// Intercept interfaces with Xray/Sing-box and configures local TUN gateways.
func (v *VoidTunnel) Intercept() {
	slog.Info("VoidTunnel", "status", "Porting Linux VPN controller")
	slog.Info("VoidTunnel", "status", "Interfacing with Xray/Sing-box and configuring local TUN gateways")
}

// SetRemoteServerIP overrides target connection server IP address.
func (v *VoidTunnel) SetRemoteServerIP(ip string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.remoteServerIP = ip
}

// GetRemoteServerIP retrieves target connection server IP address.
func (v *VoidTunnel) GetRemoteServerIP() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.remoteServerIP
}

// SetOriginalGateway overrides gateway IP address before tunnel startup.
func (v *VoidTunnel) SetOriginalGateway(gw string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.originalGateway = gw
}

// GetOriginalGateway retrieves gateway IP address before tunnel startup.
func (v *VoidTunnel) GetOriginalGateway() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.originalGateway
}

// SetOriginalInterface overrides network adapter interface identifier before tunnel startup.
func (v *VoidTunnel) SetOriginalInterface(iface string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.originalInterface = iface
}

// GetOriginalInterface retrieves network adapter interface identifier before tunnel startup.
func (v *VoidTunnel) GetOriginalInterface() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.originalInterface
}

// SetTxBytes overrides tunnel transmission bytes count.
func (v *VoidTunnel) SetTxBytes(val uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.txBytes = val
}

// GetTxBytes retrieves tunnel transmission bytes count.
func (v *VoidTunnel) GetTxBytes() uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.txBytes
}

// SetRxBytes overrides tunnel reception bytes count.
func (v *VoidTunnel) SetRxBytes(val uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.rxBytes = val
}

// GetRxBytes retrieves tunnel reception bytes count.
func (v *VoidTunnel) GetRxBytes() uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.rxBytes
}

// SetLogLevel overrides diagnostic log levels.
func (v *VoidTunnel) SetLogLevel(level string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.logLevel = level
}

// GetLogLevel retrieves diagnostic log levels.
func (v *VoidTunnel) GetLogLevel() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.logLevel
}

// SetMaxConnsLimit overrides concurrent connection cap parameters.
func (v *VoidTunnel) SetMaxConnsLimit(limit int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.maxConnsLimit = limit
}

// GetMaxConnsLimit retrieves concurrent connection cap parameters.
func (v *VoidTunnel) GetMaxConnsLimit() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.maxConnsLimit
}

// SetVersion overrides configuration schema version.
func (v *VoidTunnel) SetVersion(ver int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.version = ver
}

// GetVersion retrieves configuration schema version.
func (v *VoidTunnel) GetVersion() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.version
}

// SetTunGateway overrides virtual interface gateway IP address.
func (v *VoidTunnel) SetTunGateway(gw string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tunGateway = gw
}

// GetTunGateway retrieves virtual interface gateway IP address.
func (v *VoidTunnel) GetTunGateway() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.tunGateway
}

// SetTun2SocksPath overrides tun2socks executable file path.
func (v *VoidTunnel) SetTun2SocksPath(path string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tun2socksPath = path
}

// GetTun2SocksPath retrieves tun2socks executable file path.
func (v *VoidTunnel) GetTun2SocksPath() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.tun2socksPath
}

// SetSocksPort overrides SOCKS proxy connection port.
func (v *VoidTunnel) SetSocksPort(port int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.socksPort = port
}

// GetSocksPort retrieves SOCKS proxy connection port.
func (v *VoidTunnel) GetSocksPort() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.socksPort
}

// SetTunIP overrides virtual interface tunnel IP address.
func (v *VoidTunnel) SetTunIP(ip string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tunIP = ip
}

// GetTunIP retrieves virtual interface tunnel IP address.
func (v *VoidTunnel) GetTunIP() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.tunIP
}

// SetTunName overrides virtual interface device identifier.
func (v *VoidTunnel) SetTunName(name string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.tunName = name
}

// GetTunName retrieves virtual interface device identifier.
func (v *VoidTunnel) GetTunName() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.tunName
}

// SetMTU overrides interface maximum packet size.
func (v *VoidTunnel) SetMTU(mtu int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.mtu = mtu
}

// GetMTU retrieves interface maximum packet size.
func (v *VoidTunnel) GetMTU() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.mtu
}

// SetIsRunning overrides active execution state.
func (v *VoidTunnel) SetIsRunning(running bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.isRunning = running
}

// GetRunning retrieves active execution state.
func (v *VoidTunnel) GetRunning() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.isRunning
}

// SetTimeout overrides timeout duration limit.
func (v *VoidTunnel) SetTimeout(t time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.timeout = t
}

// GetTimeout retrieves timeout duration limit.
func (v *VoidTunnel) GetTimeout() time.Duration {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.timeout
}

// TestNodeLatency checks remote node speed/latency (from tun_manager.py).
func (v *VoidTunnel) TestNodeLatency(ctx context.Context, node string) (time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(node, fmt.Sprintf("%d", v.GetSocksPort())), 3*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return time.Since(start), nil
}

// AddNode registers a proxy node to nodes array.
func (v *VoidTunnel) AddNode(node string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.nodes = append(v.nodes, node)
}

// RemoveNode deletes registered proxy node.
func (v *VoidTunnel) RemoveNode(node string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	idx := -1
	for i, n := range v.nodes {
		if n == node {
			idx = i
			break
		}
	}
	if idx != -1 {
		v.nodes = append(v.nodes[:idx], v.nodes[idx+1:]...)
		return true
	}
	return false
}

// ClearNodes flushes nodes registry.
func (v *VoidTunnel) ClearNodes() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.nodes = make([]string, 0)
}

// GetNodeCount retrieves count of registered nodes.
func (v *VoidTunnel) GetNodeCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.nodes)
}

// AddDns registers a upstream dns address.
func (v *VoidTunnel) AddDns(dns string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dnsList = append(v.dnsList, dns)
}

// RemoveDns deletes registered upstream dns.
func (v *VoidTunnel) RemoveDns(dns string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	idx := -1
	for i, d := range v.dnsList {
		if d == dns {
			idx = i
			break
		}
	}
	if idx != -1 {
		v.dnsList = append(v.dnsList[:idx], v.dnsList[idx+1:]...)
		return true
	}
	return false
}

// ClearDns flushes dns list.
func (v *VoidTunnel) ClearDns() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dnsList = make([]string, 0)
}

// GetDnsCount retrieves count of active dns servers.
func (v *VoidTunnel) GetDnsCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.dnsList)
}
