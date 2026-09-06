package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultNetworkMonitorInterval = 2 * time.Second
	DefaultNetworkHistoryLimit    = 64
	MaxNetworkSubscribers         = 64
)

type InterfaceState struct {
	Index        int      `json:"index"`
	Name         string   `json:"name"`
	MTU          int      `json:"mtu"`
	HardwareAddr string   `json:"hardware_addr,omitempty"`
	Flags        []string `json:"flags,omitempty"`
	Addresses    []string `json:"addresses,omitempty"`
}

type NetworkSnapshot struct {
	Revision             uint64           `json:"revision"`
	CapturedAt           time.Time        `json:"captured_at"`
	Fingerprint          string           `json:"fingerprint"`
	Interfaces           []InterfaceState `json:"interfaces"`
	DefaultIPv4Interface string           `json:"default_ipv4_interface,omitempty"`
	DefaultIPv4LocalIP   string           `json:"default_ipv4_local_ip,omitempty"`
	DefaultIPv6Interface string           `json:"default_ipv6_interface,omitempty"`
	DefaultIPv6LocalIP   string           `json:"default_ipv6_local_ip,omitempty"`
}

type NetworkChange struct {
	Revision   uint64          `json:"revision"`
	ObservedAt time.Time       `json:"observed_at"`
	Kinds      []string        `json:"kinds"`
	Previous   NetworkSnapshot `json:"previous"`
	Current    NetworkSnapshot `json:"current"`
}

type NetworkMonitorStatus struct {
	Running   bool            `json:"running"`
	Current   NetworkSnapshot `json:"current"`
	History   []NetworkChange `json:"history"`
	LastError string          `json:"last_error,omitempty"`
}

type networkCaptureFunc func(context.Context) (NetworkSnapshot, error)

type NetworkMonitor struct {
	mu           sync.RWMutex
	interval     time.Duration
	historyLimit int
	capture      networkCaptureFunc
	current      NetworkSnapshot
	history      []NetworkChange
	lastError    string
	running      bool
	cancel       context.CancelFunc
	done         chan struct{}
	nextSubID    uint64
	subscribers  map[uint64]chan NetworkChange
}

func NewNetworkMonitor(interval time.Duration) *NetworkMonitor {
	return newNetworkMonitor(interval, DefaultNetworkHistoryLimit, captureNetworkSnapshot)
}

func newNetworkMonitor(interval time.Duration, historyLimit int, capture networkCaptureFunc) *NetworkMonitor {
	if interval <= 0 {
		interval = DefaultNetworkMonitorInterval
	}
	if historyLimit <= 0 {
		historyLimit = DefaultNetworkHistoryLimit
	}
	if capture == nil {
		capture = captureNetworkSnapshot
	}
	return &NetworkMonitor{
		interval: interval, historyLimit: historyLimit, capture: capture,
		subscribers: make(map[uint64]chan NetworkChange),
	}
}

var defaultNetworkMonitor = NewNetworkMonitor(DefaultNetworkMonitorInterval)

func GetNetworkMonitor() *NetworkMonitor { return defaultNetworkMonitor }

func (m *NetworkMonitor) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	loopCtx, cancel := context.WithCancel(ctx)
	m.running = true
	m.cancel = cancel
	m.done = make(chan struct{})
	done := m.done
	m.mu.Unlock()

	// Establish initial truth before the first interval. Failure is retained but
	// does not terminate monitoring; transient interface enumeration can recover.
	_, _ = m.Refresh(loopCtx)
	go func() {
		defer close(done)
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				_, _ = m.Refresh(loopCtx)
			}
		}
	}()
}

func (m *NetworkMonitor) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	cancel, done := m.cancel, m.done
	m.running = false
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (m *NetworkMonitor) Refresh(ctx context.Context) (NetworkSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	next, err := m.capture(ctx)
	if err != nil {
		m.mu.Lock()
		m.lastError = err.Error()
		current := cloneNetworkSnapshot(m.current)
		m.mu.Unlock()
		return current, err
	}
	next.CapturedAt = time.Now().UTC()
	if next.Fingerprint == "" {
		next.Fingerprint = fingerprintNetwork(next)
	}

	m.mu.Lock()
	m.lastError = ""
	if m.current.Revision == 0 {
		next.Revision = 1
		m.current = cloneNetworkSnapshot(next)
		out := cloneNetworkSnapshot(next)
		m.mu.Unlock()
		return out, nil
	}
	if next.Fingerprint == m.current.Fingerprint {
		// Keep the stable revision but refresh observation time and optional
		// metadata returned by capture.
		next.Revision = m.current.Revision
		m.current = cloneNetworkSnapshot(next)
		out := cloneNetworkSnapshot(next)
		m.mu.Unlock()
		return out, nil
	}
	previous := cloneNetworkSnapshot(m.current)
	next.Revision = previous.Revision + 1
	change := NetworkChange{
		Revision: next.Revision, ObservedAt: next.CapturedAt,
		Kinds: classifyNetworkChange(previous, next), Previous: previous,
		Current: cloneNetworkSnapshot(next),
	}
	m.current = cloneNetworkSnapshot(next)
	m.history = append(m.history, cloneNetworkChange(change))
	if len(m.history) > m.historyLimit {
		m.history = append([]NetworkChange(nil), m.history[len(m.history)-m.historyLimit:]...)
	}
	subs := make([]chan NetworkChange, 0, len(m.subscribers))
	for _, ch := range m.subscribers {
		subs = append(subs, ch)
	}
	out := cloneNetworkSnapshot(next)
	m.mu.Unlock()

	for _, ch := range subs {
		publishLatestNetworkChange(ch, change)
	}
	return out, nil
}

func (m *NetworkMonitor) Snapshot() NetworkSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneNetworkSnapshot(m.current)
}

func (m *NetworkMonitor) Status(historyLimit int) NetworkMonitorStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if historyLimit < 0 {
		historyLimit = 0
	}
	if historyLimit > len(m.history) {
		historyLimit = len(m.history)
	}
	start := len(m.history) - historyLimit
	history := make([]NetworkChange, 0, historyLimit)
	for _, c := range m.history[start:] {
		history = append(history, cloneNetworkChange(c))
	}
	return NetworkMonitorStatus{Running: m.running, Current: cloneNetworkSnapshot(m.current), History: history, LastError: m.lastError}
}

func (m *NetworkMonitor) Subscribe(buffer int) (<-chan NetworkChange, func(), error) {
	if buffer < 1 {
		buffer = 1
	}
	if buffer > 32 {
		buffer = 32
	}
	m.mu.Lock()
	if len(m.subscribers) >= MaxNetworkSubscribers {
		m.mu.Unlock()
		return nil, nil, errors.New("network monitor subscriber limit reached")
	}
	m.nextSubID++
	id := m.nextSubID
	ch := make(chan NetworkChange, buffer)
	m.subscribers[id] = ch
	m.mu.Unlock()
	var once sync.Once
	unsubscribe := func() {
		once.Do(func() {
			m.mu.Lock()
			delete(m.subscribers, id)
			m.mu.Unlock()
		})
	}
	return ch, unsubscribe, nil
}

func publishLatestNetworkChange(ch chan NetworkChange, change NetworkChange) {
	copyChange := cloneNetworkChange(change)
	select {
	case ch <- copyChange:
		return
	default:
	}
	// Coalesce a slow subscriber by dropping one stale buffered event and
	// attempting to publish the newest state. Never block the monitor loop.
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- copyChange:
	default:
	}
}

func captureNetworkSnapshot(context.Context) (NetworkSnapshot, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return NetworkSnapshot{}, err
	}
	states := make([]InterfaceState, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		addresses := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			if s := strings.TrimSpace(addr.String()); s != "" {
				addresses = append(addresses, s)
			}
		}
		if len(addresses) == 0 {
			continue
		}
		sort.Strings(addresses)
		flags := interfaceFlagNames(iface.Flags)
		states = append(states, InterfaceState{Index: iface.Index, Name: iface.Name, MTU: iface.MTU, HardwareAddr: iface.HardwareAddr.String(), Flags: flags, Addresses: addresses})
	}
	sort.Slice(states, func(i, j int) bool {
		if states[i].Index == states[j].Index {
			return states[i].Name < states[j].Name
		}
		return states[i].Index < states[j].Index
	})
	v4iface, v4ip := inferDefaultInterface("udp4", "1.1.1.1:53", states)
	v6iface, v6ip := inferDefaultInterface("udp6", "[2606:4700:4700::1111]:53", states)
	s := NetworkSnapshot{Interfaces: states, DefaultIPv4Interface: v4iface, DefaultIPv4LocalIP: v4ip, DefaultIPv6Interface: v6iface, DefaultIPv6LocalIP: v6ip}
	s.Fingerprint = fingerprintNetwork(s)
	return s, nil
}

func inferDefaultInterface(network, target string, states []InterfaceState) (string, string) {
	remote, err := net.ResolveUDPAddr(network, target)
	if err != nil {
		return "", ""
	}
	conn, err := net.DialUDP(network, nil, remote)
	if err != nil {
		return "", ""
	}
	local := conn.LocalAddr().(*net.UDPAddr)
	_ = conn.Close()
	ip := local.IP.String()
	for _, iface := range states {
		for _, raw := range iface.Addresses {
			addrIP, _, err := net.ParseCIDR(raw)
			if err == nil && addrIP.Equal(local.IP) {
				return iface.Name, ip
			}
			if err != nil {
				if parsed := net.ParseIP(strings.Split(raw, "%")[0]); parsed != nil && parsed.Equal(local.IP) {
					return iface.Name, ip
				}
			}
		}
	}
	return "", ip
}

func interfaceFlagNames(flags net.Flags) []string {
	pairs := []struct {
		flag net.Flags
		name string
	}{
		{net.FlagUp, "up"}, {net.FlagBroadcast, "broadcast"}, {net.FlagLoopback, "loopback"},
		{net.FlagPointToPoint, "point_to_point"}, {net.FlagMulticast, "multicast"}, {net.FlagRunning, "running"},
	}
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if flags&p.flag != 0 {
			out = append(out, p.name)
		}
	}
	return out
}

func fingerprintNetwork(s NetworkSnapshot) string {
	var b strings.Builder
	for _, iface := range s.Interfaces {
		b.WriteString(strconv.Itoa(iface.Index))
		b.WriteByte('|')
		b.WriteString(iface.Name)
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(iface.MTU))
		b.WriteByte('|')
		b.WriteString(iface.HardwareAddr)
		b.WriteByte('|')
		for _, flag := range iface.Flags {
			b.WriteString(flag)
			b.WriteByte(',')
		}
		b.WriteByte('|')
		for _, addr := range iface.Addresses {
			b.WriteString(addr)
			b.WriteByte(',')
		}
		b.WriteByte(';')
	}
	b.WriteString("v4=")
	b.WriteString(s.DefaultIPv4Interface)
	b.WriteByte('|')
	b.WriteString(s.DefaultIPv4LocalIP)
	b.WriteString(";v6=")
	b.WriteString(s.DefaultIPv6Interface)
	b.WriteByte('|')
	b.WriteString(s.DefaultIPv6LocalIP)
	d := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(d[:])
}

func classifyNetworkChange(a, b NetworkSnapshot) []string {
	var kinds []string
	if a.DefaultIPv4Interface != b.DefaultIPv4Interface || a.DefaultIPv4LocalIP != b.DefaultIPv4LocalIP {
		kinds = append(kinds, "default_route_ipv4")
	}
	if a.DefaultIPv6Interface != b.DefaultIPv6Interface || a.DefaultIPv6LocalIP != b.DefaultIPv6LocalIP {
		kinds = append(kinds, "default_route_ipv6")
	}
	if interfaceShape(a.Interfaces) != interfaceShape(b.Interfaces) {
		kinds = append(kinds, "interfaces")
	}
	if len(kinds) == 0 {
		kinds = append(kinds, "network")
	}
	return kinds
}

func interfaceShape(in []InterfaceState) string {
	var b strings.Builder
	for _, iface := range in {
		b.WriteString(strconv.Itoa(iface.Index))
		b.WriteByte('|')
		b.WriteString(iface.Name)
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(iface.MTU))
		b.WriteByte('|')
		b.WriteString(iface.HardwareAddr)
		b.WriteByte('|')
		for _, flag := range iface.Flags {
			b.WriteString(flag)
			b.WriteByte(',')
		}
		b.WriteByte('|')
		for _, addr := range iface.Addresses {
			b.WriteString(addr)
			b.WriteByte(',')
		}
		b.WriteByte(';')
	}
	return b.String()
}

func cloneNetworkSnapshot(in NetworkSnapshot) NetworkSnapshot {
	out := in
	out.Interfaces = make([]InterfaceState, len(in.Interfaces))
	for i, iface := range in.Interfaces {
		out.Interfaces[i] = iface
		out.Interfaces[i].Flags = append([]string(nil), iface.Flags...)
		out.Interfaces[i].Addresses = append([]string(nil), iface.Addresses...)
	}
	return out
}

func cloneNetworkChange(in NetworkChange) NetworkChange {
	out := in
	out.Kinds = append([]string(nil), in.Kinds...)
	out.Previous = cloneNetworkSnapshot(in.Previous)
	out.Current = cloneNetworkSnapshot(in.Current)
	return out
}
