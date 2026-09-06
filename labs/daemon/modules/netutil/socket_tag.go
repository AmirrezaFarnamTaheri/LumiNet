// Package netutil provides network socket utilities and tagging controls.
// Ported from: MaybeEdgeScanner (go-sidecar/sidecar_socket_tag.go)
// Target path: server/internal/netutil/socket_tag.go

package netutil

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"syscall"
	"time"
)

type contextKey string

const socketMarkKey contextKey = "socket_mark"

// SocketTagConfig controls socket options and policy routing markers.
type SocketTagConfig struct {
	mu            sync.RWMutex
	SocketMark    int
	InterfaceHint string
	RoutingTable  int
	TrafficClass  int
	Priority      int
	Timeout       time.Duration
	NoDelay       bool
	KeepAliveSec  int
	BindAddress   string
	IsActive      bool
}

// Getters & Setters for SocketTagConfig
func (c *SocketTagConfig) GetSocketMark() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.SocketMark }
func (c *SocketTagConfig) SetSocketMark(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.SocketMark = v }
func (c *SocketTagConfig) GetInterfaceHint() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.InterfaceHint }
func (c *SocketTagConfig) SetInterfaceHint(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.InterfaceHint = v }
func (c *SocketTagConfig) GetRoutingTable() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.RoutingTable }
func (c *SocketTagConfig) SetRoutingTable(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.RoutingTable = v }
func (c *SocketTagConfig) GetTrafficClass() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.TrafficClass }
func (c *SocketTagConfig) SetTrafficClass(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.TrafficClass = v }
func (c *SocketTagConfig) GetPriority() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.Priority }
func (c *SocketTagConfig) SetPriority(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.Priority = v }
func (c *SocketTagConfig) GetTimeout() time.Duration { c.mu.RLock(); defer c.mu.RUnlock(); return c.Timeout }
func (c *SocketTagConfig) SetTimeout(v time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.Timeout = v }
func (c *SocketTagConfig) GetNoDelay() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.NoDelay }
func (c *SocketTagConfig) SetNoDelay(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.NoDelay = v }
func (c *SocketTagConfig) GetKeepAliveSec() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.KeepAliveSec }
func (c *SocketTagConfig) SetKeepAliveSec(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.KeepAliveSec = v }
func (c *SocketTagConfig) GetBindAddress() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.BindAddress }
func (c *SocketTagConfig) SetBindAddress(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.BindAddress = v }
func (c *SocketTagConfig) GetIsActive() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.IsActive }
func (c *SocketTagConfig) SetIsActive(v bool) { c.mu.Lock(); defer c.mu.Unlock(); c.IsActive = v }

// Builders for SocketTagConfig
func (c *SocketTagConfig) WithSocketMark(v int) *SocketTagConfig { c.SetSocketMark(v); return c }
func (c *SocketTagConfig) WithInterfaceHint(v string) *SocketTagConfig { c.SetInterfaceHint(v); return c }
func (c *SocketTagConfig) WithRoutingTable(v int) *SocketTagConfig { c.SetRoutingTable(v); return c }
func (c *SocketTagConfig) WithTrafficClass(v int) *SocketTagConfig { c.SetTrafficClass(v); return c }
func (c *SocketTagConfig) WithPriority(v int) *SocketTagConfig { c.SetPriority(v); return c }
func (c *SocketTagConfig) WithTimeout(v time.Duration) *SocketTagConfig { c.SetTimeout(v); return c }
func (c *SocketTagConfig) WithNoDelay(v bool) *SocketTagConfig { c.SetNoDelay(v); return c }
func (c *SocketTagConfig) WithKeepAliveSec(v int) *SocketTagConfig { c.SetKeepAliveSec(v); return c }
func (c *SocketTagConfig) WithBindAddress(v string) *SocketTagConfig { c.SetBindAddress(v); return c }
func (c *SocketTagConfig) WithIsActive(v bool) *SocketTagConfig { c.SetIsActive(v); return c }

// Operations
func NewSocketTagConfig() *SocketTagConfig {
	return &SocketTagConfig{
		NoDelay:      true,
		KeepAliveSec: 15,
		IsActive:     true,
	}
}

func WithSocketMark(ctx context.Context, mark int) context.Context {
	if mark == 0 {
		return ctx
	}
	return context.WithValue(ctx, socketMarkKey, mark)
}

func GetSocketMark(ctx context.Context) int {
	if val := ctx.Value(socketMarkKey); val != nil {
		if mark, ok := val.(int); ok {
			return mark
		}
	}
	return 0
}

func ConfigureDialerWithMark(ctx context.Context, dialer *net.Dialer) {
	mark := GetSocketMark(ctx)
	if mark == 0 {
		return
	}
	originalControl := dialer.Control
	dialer.Control = func(network, address string, c syscall.RawConn) error {
		if originalControl != nil {
			if err := originalControl(network, address, c); err != nil {
				return err
			}
		}
		return c.Control(func(fd uintptr) {
			_ = setSocketMark(fd, mark)
		})
	}
}



func (c *SocketTagConfig) ApplySocketOptions(raw syscall.RawConn) error {
	return raw.Control(func(fd uintptr) {
		if c.GetSocketMark() > 0 {
			_ = setSocketMark(fd, c.GetSocketMark())
		}
	})
}

func (c *SocketTagConfig) CreateDialer(ctx context.Context) *net.Dialer {
	dialer := &net.Dialer{
		Timeout:   c.GetTimeout(),
		KeepAlive: time.Duration(c.GetKeepAliveSec()) * time.Second,
	}
	ConfigureDialerWithMark(ctx, dialer)
	return dialer
}

func (c *SocketTagConfig) ValidateConfig() bool {
	return c.GetIsActive()
}

func (c *SocketTagConfig) ResetConfig() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.SocketMark = 0
	c.InterfaceHint = ""
	c.RoutingTable = 0
	c.TrafficClass = 0
	c.Priority = 0
}

func (c *SocketTagConfig) ExportConfigJSON() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	res, err := json.Marshal(c)
	return string(res), err
}

func (c *SocketTagConfig) GetStatusMessage() string {
	if c.GetIsActive() {
		return "Socket tagging is active"
	}
	return "Socket tagging is inactive"
}

func (c *SocketTagConfig) IsMarkApplied(ctx context.Context) bool {
	return GetSocketMark(ctx) > 0
}

// ---------------------------------------------------------------------------
// ContextDirectDialer — absorbed from system/socket_tag.go
// ---------------------------------------------------------------------------

// ContextDirectDialer wraps a context and exposes a Dialer that applies the
// context's socket mark on every outbound connection.
type ContextDirectDialer struct {
	Ctx context.Context
}

// Dial dials network and addr, applying socket mark rules from the context.
func (d *ContextDirectDialer) Dial(network, addr string) (net.Conn, error) {
	dialer := net.Dialer{}
	ConfigureDialerWithMark(d.Ctx, &dialer)
	return dialer.DialContext(d.Ctx, network, addr)
}

