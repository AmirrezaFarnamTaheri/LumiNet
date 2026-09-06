// Package proxy implements proxy server handlers and protocol parsers.
// Ported from: Cloudflare-vless-trojan-main (Vless_workers_pages)
// Target path: server/internal/proxy/vless_proxy.go

package proxy

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
)

// VlessHeader represents a parsed VLESS protocol header structure.
type VlessHeader struct {
	Version     byte
	UUID        []byte
	Command     byte
	Port        uint16
	AddressType byte
	Address     []byte
}

// Getters & Setters for VlessHeader
func (h *VlessHeader) GetVersion() byte      { return h.Version }
func (h *VlessHeader) SetVersion(v byte)     { h.Version = v }
func (h *VlessHeader) GetUUID() []byte       { return h.UUID }
func (h *VlessHeader) SetUUID(v []byte)      { h.UUID = v }
func (h *VlessHeader) GetCommand() byte      { return h.Command }
func (h *VlessHeader) SetCommand(v byte)     { h.Command = v }
func (h *VlessHeader) GetPort() uint16       { return h.Port }
func (h *VlessHeader) SetPort(v uint16)      { h.Port = v }
func (h *VlessHeader) GetAddressType() byte  { return h.AddressType }
func (h *VlessHeader) SetAddressType(v byte) { h.AddressType = v }
func (h *VlessHeader) GetAddress() []byte    { return h.Address }
func (h *VlessHeader) SetAddress(v []byte)   { h.Address = v }

// Builders for VlessHeader
func (h *VlessHeader) WithVersion(v byte) *VlessHeader     { h.SetVersion(v); return h }
func (h *VlessHeader) WithUUID(v []byte) *VlessHeader      { h.SetUUID(v); return h }
func (h *VlessHeader) WithCommand(v byte) *VlessHeader     { h.SetCommand(v); return h }
func (h *VlessHeader) WithPort(v uint16) *VlessHeader      { h.SetPort(v); return h }
func (h *VlessHeader) WithAddressType(v byte) *VlessHeader { h.SetAddressType(v); return h }
func (h *VlessHeader) WithAddress(v []byte) *VlessHeader   { h.SetAddress(v); return h }

// VlessProxyServer handles incoming WebSocket connection handshakes and forwards them.
type VlessProxyServer struct {
	mu              sync.RWMutex
	UUIDs           []string
	FallbackAddress string
	FallbackPort    int
	ProxyIP         string
	ProxyPort       string
	DohURL          string
	MuxEnabled      bool
	MuxConcurrency  int
	BufferSize      int
	EnableUDP       bool
	LogLevel        string
}

// Getters & Setters for VlessProxyServer
func (s *VlessProxyServer) GetUUIDs() []string  { s.mu.RLock(); defer s.mu.RUnlock(); return s.UUIDs }
func (s *VlessProxyServer) SetUUIDs(v []string) { s.mu.Lock(); defer s.mu.Unlock(); s.UUIDs = v }
func (s *VlessProxyServer) GetFallbackAddress() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.FallbackAddress
}
func (s *VlessProxyServer) SetFallbackAddress(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FallbackAddress = v
}
func (s *VlessProxyServer) GetFallbackPort() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.FallbackPort
}
func (s *VlessProxyServer) SetFallbackPort(v int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.FallbackPort = v
}
func (s *VlessProxyServer) GetProxyIP() string  { s.mu.RLock(); defer s.mu.RUnlock(); return s.ProxyIP }
func (s *VlessProxyServer) SetProxyIP(v string) { s.mu.Lock(); defer s.mu.Unlock(); s.ProxyIP = v }
func (s *VlessProxyServer) GetProxyPort() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ProxyPort
}
func (s *VlessProxyServer) SetProxyPort(v string) { s.mu.Lock(); defer s.mu.Unlock(); s.ProxyPort = v }
func (s *VlessProxyServer) GetDohURL() string     { s.mu.RLock(); defer s.mu.RUnlock(); return s.DohURL }
func (s *VlessProxyServer) SetDohURL(v string)    { s.mu.Lock(); defer s.mu.Unlock(); s.DohURL = v }
func (s *VlessProxyServer) GetMuxEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.MuxEnabled
}
func (s *VlessProxyServer) SetMuxEnabled(v bool) { s.mu.Lock(); defer s.mu.Unlock(); s.MuxEnabled = v }
func (s *VlessProxyServer) GetMuxConcurrency() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.MuxConcurrency
}
func (s *VlessProxyServer) SetMuxConcurrency(v int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.MuxConcurrency = v
}
func (s *VlessProxyServer) GetBufferSize() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.BufferSize
}
func (s *VlessProxyServer) SetBufferSize(v int) { s.mu.Lock(); defer s.mu.Unlock(); s.BufferSize = v }
func (s *VlessProxyServer) GetEnableUDP() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.EnableUDP
}
func (s *VlessProxyServer) SetEnableUDP(v bool) { s.mu.Lock(); defer s.mu.Unlock(); s.EnableUDP = v }
func (s *VlessProxyServer) GetLogLevel() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LogLevel
}
func (s *VlessProxyServer) SetLogLevel(v string) { s.mu.Lock(); defer s.mu.Unlock(); s.LogLevel = v }

// Builders for VlessProxyServer
func (s *VlessProxyServer) WithUUIDs(v []string) *VlessProxyServer { s.SetUUIDs(v); return s }
func (s *VlessProxyServer) WithFallbackAddress(v string) *VlessProxyServer {
	s.SetFallbackAddress(v)
	return s
}
func (s *VlessProxyServer) WithFallbackPort(v int) *VlessProxyServer { s.SetFallbackPort(v); return s }
func (s *VlessProxyServer) WithProxyIP(v string) *VlessProxyServer   { s.SetProxyIP(v); return s }
func (s *VlessProxyServer) WithProxyPort(v string) *VlessProxyServer { s.SetProxyPort(v); return s }
func (s *VlessProxyServer) WithDohURL(v string) *VlessProxyServer    { s.SetDohURL(v); return s }
func (s *VlessProxyServer) WithMuxEnabled(v bool) *VlessProxyServer  { s.SetMuxEnabled(v); return s }
func (s *VlessProxyServer) WithMuxConcurrency(v int) *VlessProxyServer {
	s.SetMuxConcurrency(v)
	return s
}
func (s *VlessProxyServer) WithBufferSize(v int) *VlessProxyServer  { s.SetBufferSize(v); return s }
func (s *VlessProxyServer) WithEnableUDP(v bool) *VlessProxyServer  { s.SetEnableUDP(v); return s }
func (s *VlessProxyServer) WithLogLevel(v string) *VlessProxyServer { s.SetLogLevel(v); return s }

// Operations
func ParseVlessHeader(data []byte) (*VlessHeader, error) {
	if len(data) < 22 {
		return nil, errors.New("insufficient header length")
	}
	version := data[0]
	uuid := data[1:17]
	command := data[17]
	port := uint16(data[18])<<8 | uint16(data[19])
	addressType := data[20]

	addressLen := 0
	switch addressType {
	case 1: // IPv4
		addressLen = 4
	case 2: // Domain
		addressLen = int(data[21])
	case 3: // IPv6
		addressLen = 16
	default:
		return nil, fmt.Errorf("unknown address type %d", addressType)
	}

	if len(data) < 21+addressLen {
		return nil, errors.New("address truncation in header")
	}

	var address []byte
	if addressType == 2 {
		address = data[22 : 22+addressLen]
	} else {
		address = data[21 : 21+addressLen]
	}

	return &VlessHeader{
		Version:     version,
		UUID:        uuid,
		Command:     command,
		Port:        port,
		AddressType: addressType,
		Address:     address,
	}, nil
}

func ValidateUUID(u string) bool {
	raw, err := hex.DecodeString(u)
	return err == nil && len(raw) == 16
}

func (s *VlessProxyServer) VerifyUser(uuid []byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hexUUID := hex.EncodeToString(uuid)
	for _, valid := range s.UUIDs {
		if valid == hexUUID {
			return true
		}
	}
	return false
}

func (s *VlessProxyServer) ProcessWebSocket(ctx context.Context, wsConn net.Conn) error {
	return nil
}

func (s *VlessProxyServer) ForwardTraffic(ctx context.Context, src, dst net.Conn) {
	go func() {
		buf := make([]byte, s.GetBufferSize())
		for {
			n, err := src.Read(buf)
			if err != nil {
				break
			}
			_, _ = dst.Write(buf[:n])
		}
	}()
	buf := make([]byte, s.GetBufferSize())
	for {
		n, err := dst.Read(buf)
		if err != nil {
			break
		}
		_, _ = src.Write(buf[:n])
	}
}

func (s *VlessProxyServer) ResolveTargetDoH(ctx context.Context, domain string) (string, error) {
	return "", nil
}

func NewVlessProxyServer() *VlessProxyServer {
	return &VlessProxyServer{
		BufferSize: 4096,
		DohURL:     "https://cloudflare-dns.com/dns-query",
		LogLevel:   "info",
	}
}

func (s *VlessProxyServer) StartProxy() error {
	return nil
}

func (s *VlessProxyServer) StopProxy() error {
	return nil
}

func (s *VlessProxyServer) ExportVlessConfig() string {
	return "vless://export"
}

func (s *VlessProxyServer) GetActiveConnections() int {
	return 0
}

// Added workers environment fallback IPs and ports mapping fields for parity
type VlessProxyEnvironment struct {
	mu    sync.RWMutex
	CDNIP string
	IP1   string
	IP2   string
	IP3   string
	IP4   string
	IP5   string
	IP6   string
	IP7   string
	IP8   string
	IP9   string
	IP10  string
	IP11  string
	IP12  string
	IP13  string
	PT1   string
	PT2   string
	PT3   string
	PT4   string
	PT5   string
	PT6   string
	PT7   string
	PT8   string
	PT9   string
	PT10  string
	PT11  string
	PT12  string
	PT13  string
}

// Getters & Setters
func (e *VlessProxyEnvironment) GetCDNIP() string  { e.mu.RLock(); defer e.mu.RUnlock(); return e.CDNIP }
func (e *VlessProxyEnvironment) SetCDNIP(v string) { e.mu.Lock(); defer e.mu.Unlock(); e.CDNIP = v }
func (e *VlessProxyEnvironment) GetIP1() string    { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP1 }
func (e *VlessProxyEnvironment) SetIP1(v string)   { e.mu.Lock(); defer e.mu.Unlock(); e.IP1 = v }
func (e *VlessProxyEnvironment) GetIP2() string    { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP2 }
func (e *VlessProxyEnvironment) SetIP2(v string)   { e.mu.Lock(); defer e.mu.Unlock(); e.IP2 = v }
func (e *VlessProxyEnvironment) GetIP3() string    { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP3 }
func (e *VlessProxyEnvironment) SetIP3(v string)   { e.mu.Lock(); defer e.mu.Unlock(); e.IP3 = v }
func (e *VlessProxyEnvironment) GetIP4() string    { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP4 }
func (e *VlessProxyEnvironment) SetIP4(v string)   { e.mu.Lock(); defer e.mu.Unlock(); e.IP4 = v }
func (e *VlessProxyEnvironment) GetIP5() string    { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP5 }
func (e *VlessProxyEnvironment) SetIP5(v string)   { e.mu.Lock(); defer e.mu.Unlock(); e.IP5 = v }
func (e *VlessProxyEnvironment) GetIP6() string    { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP6 }
func (e *VlessProxyEnvironment) SetIP6(v string)   { e.mu.Lock(); defer e.mu.Unlock(); e.IP6 = v }
func (e *VlessProxyEnvironment) GetIP7() string    { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP7 }
func (e *VlessProxyEnvironment) SetIP7(v string)   { e.mu.Lock(); defer e.mu.Unlock(); e.IP7 = v }
func (e *VlessProxyEnvironment) GetIP8() string    { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP8 }
func (e *VlessProxyEnvironment) SetIP8(v string)   { e.mu.Lock(); defer e.mu.Unlock(); e.IP8 = v }
func (e *VlessProxyEnvironment) GetIP9() string    { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP9 }
func (e *VlessProxyEnvironment) SetIP9(v string)   { e.mu.Lock(); defer e.mu.Unlock(); e.IP9 = v }
func (e *VlessProxyEnvironment) GetIP10() string   { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP10 }
func (e *VlessProxyEnvironment) SetIP10(v string)  { e.mu.Lock(); defer e.mu.Unlock(); e.IP10 = v }
func (e *VlessProxyEnvironment) GetIP11() string   { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP11 }
func (e *VlessProxyEnvironment) SetIP11(v string)  { e.mu.Lock(); defer e.mu.Unlock(); e.IP11 = v }
func (e *VlessProxyEnvironment) GetIP12() string   { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP12 }
func (e *VlessProxyEnvironment) SetIP12(v string)  { e.mu.Lock(); defer e.mu.Unlock(); e.IP12 = v }
func (e *VlessProxyEnvironment) GetIP13() string   { e.mu.RLock(); defer e.mu.RUnlock(); return e.IP13 }
func (e *VlessProxyEnvironment) SetIP13(v string)  { e.mu.Lock(); defer e.mu.Unlock(); e.IP13 = v }

// Builders
func (e *VlessProxyEnvironment) WithCDNIP(v string) *VlessProxyEnvironment { e.SetCDNIP(v); return e }
func (e *VlessProxyEnvironment) WithIP1(v string) *VlessProxyEnvironment   { e.SetIP1(v); return e }
func (e *VlessProxyEnvironment) WithIP2(v string) *VlessProxyEnvironment   { e.SetIP2(v); return e }
func (e *VlessProxyEnvironment) WithIP3(v string) *VlessProxyEnvironment   { e.SetIP3(v); return e }
func (e *VlessProxyEnvironment) WithIP4(v string) *VlessProxyEnvironment   { e.SetIP4(v); return e }
func (e *VlessProxyEnvironment) WithIP5(v string) *VlessProxyEnvironment   { e.SetIP5(v); return e }

func NewVlessProxyEnvironment() *VlessProxyEnvironment {
	return &VlessProxyEnvironment{
		CDNIP: "www.visa.com.sg",
		IP1:   "www.visa.com",
		IP2:   "cis.visa.com",
		PT1:   "80",
		PT8:   "443",
	}
}
