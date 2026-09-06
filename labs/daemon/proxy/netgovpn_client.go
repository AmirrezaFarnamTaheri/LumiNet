// Package proxy implements multi-protocol proxy servers and clients.
// Ported from: NetGoVPN-Android-main (v2ray/)
// Target path: server/internal/proxy/netgovpn_client.go

package proxy

import (
	"fmt"
	"time"
)

// NetGoVPNProfile holds connection parameters for the client VPN app.
type NetGoVPNProfile struct {
	ProfileID          string `json:"profile_id"`
	ProfileName        string `json:"profile_name"`
	ServerAddress      string `json:"server_address"`
	ServerPort         int    `json:"server_port"`
	UserUUID           string `json:"user_uuid"`
	AlterID            int    `json:"alter_id"`
	Security           string `json:"security"` // auto, none, chacha20-poly1305
	Network            string `json:"network"`  // tcp, ws, grpc
	Path               string `json:"path,omitempty"`
	Host               string `json:"host,omitempty"`
	TLSVersion         string `json:"tls_version,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

// Getters & Setters for NetGoVPNProfile
func (p *NetGoVPNProfile) GetProfileID() string      { return p.ProfileID }
func (p *NetGoVPNProfile) SetProfileID(v string)     { p.ProfileID = v }
func (p *NetGoVPNProfile) GetServerAddress() string  { return p.ServerAddress }
func (p *NetGoVPNProfile) SetServerAddress(v string) { p.ServerAddress = v }

// NetGoVPNSetting holds routing filter options.
type NetGoVPNSetting struct {
	DNSList             []string `json:"dns_list"`
	BypassLocalIPs      bool     `json:"bypass_local_ips"`
	EnableAppsFiltering bool     `json:"enable_apps_filtering"`
	FilteredApps        []string `json:"filtered_apps"`
	MaxConcurrency      int      `json:"max_concurrency"`
	MuxEnabled          bool     `json:"mux_enabled"`
	LogLevel            string   `json:"log_level"`
}

// Getters & Setters for NetGoVPNSetting
func (s *NetGoVPNSetting) GetLogLevel() string  { return s.LogLevel }
func (s *NetGoVPNSetting) SetLogLevel(v string) { s.LogLevel = v }

// GenerateV2rayConfigRaw returns connection debug string.
func (p *NetGoVPNProfile) GenerateV2rayConfigRaw() string {
	return fmt.Sprintf("v2ray-profile-%s-%s:%d", p.ProfileID, p.ServerAddress, p.ServerPort)
}

// Additional getters & setters for NetGoVPNProfile
func (p *NetGoVPNProfile) GetProfileName() string       { return p.ProfileName }
func (p *NetGoVPNProfile) SetProfileName(v string)      { p.ProfileName = v }
func (p *NetGoVPNProfile) GetServerPort() int           { return p.ServerPort }
func (p *NetGoVPNProfile) SetServerPort(v int)          { p.ServerPort = v }
func (p *NetGoVPNProfile) GetUserUUID() string          { return p.UserUUID }
func (p *NetGoVPNProfile) SetUserUUID(v string)         { p.UserUUID = v }
func (p *NetGoVPNProfile) GetAlterID() int              { return p.AlterID }
func (p *NetGoVPNProfile) SetAlterID(v int)             { p.AlterID = v }
func (p *NetGoVPNProfile) GetSecurity() string          { return p.Security }
func (p *NetGoVPNProfile) SetSecurity(v string)         { p.Security = v }
func (p *NetGoVPNProfile) GetNetwork() string           { return p.Network }
func (p *NetGoVPNProfile) SetNetwork(v string)          { p.Network = v }
func (p *NetGoVPNProfile) GetPath() string              { return p.Path }
func (p *NetGoVPNProfile) SetPath(v string)             { p.Path = v }
func (p *NetGoVPNProfile) GetHost() string              { return p.Host }
func (p *NetGoVPNProfile) SetHost(v string)             { p.Host = v }
func (p *NetGoVPNProfile) GetTLSVersion() string        { return p.TLSVersion }
func (p *NetGoVPNProfile) SetTLSVersion(v string)       { p.TLSVersion = v }
func (p *NetGoVPNProfile) GetInsecureSkipVerify() bool  { return p.InsecureSkipVerify }
func (p *NetGoVPNProfile) SetInsecureSkipVerify(v bool) { p.InsecureSkipVerify = v }

// Additional getters & setters for NetGoVPNSetting
func (s *NetGoVPNSetting) GetBypassLocalIPs() bool       { return s.BypassLocalIPs }
func (s *NetGoVPNSetting) SetBypassLocalIPs(v bool)      { s.BypassLocalIPs = v }
func (s *NetGoVPNSetting) GetEnableAppsFiltering() bool  { return s.EnableAppsFiltering }
func (s *NetGoVPNSetting) SetEnableAppsFiltering(v bool) { s.EnableAppsFiltering = v }
func (s *NetGoVPNSetting) GetMaxConcurrency() int        { return s.MaxConcurrency }
func (s *NetGoVPNSetting) SetMaxConcurrency(v int)       { s.MaxConcurrency = v }
func (s *NetGoVPNSetting) GetMuxEnabled() bool           { return s.MuxEnabled }
func (s *NetGoVPNSetting) SetMuxEnabled(v bool)          { s.MuxEnabled = v }

// NetGoVPNAppRules represents per-application proxy filtering configurations.
type NetGoVPNAppRules struct {
	RuleID      int
	PackageName string
	BypassProxy bool
	AllowedWiFi bool
}

// Getters & Setters for NetGoVPNAppRules
func (r *NetGoVPNAppRules) GetRuleID() int          { return r.RuleID }
func (r *NetGoVPNAppRules) SetRuleID(v int)         { r.RuleID = v }
func (r *NetGoVPNAppRules) GetPackageName() string  { return r.PackageName }
func (r *NetGoVPNAppRules) SetPackageName(v string) { r.PackageName = v }
func (r *NetGoVPNAppRules) GetBypassProxy() bool    { return r.BypassProxy }
func (r *NetGoVPNAppRules) SetBypassProxy(v bool)   { r.BypassProxy = v }
func (r *NetGoVPNAppRules) GetAllowedWiFi() bool    { return r.AllowedWiFi }
func (r *NetGoVPNAppRules) SetAllowedWiFi(v bool)   { r.AllowedWiFi = v }

// NetGoVPNMuxConfig contains protocol multiplexing parameters.
type NetGoVPNMuxConfig struct {
	MuxID          int
	Concurrency    int
	IdleTimeoutSec int
}

// Getters & Setters for NetGoVPNMuxConfig
func (m *NetGoVPNMuxConfig) GetMuxID() int           { return m.MuxID }
func (m *NetGoVPNMuxConfig) SetMuxID(v int)          { m.MuxID = v }
func (m *NetGoVPNMuxConfig) GetConcurrency() int     { return m.Concurrency }
func (m *NetGoVPNMuxConfig) SetConcurrency(v int)    { m.Concurrency = v }
func (m *NetGoVPNMuxConfig) GetIdleTimeoutSec() int  { return m.IdleTimeoutSec }
func (m *NetGoVPNMuxConfig) SetIdleTimeoutSec(v int) { m.IdleTimeoutSec = v }

// NetGoVPNPingResult stores ping execution states.
type NetGoVPNPingResult struct {
	ServerConfig string
	DelayMs      int
	Error        string
	TargetHost   string
	TargetPort   int
	Successful   bool
}

// Getters & Setters for NetGoVPNPingResult
func (p *NetGoVPNPingResult) GetServerConfig() string  { return p.ServerConfig }
func (p *NetGoVPNPingResult) SetServerConfig(v string) { p.ServerConfig = v }
func (p *NetGoVPNPingResult) GetDelayMs() int          { return p.DelayMs }
func (p *NetGoVPNPingResult) SetDelayMs(v int)         { p.DelayMs = v }
func (p *NetGoVPNPingResult) GetError() string         { return p.Error }
func (p *NetGoVPNPingResult) SetError(v string)        { p.Error = v }
func (p *NetGoVPNPingResult) GetTargetHost() string    { return p.TargetHost }
func (p *NetGoVPNPingResult) SetTargetHost(v string)   { p.TargetHost = v }
func (p *NetGoVPNPingResult) GetTargetPort() int       { return p.TargetPort }
func (p *NetGoVPNPingResult) SetTargetPort(v int)      { p.TargetPort = v }
func (p *NetGoVPNPingResult) GetSuccessful() bool      { return p.Successful }
func (p *NetGoVPNPingResult) SetSuccessful(v bool)     { p.Successful = v }

// NetGoVPNPermissionState captures requested Android package permission states.
type NetGoVPNPermissionState struct {
	PermissionType string
	Granted        bool
	ReqCode        int
	RationaleShown bool
}

// Getters & Setters for NetGoVPNPermissionState
func (s *NetGoVPNPermissionState) GetPermissionType() string  { return s.PermissionType }
func (s *NetGoVPNPermissionState) SetPermissionType(v string) { s.PermissionType = v }
func (s *NetGoVPNPermissionState) GetGranted() bool           { return s.Granted }
func (s *NetGoVPNPermissionState) SetGranted(v bool)          { s.Granted = v }
func (s *NetGoVPNPermissionState) GetReqCode() int            { return s.ReqCode }
func (s *NetGoVPNPermissionState) SetReqCode(v int)           { s.ReqCode = v }
func (s *NetGoVPNPermissionState) GetRationaleShown() bool    { return s.RationaleShown }
func (s *NetGoVPNPermissionState) SetRationaleShown(v bool)   { s.RationaleShown = v }

// NetGoVPNFirebaseMessage logs incoming push notifications.
type NetGoVPNFirebaseMessage struct {
	MessageID string
	Title     string
	Body      string
	Payload   string
	SentTime  time.Time
}

// Getters & Setters for NetGoVPNFirebaseMessage
func (m *NetGoVPNFirebaseMessage) GetMessageID() string    { return m.MessageID }
func (m *NetGoVPNFirebaseMessage) SetMessageID(v string)   { m.MessageID = v }
func (m *NetGoVPNFirebaseMessage) GetTitle() string        { return m.Title }
func (m *NetGoVPNFirebaseMessage) SetTitle(v string)       { m.Title = v }
func (m *NetGoVPNFirebaseMessage) GetBody() string         { return m.Body }
func (m *NetGoVPNFirebaseMessage) SetBody(v string)        { m.Body = v }
func (m *NetGoVPNFirebaseMessage) GetPayload() string      { return m.Payload }
func (m *NetGoVPNFirebaseMessage) SetPayload(v string)     { m.Payload = v }
func (m *NetGoVPNFirebaseMessage) GetSentTime() time.Time  { return m.SentTime }
func (m *NetGoVPNFirebaseMessage) SetSentTime(v time.Time) { m.SentTime = v }
