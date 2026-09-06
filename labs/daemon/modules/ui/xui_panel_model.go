// Package ui implements xui panel models ported from 3x-ui-main.
// Source: 3x-ui-main/database/model/model.go, sub/subService.go
// Target: server/internal/ui/xui_panel_model.go

package ui

import "time"

// XuiProtocol represents the proxy protocol type for xui inbounds.
type XuiProtocol string

const (
	XuiProtocolVMESS       XuiProtocol = "vmess"
	XuiProtocolVLESS       XuiProtocol = "vless"
	XuiProtocolMVLESS      XuiProtocol = "mvless"
	XuiProtocolTunnel      XuiProtocol = "tunnel"
	XuiProtocolHTTP        XuiProtocol = "http"
	XuiProtocolTrojan      XuiProtocol = "trojan"
	XuiProtocolShadowsocks XuiProtocol = "shadowsocks"
	XuiProtocolMixed       XuiProtocol = "mixed"
	XuiProtocolWireGuard   XuiProtocol = "wireguard"
)

// XuiUser represents a panel user account. Source: model.User
type XuiUser struct {
	UserID   int
	Username string
	Password string
}

func (u *XuiUser) GetUserID() int       { return u.UserID }
func (u *XuiUser) SetUserID(v int)      { u.UserID = v }
func (u *XuiUser) GetUsername() string  { return u.Username }
func (u *XuiUser) SetUsername(v string) { u.Username = v }
func (u *XuiUser) GetPassword() string  { return u.Password }
func (u *XuiUser) SetPassword(v string) { u.Password = v }

// XuiInbound represents a full xui inbound configuration. Source: model.Inbound
type XuiInbound struct {
	InboundID            int
	UserID               int
	Up                   int64
	Down                 int64
	Total                int64
	AllTime              int64
	Remark               string
	Enable               bool
	ExpiryTime           int64
	TrafficReset         string
	LastTrafficResetTime int64
	Listen               string
	Port                 int
	Protocol             XuiProtocol
	Settings             string
	StreamSettings       string
	Tag                  string
	Sniffing             string
}

func (i *XuiInbound) GetInboundID() int               { return i.InboundID }
func (i *XuiInbound) SetInboundID(v int)              { i.InboundID = v }
func (i *XuiInbound) GetUserID() int                  { return i.UserID }
func (i *XuiInbound) SetUserID(v int)                 { i.UserID = v }
func (i *XuiInbound) GetUp() int64                    { return i.Up }
func (i *XuiInbound) SetUp(v int64)                   { i.Up = v }
func (i *XuiInbound) GetDown() int64                  { return i.Down }
func (i *XuiInbound) SetDown(v int64)                 { i.Down = v }
func (i *XuiInbound) GetTotal() int64                 { return i.Total }
func (i *XuiInbound) SetTotal(v int64)                { i.Total = v }
func (i *XuiInbound) GetAllTime() int64               { return i.AllTime }
func (i *XuiInbound) SetAllTime(v int64)              { i.AllTime = v }
func (i *XuiInbound) GetRemark() string               { return i.Remark }
func (i *XuiInbound) SetRemark(v string)              { i.Remark = v }
func (i *XuiInbound) GetEnable() bool                 { return i.Enable }
func (i *XuiInbound) SetEnable(v bool)                { i.Enable = v }
func (i *XuiInbound) GetExpiryTime() int64            { return i.ExpiryTime }
func (i *XuiInbound) SetExpiryTime(v int64)           { i.ExpiryTime = v }
func (i *XuiInbound) GetTrafficReset() string         { return i.TrafficReset }
func (i *XuiInbound) SetTrafficReset(v string)        { i.TrafficReset = v }
func (i *XuiInbound) GetLastTrafficResetTime() int64  { return i.LastTrafficResetTime }
func (i *XuiInbound) SetLastTrafficResetTime(v int64) { i.LastTrafficResetTime = v }
func (i *XuiInbound) GetListen() string               { return i.Listen }
func (i *XuiInbound) SetListen(v string)              { i.Listen = v }
func (i *XuiInbound) GetPort() int                    { return i.Port }
func (i *XuiInbound) SetPort(v int)                   { i.Port = v }
func (i *XuiInbound) GetProtocol() XuiProtocol        { return i.Protocol }
func (i *XuiInbound) SetProtocol(v XuiProtocol)       { i.Protocol = v }
func (i *XuiInbound) GetSettings() string             { return i.Settings }
func (i *XuiInbound) SetSettings(v string)            { i.Settings = v }
func (i *XuiInbound) GetStreamSettings() string       { return i.StreamSettings }
func (i *XuiInbound) SetStreamSettings(v string)      { i.StreamSettings = v }
func (i *XuiInbound) GetTag() string                  { return i.Tag }
func (i *XuiInbound) SetTag(v string)                 { i.Tag = v }
func (i *XuiInbound) GetSniffing() string             { return i.Sniffing }
func (i *XuiInbound) SetSniffing(v string)            { i.Sniffing = v }

// XuiOutboundTraffics tracks outbound traffic statistics. Source: model.OutboundTraffics
type XuiOutboundTraffics struct {
	TrafficID int
	Tag       string
	Up        int64
	Down      int64
	Total     int64
}

func (o *XuiOutboundTraffics) GetTrafficID() int  { return o.TrafficID }
func (o *XuiOutboundTraffics) SetTrafficID(v int) { o.TrafficID = v }
func (o *XuiOutboundTraffics) GetTag() string     { return o.Tag }
func (o *XuiOutboundTraffics) SetTag(v string)    { o.Tag = v }
func (o *XuiOutboundTraffics) GetUp() int64       { return o.Up }
func (o *XuiOutboundTraffics) SetUp(v int64)      { o.Up = v }
func (o *XuiOutboundTraffics) GetDown() int64     { return o.Down }
func (o *XuiOutboundTraffics) SetDown(v int64)    { o.Down = v }
func (o *XuiOutboundTraffics) GetTotal() int64    { return o.Total }
func (o *XuiOutboundTraffics) SetTotal(v int64)   { o.Total = v }

// XuiInboundClientIPs stores per-client IPs for access control. Source: model.InboundClientIps
type XuiInboundClientIPs struct {
	EntryID     int
	ClientEmail string
	IPs         string
}

func (c *XuiInboundClientIPs) GetEntryID() int         { return c.EntryID }
func (c *XuiInboundClientIPs) SetEntryID(v int)        { c.EntryID = v }
func (c *XuiInboundClientIPs) GetClientEmail() string  { return c.ClientEmail }
func (c *XuiInboundClientIPs) SetClientEmail(v string) { c.ClientEmail = v }
func (c *XuiInboundClientIPs) GetIPs() string          { return c.IPs }
func (c *XuiInboundClientIPs) SetIPs(v string)         { c.IPs = v }

// XuiClient represents a client with traffic limits and identity. Source: model.Client
type XuiClient struct {
	ClientID   string
	Security   string
	Password   string
	Flow       string
	Email      string
	LimitIP    int
	TotalGB    int64
	ExpiryTime int64
	Enable     bool
	TgID       int64
	SubID      string
	Comment    string
	Reset      int
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (c *XuiClient) GetClientID() string     { return c.ClientID }
func (c *XuiClient) SetClientID(v string)    { c.ClientID = v }
func (c *XuiClient) GetSecurity() string     { return c.Security }
func (c *XuiClient) SetSecurity(v string)    { c.Security = v }
func (c *XuiClient) GetPassword() string     { return c.Password }
func (c *XuiClient) SetPassword(v string)    { c.Password = v }
func (c *XuiClient) GetFlow() string         { return c.Flow }
func (c *XuiClient) SetFlow(v string)        { c.Flow = v }
func (c *XuiClient) GetEmail() string        { return c.Email }
func (c *XuiClient) SetEmail(v string)       { c.Email = v }
func (c *XuiClient) GetLimitIP() int         { return c.LimitIP }
func (c *XuiClient) SetLimitIP(v int)        { c.LimitIP = v }
func (c *XuiClient) GetTotalGB() int64       { return c.TotalGB }
func (c *XuiClient) SetTotalGB(v int64)      { c.TotalGB = v }
func (c *XuiClient) GetExpiryTime() int64    { return c.ExpiryTime }
func (c *XuiClient) SetExpiryTime(v int64)   { c.ExpiryTime = v }
func (c *XuiClient) GetEnable() bool         { return c.Enable }
func (c *XuiClient) SetEnable(v bool)        { c.Enable = v }
func (c *XuiClient) GetTgID() int64          { return c.TgID }
func (c *XuiClient) SetTgID(v int64)         { c.TgID = v }
func (c *XuiClient) GetSubID() string        { return c.SubID }
func (c *XuiClient) SetSubID(v string)       { c.SubID = v }
func (c *XuiClient) GetComment() string      { return c.Comment }
func (c *XuiClient) SetComment(v string)     { c.Comment = v }
func (c *XuiClient) GetReset() int           { return c.Reset }
func (c *XuiClient) SetReset(v int)          { c.Reset = v }
func (c *XuiClient) GetCreatedAt() time.Time  { return c.CreatedAt }
func (c *XuiClient) SetCreatedAt(v time.Time) { c.CreatedAt = v }
func (c *XuiClient) GetUpdatedAt() time.Time  { return c.UpdatedAt }
func (c *XuiClient) SetUpdatedAt(v time.Time) { c.UpdatedAt = v }

// XuiSetting stores panel configuration key-value entries. Source: model.Setting
type XuiSetting struct {
	SettingID int
	Key       string
	Value     string
}

func (s *XuiSetting) GetSettingID() int  { return s.SettingID }
func (s *XuiSetting) SetSettingID(v int) { s.SettingID = v }
func (s *XuiSetting) GetKey() string     { return s.Key }
func (s *XuiSetting) SetKey(v string)    { s.Key = v }
func (s *XuiSetting) GetValue() string   { return s.Value }
func (s *XuiSetting) SetValue(v string)  { s.Value = v }

// XuiSubService holds subscription service state. Source: sub.SubService
type XuiSubService struct {
	Address     string
	ShowInfo    bool
	RemarkModel string
	Datepicker  string
}

func (s *XuiSubService) GetAddress() string      { return s.Address }
func (s *XuiSubService) SetAddress(v string)     { s.Address = v }
func (s *XuiSubService) GetShowInfo() bool       { return s.ShowInfo }
func (s *XuiSubService) SetShowInfo(v bool)      { s.ShowInfo = v }
func (s *XuiSubService) GetRemarkModel() string  { return s.RemarkModel }
func (s *XuiSubService) SetRemarkModel(v string) { s.RemarkModel = v }
func (s *XuiSubService) GetDatepicker() string   { return s.Datepicker }
func (s *XuiSubService) SetDatepicker(v string)  { s.Datepicker = v }

// XuiExternalProxy holds external proxy routing config. Source: sub.externalProxy map
type XuiExternalProxy struct {
	ForceTLS string
	Dest     string
	Port     int
	Remark   string
}

func (e *XuiExternalProxy) GetForceTLS() string  { return e.ForceTLS }
func (e *XuiExternalProxy) SetForceTLS(v string) { e.ForceTLS = v }
func (e *XuiExternalProxy) GetDest() string      { return e.Dest }
func (e *XuiExternalProxy) SetDest(v string)     { e.Dest = v }
func (e *XuiExternalProxy) GetPort() int         { return e.Port }
func (e *XuiExternalProxy) SetPort(v int)        { e.Port = v }
func (e *XuiExternalProxy) GetRemark() string    { return e.Remark }
func (e *XuiExternalProxy) SetRemark(v string)   { e.Remark = v }

// XuiClientTraffic tracks traffic stats per client email. Source: xray.ClientTraffic
type XuiClientTraffic struct {
	ID         int
	InboundID  int
	Enable     bool
	Email      string
	Up         int64
	Down       int64
	ExpiryTime int64
	Total      int64
}

func (c *XuiClientTraffic) GetID() int             { return c.ID }
func (c *XuiClientTraffic) SetID(v int)            { c.ID = v }
func (c *XuiClientTraffic) GetInboundID() int      { return c.InboundID }
func (c *XuiClientTraffic) SetInboundID(v int)     { c.InboundID = v }
func (c *XuiClientTraffic) GetEnable() bool        { return c.Enable }
func (c *XuiClientTraffic) SetEnable(v bool)       { c.Enable = v }
func (c *XuiClientTraffic) GetEmail() string       { return c.Email }
func (c *XuiClientTraffic) SetEmail(v string)      { c.Email = v }
func (c *XuiClientTraffic) GetUp() int64           { return c.Up }
func (c *XuiClientTraffic) SetUp(v int64)          { c.Up = v }
func (c *XuiClientTraffic) GetDown() int64         { return c.Down }
func (c *XuiClientTraffic) SetDown(v int64)        { c.Down = v }
func (c *XuiClientTraffic) GetExpiryTime() int64   { return c.ExpiryTime }
func (c *XuiClientTraffic) SetExpiryTime(v int64)  { c.ExpiryTime = v }
func (c *XuiClientTraffic) GetTotal() int64        { return c.Total }
func (c *XuiClientTraffic) SetTotal(v int64)       { c.Total = v }
