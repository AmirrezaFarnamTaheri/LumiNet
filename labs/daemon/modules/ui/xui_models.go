// Package ui implements admin panel models, wireguard obfuscation, and subscription services.
// Ported from: 3x-ui-main (database/model/model.go)
// Target path: server/internal/ui/xui_models.go

package ui

import "fmt"

// UIUser represents user account in the x-ui panel.
type UIUser struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Getters & Setters for UIUser
func (u *UIUser) GetID() int { return u.ID }
func (u *UIUser) SetID(v int) { u.ID = v }
func (u *UIUser) GetUsername() string { return u.Username }
func (u *UIUser) SetUsername(v string) { u.Username = v }

// UIInbound represents Xray inbound configs and traffic.
type UIInbound struct {
	ID                   int    `json:"id"`
	UserID               int    `json:"userId"`
	Up                   int64  `json:"up"`
	Down                 int64  `json:"down"`
	Total                int64  `json:"total"`
	AllTime              int64  `json:"allTime"`
	Remark               string `json:"remark"`
	Enable               bool   `json:"enable"`
	ExpiryTime           int64  `json:"expiryTime"`
	TrafficReset         string `json:"trafficReset"`
	LastTrafficResetTime int64  `json:"lastTrafficResetTime"`
	Listen               string `json:"listen"`
	Port                 int    `json:"port"`
	Protocol             string `json:"protocol"`
	Settings             string `json:"settings"`
	StreamSettings       string `json:"streamSettings"`
	Tag                  string `json:"tag"`
	Sniffing             string `json:"sniffing"`
}

// Getters & Setters for UIInbound
func (i *UIInbound) GetID() int { return i.ID }
func (i *UIInbound) SetID(v int) { i.ID = v }
func (i *UIInbound) GetTag() string { return i.Tag }
func (i *UIInbound) SetTag(v string) { i.Tag = v }

// UIOutboundTraffics tracks traffic stats for outbounds.
type UIOutboundTraffics struct {
	ID    int    `json:"id"`
	Tag   string `json:"tag"`
	Up    int64  `json:"up"`
	Down  int64  `json:"down"`
	Total int64  `json:"total"`
}

// UIInboundClientIps stores IP addresses for access control.
type UIInboundClientIps struct {
	ID          int    `json:"id"`
	ClientEmail string `json:"clientEmail"`
	Ips         string `json:"ips"`
}

// UISetting stores key-value configuration.
type UISetting struct {
	ID    int    `json:"id"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// UIClient represents client configuration for Xray inbounds.
type UIClient struct {
	ID         string `json:"id"`
	Security   string `json:"security"`
	Password   string `json:"password"`
	Flow       string `json:"flow"`
	Email      string `json:"email"`
	LimitIP    int    `json:"limitIp"`
	TotalGB    int64  `json:"totalGB"`
	ExpiryTime int64  `json:"expiryTime"`
	Enable     bool   `json:"enable"`
	TgID       int64  `json:"tgId"`
	SubID      string `json:"subId"`
	Comment    string `json:"comment"`
	Reset      int    `json:"reset"`
	CreatedAt  int64  `json:"created_at,omitempty"`
	UpdatedAt  int64  `json:"updated_at,omitempty"`
}

func (i *UIInbound) BuildDebugString() string {
	return fmt.Sprintf("inbound-%d-tag-%s-port-%d", i.ID, i.Tag, i.Port)
}

// Getters & Setters for UIInbound
func (i *UIInbound) GetUserID() int { return i.UserID }
func (i *UIInbound) SetUserID(v int) { i.UserID = v }
func (i *UIInbound) GetPort() int { return i.Port }
func (i *UIInbound) SetPort(v int) { i.Port = v }
func (i *UIInbound) GetProtocol() string { return i.Protocol }
func (i *UIInbound) SetProtocol(v string) { i.Protocol = v }
func (i *UIInbound) GetEnable() bool { return i.Enable }
func (i *UIInbound) SetEnable(v bool) { i.Enable = v }

// Getters & Setters for UISetting
func (s *UISetting) GetID() int { return s.ID }
func (s *UISetting) SetID(v int) { s.ID = v }
func (s *UISetting) GetKey() string { return s.Key }
func (s *UISetting) SetKey(v string) { s.Key = v }
func (s *UISetting) GetValue() string { return s.Value }
func (s *UISetting) SetValue(v string) { s.Value = v }

// Getters & Setters for UIClient
func (c *UIClient) GetID() string { return c.ID }
func (c *UIClient) SetID(v string) { c.ID = v }
func (c *UIClient) GetEmail() string { return c.Email }
func (c *UIClient) SetEmail(v string) { c.Email = v }
func (c *UIClient) GetEnable() bool { return c.Enable }
func (c *UIClient) SetEnable(v bool) { c.Enable = v }
func (c *UIClient) GetSecurity() string { return c.Security }
func (c *UIClient) SetSecurity(v string) { c.Security = v }
func (c *UIClient) GetPassword() string { return c.Password }
func (c *UIClient) SetPassword(v string) { c.Password = v }
func (c *UIClient) GetFlow() string { return c.Flow }
func (c *UIClient) SetFlow(v string) { c.Flow = v }
func (c *UIClient) GetLimitIP() int { return c.LimitIP }
func (c *UIClient) SetLimitIP(v int) { c.LimitIP = v }
func (c *UIClient) GetTotalGB() int64 { return c.TotalGB }
func (c *UIClient) SetTotalGB(v int64) { c.TotalGB = v }
func (c *UIClient) GetExpiryTime() int64 { return c.ExpiryTime }
func (c *UIClient) SetExpiryTime(v int64) { c.ExpiryTime = v }
func (c *UIClient) GetTgID() int64 { return c.TgID }
func (c *UIClient) SetTgID(v int64) { c.TgID = v }
func (c *UIClient) GetSubID() string { return c.SubID }
func (c *UIClient) SetSubID(v string) { c.SubID = v }
func (c *UIClient) GetComment() string { return c.Comment }
func (c *UIClient) SetComment(v string) { c.Comment = v }
func (c *UIClient) GetReset() int { return c.Reset }
func (c *UIClient) SetReset(v int) { c.Reset = v }

// Additional getters & setters for UIInbound
func (i *UIInbound) GetUp() int64 { return i.Up }
func (i *UIInbound) SetUp(v int64) { i.Up = v }
func (i *UIInbound) GetDown() int64 { return i.Down }
func (i *UIInbound) SetDown(v int64) { i.Down = v }
func (i *UIInbound) GetTotal() int64 { return i.Total }
func (i *UIInbound) SetTotal(v int64) { i.Total = v }
func (i *UIInbound) GetAllTime() int64 { return i.AllTime }
func (i *UIInbound) SetAllTime(v int64) { i.AllTime = v }
func (i *UIInbound) GetRemark() string { return i.Remark }
func (i *UIInbound) SetRemark(v string) { i.Remark = v }
func (i *UIInbound) GetExpiryTime() int64 { return i.ExpiryTime }
func (i *UIInbound) SetExpiryTime(v int64) { i.ExpiryTime = v }
func (i *UIInbound) GetTrafficReset() string { return i.TrafficReset }
func (i *UIInbound) SetTrafficReset(v string) { i.TrafficReset = v }
func (i *UIInbound) GetLastTrafficResetTime() int64 { return i.LastTrafficResetTime }
func (i *UIInbound) SetLastTrafficResetTime(v int64) { i.LastTrafficResetTime = v }
func (i *UIInbound) GetListen() string { return i.Listen }
func (i *UIInbound) SetListen(v string) { i.Listen = v }
func (i *UIInbound) GetSettings() string { return i.Settings }
func (i *UIInbound) SetSettings(v string) { i.Settings = v }
func (i *UIInbound) GetStreamSettings() string { return i.StreamSettings }
func (i *UIInbound) SetStreamSettings(v string) { i.StreamSettings = v }
func (i *UIInbound) GetSniffing() string { return i.Sniffing }
func (i *UIInbound) SetSniffing(v string) { i.Sniffing = v }

// Additional getters & setters for UIOutboundTraffics
func (o *UIOutboundTraffics) GetID() int { return o.ID }
func (o *UIOutboundTraffics) SetID(v int) { o.ID = v }
func (o *UIOutboundTraffics) GetTag() string { return o.Tag }
func (o *UIOutboundTraffics) SetTag(v string) { o.Tag = v }
func (o *UIOutboundTraffics) GetUp() int64 { return o.Up }
func (o *UIOutboundTraffics) SetUp(v int64) { o.Up = v }
func (o *UIOutboundTraffics) GetDown() int64 { return o.Down }
func (o *UIOutboundTraffics) SetDown(v int64) { o.Down = v }
func (o *UIOutboundTraffics) GetTotal() int64 { return o.Total }
func (o *UIOutboundTraffics) SetTotal(v int64) { o.Total = v }

// Additional getters & setters for UIInboundClientIps
func (ip *UIInboundClientIps) GetID() int { return ip.ID }
func (ip *UIInboundClientIps) SetID(v int) { ip.ID = v }
func (ip *UIInboundClientIps) GetClientEmail() string { return ip.ClientEmail }
func (ip *UIInboundClientIps) SetClientEmail(v string) { ip.ClientEmail = v }
func (ip *UIInboundClientIps) GetIps() string { return ip.Ips }
func (ip *UIInboundClientIps) SetIps(v string) { ip.Ips = v }

// Additional getters & setters for UIClient time trackers
func (c *UIClient) GetCreatedAt() int64 { return c.CreatedAt }
func (c *UIClient) SetCreatedAt(v int64) { c.CreatedAt = v }
func (c *UIClient) GetUpdatedAt() int64 { return c.UpdatedAt }
func (c *UIClient) SetUpdatedAt(v int64) { c.UpdatedAt = v }

// Additional getters & setters for UIUser password
func (u *UIUser) GetPassword() string { return u.Password }
func (u *UIUser) SetPassword(v string) { u.Password = v }
