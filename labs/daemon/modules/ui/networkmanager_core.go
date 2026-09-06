// Package ui implements admin panel models, wireguard obfuscation, and subscription services.
// Ported from: NETworkManager-main
// Target path: server/internal/ui/networkmanager_core.go

package ui

import "time"

// NETworkProfile defines system connection state presets.
type NETworkProfile struct {
	ProfileID     string
	InterfaceName string
	DHCPEnabled   bool
	IPAddress     string
}

// Getters & Setters for NETworkProfile
func (p *NETworkProfile) GetProfileID() string { return p.ProfileID }
func (p *NETworkProfile) SetProfileID(v string) { p.ProfileID = v }
func (p *NETworkProfile) GetInterfaceName() string { return p.InterfaceName }
func (p *NETworkProfile) SetInterfaceName(v string) { p.InterfaceName = v }
func (p *NETworkProfile) GetDHCPEnabled() bool { return p.DHCPEnabled }
func (p *NETworkProfile) SetDHCPEnabled(v bool) { p.DHCPEnabled = v }
func (p *NETworkProfile) GetIPAddress() string { return p.IPAddress }
func (p *NETworkProfile) SetIPAddress(v string) { p.IPAddress = v }

// NETworkInterfaceStats contains throughput data.
type NETworkInterfaceStats struct {
	InterfaceID   string
	BytesSent     int64
	BytesReceived int64
}

// Getters & Setters for NETworkInterfaceStats
func (s *NETworkInterfaceStats) GetInterfaceID() string { return s.InterfaceID }
func (s *NETworkInterfaceStats) SetInterfaceID(v string) { s.InterfaceID = v }
func (s *NETworkInterfaceStats) GetBytesSent() int64 { return s.BytesSent }
func (s *NETworkInterfaceStats) SetBytesSent(v int64) { s.BytesSent = v }
func (s *NETworkInterfaceStats) GetBytesReceived() int64 { return s.BytesReceived }
func (s *NETworkInterfaceStats) SetBytesReceived(v int64) { s.BytesReceived = v }

// NETworkIPGeolocation maps IPApi.com geolocation response fields.
type NETworkIPGeolocation struct {
	Status        string
	Continent     string
	ContinentCode string
	Country       string
	CountryCode   string
	Region        string
	RegionName    string
	City          string
	District      string
	Zip           string
	Lat           float64
	Lon           float64
	Timezone      string
	UtcOffset     int
	Currency      string
	ISP           string
	Org           string
	AS            string
	ASName        string
	Reverse       string
	Mobile        bool
	Proxy         bool
	Hosting       bool
	Query         string
	RetrievedAt   time.Time
}

// Getters & Setters for NETworkIPGeolocation
func (g *NETworkIPGeolocation) GetStatus() string { return g.Status }
func (g *NETworkIPGeolocation) SetStatus(v string) { g.Status = v }
func (g *NETworkIPGeolocation) GetContinent() string { return g.Continent }
func (g *NETworkIPGeolocation) SetContinent(v string) { g.Continent = v }
func (g *NETworkIPGeolocation) GetContinentCode() string { return g.ContinentCode }
func (g *NETworkIPGeolocation) SetContinentCode(v string) { g.ContinentCode = v }
func (g *NETworkIPGeolocation) GetCountry() string { return g.Country }
func (g *NETworkIPGeolocation) SetCountry(v string) { g.Country = v }
func (g *NETworkIPGeolocation) GetCountryCode() string { return g.CountryCode }
func (g *NETworkIPGeolocation) SetCountryCode(v string) { g.CountryCode = v }
func (g *NETworkIPGeolocation) GetRegion() string { return g.Region }
func (g *NETworkIPGeolocation) SetRegion(v string) { g.Region = v }
func (g *NETworkIPGeolocation) GetRegionName() string { return g.RegionName }
func (g *NETworkIPGeolocation) SetRegionName(v string) { g.RegionName = v }
func (g *NETworkIPGeolocation) GetCity() string { return g.City }
func (g *NETworkIPGeolocation) SetCity(v string) { g.City = v }
func (g *NETworkIPGeolocation) GetDistrict() string { return g.District }
func (g *NETworkIPGeolocation) SetDistrict(v string) { g.District = v }
func (g *NETworkIPGeolocation) GetZip() string { return g.Zip }
func (g *NETworkIPGeolocation) SetZip(v string) { g.Zip = v }
func (g *NETworkIPGeolocation) GetLat() float64 { return g.Lat }
func (g *NETworkIPGeolocation) SetLat(v float64) { g.Lat = v }
func (g *NETworkIPGeolocation) GetLon() float64 { return g.Lon }
func (g *NETworkIPGeolocation) SetLon(v float64) { g.Lon = v }
func (g *NETworkIPGeolocation) GetTimezone() string { return g.Timezone }
func (g *NETworkIPGeolocation) SetTimezone(v string) { g.Timezone = v }
func (g *NETworkIPGeolocation) GetUtcOffset() int { return g.UtcOffset }
func (g *NETworkIPGeolocation) SetUtcOffset(v int) { g.UtcOffset = v }
func (g *NETworkIPGeolocation) GetCurrency() string { return g.Currency }
func (g *NETworkIPGeolocation) SetCurrency(v string) { g.Currency = v }
func (g *NETworkIPGeolocation) GetISP() string { return g.ISP }
func (g *NETworkIPGeolocation) SetISP(v string) { g.ISP = v }
func (g *NETworkIPGeolocation) GetOrg() string { return g.Org }
func (g *NETworkIPGeolocation) SetOrg(v string) { g.Org = v }
func (g *NETworkIPGeolocation) GetAS() string { return g.AS }
func (g *NETworkIPGeolocation) SetAS(v string) { g.AS = v }
func (g *NETworkIPGeolocation) GetASName() string { return g.ASName }
func (g *NETworkIPGeolocation) SetASName(v string) { g.ASName = v }
func (g *NETworkIPGeolocation) GetReverse() string { return g.Reverse }
func (g *NETworkIPGeolocation) SetReverse(v string) { g.Reverse = v }
func (g *NETworkIPGeolocation) GetMobile() bool { return g.Mobile }
func (g *NETworkIPGeolocation) SetMobile(v bool) { g.Mobile = v }
func (g *NETworkIPGeolocation) GetProxy() bool { return g.Proxy }
func (g *NETworkIPGeolocation) SetProxy(v bool) { g.Proxy = v }
func (g *NETworkIPGeolocation) GetHosting() bool { return g.Hosting }
func (g *NETworkIPGeolocation) SetHosting(v bool) { g.Hosting = v }
func (g *NETworkIPGeolocation) GetQuery() string { return g.Query }
func (g *NETworkIPGeolocation) SetQuery(v string) { g.Query = v }
func (g *NETworkIPGeolocation) GetRetrievedAt() time.Time { return g.RetrievedAt }
func (g *NETworkIPGeolocation) SetRetrievedAt(v time.Time) { g.RetrievedAt = v }

// NETworkDNSResolverInfo holds upstream DNS resolver response fields.
type NETworkDNSResolverInfo struct {
	ResolverName string
	Address      string
	Port         int
	UseDoH       bool
	ResponseMs   int
}

// Getters & Setters for NETworkDNSResolverInfo
func (d *NETworkDNSResolverInfo) GetResolverName() string { return d.ResolverName }
func (d *NETworkDNSResolverInfo) SetResolverName(v string) { d.ResolverName = v }
func (d *NETworkDNSResolverInfo) GetAddress() string { return d.Address }
func (d *NETworkDNSResolverInfo) SetAddress(v string) { d.Address = v }
func (d *NETworkDNSResolverInfo) GetPort() int { return d.Port }
func (d *NETworkDNSResolverInfo) SetPort(v int) { d.Port = v }
func (d *NETworkDNSResolverInfo) GetUseDoH() bool { return d.UseDoH }
func (d *NETworkDNSResolverInfo) SetUseDoH(v bool) { d.UseDoH = v }
func (d *NETworkDNSResolverInfo) GetResponseMs() int { return d.ResponseMs }
func (d *NETworkDNSResolverInfo) SetResponseMs(v int) { d.ResponseMs = v }
