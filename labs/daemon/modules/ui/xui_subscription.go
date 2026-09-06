// Package ui implements xui subscription page models ported from 3x-ui-main.
// Source: 3x-ui-main/sub/subService.go (PageData, ResolveRequest, BuildURLs, BuildPageData, genRemark helpers)
// Target: server/internal/ui/xui_subscription.go

package ui

import (
	"fmt"
	"strings"
)

// XuiPageData is the view model for subscription info pages.
// Source: sub/subService.go PageData struct
type XuiPageData struct {
	Host          string
	BasePath      string
	SID           string
	Download      string
	Upload        string
	Total         string
	Used          string
	Remained      string
	Expire        int64
	LastOnline    int64
	Datepicker    string
	DownloadByte  int64
	UploadByte    int64
	TotalByte     int64
	SubURL        string
	SubJSONURL    string
	Result        []string
}

func (p *XuiPageData) GetHost() string          { return p.Host }
func (p *XuiPageData) SetHost(v string)         { p.Host = v }
func (p *XuiPageData) GetBasePath() string       { return p.BasePath }
func (p *XuiPageData) SetBasePath(v string)      { p.BasePath = v }
func (p *XuiPageData) GetSID() string            { return p.SID }
func (p *XuiPageData) SetSID(v string)           { p.SID = v }
func (p *XuiPageData) GetDownload() string       { return p.Download }
func (p *XuiPageData) SetDownload(v string)      { p.Download = v }
func (p *XuiPageData) GetUpload() string         { return p.Upload }
func (p *XuiPageData) SetUpload(v string)        { p.Upload = v }
func (p *XuiPageData) GetTotal() string          { return p.Total }
func (p *XuiPageData) SetTotal(v string)         { p.Total = v }
func (p *XuiPageData) GetUsed() string           { return p.Used }
func (p *XuiPageData) SetUsed(v string)          { p.Used = v }
func (p *XuiPageData) GetRemained() string       { return p.Remained }
func (p *XuiPageData) SetRemained(v string)      { p.Remained = v }
func (p *XuiPageData) GetExpire() int64          { return p.Expire }
func (p *XuiPageData) SetExpire(v int64)         { p.Expire = v }
func (p *XuiPageData) GetLastOnline() int64      { return p.LastOnline }
func (p *XuiPageData) SetLastOnline(v int64)     { p.LastOnline = v }
func (p *XuiPageData) GetDatepicker() string     { return p.Datepicker }
func (p *XuiPageData) SetDatepicker(v string)    { p.Datepicker = v }
func (p *XuiPageData) GetDownloadByte() int64    { return p.DownloadByte }
func (p *XuiPageData) SetDownloadByte(v int64)   { p.DownloadByte = v }
func (p *XuiPageData) GetUploadByte() int64      { return p.UploadByte }
func (p *XuiPageData) SetUploadByte(v int64)     { p.UploadByte = v }
func (p *XuiPageData) GetTotalByte() int64       { return p.TotalByte }
func (p *XuiPageData) SetTotalByte(v int64)      { p.TotalByte = v }
func (p *XuiPageData) GetSubURL() string         { return p.SubURL }
func (p *XuiPageData) SetSubURL(v string)        { p.SubURL = v }
func (p *XuiPageData) GetSubJSONURL() string     { return p.SubJSONURL }
func (p *XuiPageData) SetSubJSONURL(v string)    { p.SubJSONURL = v }
func (p *XuiPageData) GetResult() []string       { return p.Result }
func (p *XuiPageData) SetResult(v []string)      { p.Result = v }

// XuiTrafficSummary holds aggregated traffic stats for a subscription.
// Source: sub/subService.go GetSubs aggregation loop
type XuiTrafficSummary struct {
	Up         int64
	Down       int64
	Total      int64
	ExpiryTime int64
	LastOnline int64
}

func (t *XuiTrafficSummary) GetUp() int64           { return t.Up }
func (t *XuiTrafficSummary) SetUp(v int64)          { t.Up = v }
func (t *XuiTrafficSummary) GetDown() int64         { return t.Down }
func (t *XuiTrafficSummary) SetDown(v int64)        { t.Down = v }
func (t *XuiTrafficSummary) GetTotal() int64        { return t.Total }
func (t *XuiTrafficSummary) SetTotal(v int64)       { t.Total = v }
func (t *XuiTrafficSummary) GetExpiryTime() int64   { return t.ExpiryTime }
func (t *XuiTrafficSummary) SetExpiryTime(v int64)  { t.ExpiryTime = v }
func (t *XuiTrafficSummary) GetLastOnline() int64   { return t.LastOnline }
func (t *XuiTrafficSummary) SetLastOnline(v int64)  { t.LastOnline = v }

// MergeXuiTrafficSummary adds a second traffic record into the first.
// Source: sub/subService.go GetSubs aggregation loop.
func MergeXuiTrafficSummary(acc *XuiTrafficSummary, next *XuiTrafficSummary) {
	acc.Up += next.Up
	acc.Down += next.Down
	if acc.Total == 0 || next.Total == 0 {
		acc.Total = 0
	} else {
		acc.Total += next.Total
	}
	if next.ExpiryTime != acc.ExpiryTime {
		acc.ExpiryTime = 0
	}
	if next.LastOnline > acc.LastOnline {
		acc.LastOnline = next.LastOnline
	}
}

// XuiRemarkConfig configures how subscription link remarks are generated.
// Source: sub/subService.go genRemark + SubService.remarkModel / showInfo
type XuiRemarkConfig struct {
	// SeparationChar is the separator between remark parts (first char of remarkModel).
	SeparationChar string
	// OrderChars defines the order of remark components: 'i'=inbound, 'e'=email, 'o'=extra.
	OrderChars string
	// ShowInfo controls whether traffic/expiry stats are appended to the remark.
	ShowInfo bool
	// Datepicker is "gregorian" or "jalali".
	Datepicker string
}

func (r *XuiRemarkConfig) GetSeparationChar() string  { return r.SeparationChar }
func (r *XuiRemarkConfig) SetSeparationChar(v string) { r.SeparationChar = v }
func (r *XuiRemarkConfig) GetOrderChars() string      { return r.OrderChars }
func (r *XuiRemarkConfig) SetOrderChars(v string)     { r.OrderChars = v }
func (r *XuiRemarkConfig) GetShowInfo() bool           { return r.ShowInfo }
func (r *XuiRemarkConfig) SetShowInfo(v bool)          { r.ShowInfo = v }
func (r *XuiRemarkConfig) GetDatepicker() string       { return r.Datepicker }
func (r *XuiRemarkConfig) SetDatepicker(v string)      { r.Datepicker = v }

// XuiLinkStreamParams holds the generic stream-level URI query parameters.
// Source: sub/subService.go params map
type XuiLinkStreamParams struct {
	Type          string // network type: tcp, ws, grpc, httpupgrade, xhttp, kcp, quic
	Security      string // tls, reality, none
	Path          string
	Host          string
	HeaderType    string
	Seed          string
	QuicSecurity  string
	QuicKey       string
	ServiceName   string
	Authority     string
	Mode          string
	ALPN          string
	SNI           string
	Fingerprint   string
	AllowInsecure string
	Flow          string
	PBK           string
	SID           string
	PQV           string
	SPX           string
	Encryption    string
}

func (p *XuiLinkStreamParams) GetType() string          { return p.Type }
func (p *XuiLinkStreamParams) SetType(v string)         { p.Type = v }
func (p *XuiLinkStreamParams) GetSecurity() string      { return p.Security }
func (p *XuiLinkStreamParams) SetSecurity(v string)     { p.Security = v }
func (p *XuiLinkStreamParams) GetPath() string          { return p.Path }
func (p *XuiLinkStreamParams) SetPath(v string)         { p.Path = v }
func (p *XuiLinkStreamParams) GetHost() string          { return p.Host }
func (p *XuiLinkStreamParams) SetHost(v string)         { p.Host = v }
func (p *XuiLinkStreamParams) GetHeaderType() string    { return p.HeaderType }
func (p *XuiLinkStreamParams) SetHeaderType(v string)   { p.HeaderType = v }
func (p *XuiLinkStreamParams) GetSeed() string          { return p.Seed }
func (p *XuiLinkStreamParams) SetSeed(v string)         { p.Seed = v }
func (p *XuiLinkStreamParams) GetQuicSecurity() string  { return p.QuicSecurity }
func (p *XuiLinkStreamParams) SetQuicSecurity(v string) { p.QuicSecurity = v }
func (p *XuiLinkStreamParams) GetServiceName() string   { return p.ServiceName }
func (p *XuiLinkStreamParams) SetServiceName(v string)  { p.ServiceName = v }
func (p *XuiLinkStreamParams) GetAuthority() string     { return p.Authority }
func (p *XuiLinkStreamParams) SetAuthority(v string)    { p.Authority = v }
func (p *XuiLinkStreamParams) GetMode() string          { return p.Mode }
func (p *XuiLinkStreamParams) SetMode(v string)         { p.Mode = v }
func (p *XuiLinkStreamParams) GetALPN() string          { return p.ALPN }
func (p *XuiLinkStreamParams) SetALPN(v string)         { p.ALPN = v }
func (p *XuiLinkStreamParams) GetSNI() string           { return p.SNI }
func (p *XuiLinkStreamParams) SetSNI(v string)          { p.SNI = v }
func (p *XuiLinkStreamParams) GetFingerprint() string   { return p.Fingerprint }
func (p *XuiLinkStreamParams) SetFingerprint(v string)  { p.Fingerprint = v }
func (p *XuiLinkStreamParams) GetFlow() string          { return p.Flow }
func (p *XuiLinkStreamParams) SetFlow(v string)         { p.Flow = v }
func (p *XuiLinkStreamParams) GetPBK() string           { return p.PBK }
func (p *XuiLinkStreamParams) SetPBK(v string)          { p.PBK = v }
func (p *XuiLinkStreamParams) GetSID() string           { return p.SID }
func (p *XuiLinkStreamParams) SetSID(v string)          { p.SID = v }
func (p *XuiLinkStreamParams) GetPQV() string           { return p.PQV }
func (p *XuiLinkStreamParams) SetPQV(v string)          { p.PQV = v }
func (p *XuiLinkStreamParams) GetSPX() string           { return p.SPX }
func (p *XuiLinkStreamParams) SetSPX(v string)          { p.SPX = v }
func (p *XuiLinkStreamParams) GetEncryption() string    { return p.Encryption }
func (p *XuiLinkStreamParams) SetEncryption(v string)   { p.Encryption = v }

// XuiSubURLBuilder constructs subscription and JSON URL strings.
// Source: sub/subService.go BuildURLs, buildSingleURL, joinPathWithID
type XuiSubURLBuilder struct {
	ConfiguredSubURI     string
	ConfiguredSubJSONURI string
}

func (b *XuiSubURLBuilder) GetConfiguredSubURI() string        { return b.ConfiguredSubURI }
func (b *XuiSubURLBuilder) SetConfiguredSubURI(v string)       { b.ConfiguredSubURI = v }
func (b *XuiSubURLBuilder) GetConfiguredSubJSONURI() string    { return b.ConfiguredSubJSONURI }
func (b *XuiSubURLBuilder) SetConfiguredSubJSONURI(v string)   { b.ConfiguredSubJSONURI = v }

// Build constructs the subscription and JSON subscription URLs for a given sub ID.
// Source: sub/subService.go BuildURLs
func (b *XuiSubURLBuilder) Build(scheme, hostWithPort, subPath, subJSONPath, subID string) (subURL, subJSONURL string) {
	if subID == "" {
		return "", ""
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, hostWithPort)
	if b.ConfiguredSubURI != "" {
		subURL = xuiJoinPathWithID(b.ConfiguredSubURI, subID)
	} else {
		subURL = xuiJoinPathWithID(baseURL+subPath, subID)
	}
	if b.ConfiguredSubJSONURI != "" {
		subJSONURL = xuiJoinPathWithID(b.ConfiguredSubJSONURI, subID)
	} else {
		subJSONURL = xuiJoinPathWithID(baseURL+subJSONPath, subID)
	}
	return subURL, subJSONURL
}

// xuiJoinPathWithID safely concatenates a base path with a subscription ID.
// Source: sub/subService.go joinPathWithID
func xuiJoinPathWithID(basePath, subID string) string {
	if strings.HasSuffix(basePath, "/") {
		return basePath + subID
	}
	return basePath + "/" + subID
}
