// Package ui implements AmneziaWG tunnel models ported from 3ax-ui-main.
// Source: 3ax-ui-main/database/model/awg.go
// Target: server/internal/ui/amnezia_wg_model.go

package ui

// AwgServer stores AmneziaWG server interface configuration.
// Source: 3ax-ui-main/database/model/awg.go AwgServer
type AwgServer struct {
	ID            int
	Enable        bool
	InterfaceName string
	ListenPort    int
	MTU           int

	// Server keys
	PrivateKey string
	PublicKey  string

	// IPv4 tunnel network
	IPv4Address string
	IPv4Pool    string

	// IPv6 - native public addresses
	IPv6Enabled bool
	IPv6Address string
	IPv6Pool    string
	IPv6Gateway string

	// AmneziaWG 1.x obfuscation core parameters (Jc/Jmin/Jmax/S1/S2/H1–H4)
	Jc   int
	Jmin int
	Jmax int
	S1   int
	S2   int

	// AmneziaWG 2.0 additional obfuscation parameters (S3/S4/I1)
	// S3/S4 add padding to cookie/transport packets;
	// I1 is a CPS signature packet sent before handshakes.
	// H1-H4 are stored as strings: "1" for 1.x single values, "100000-800000" for 2.0 ranges.
	S3 int
	S4 int
	H1 string
	H2 string
	H3 string
	H4 string
	I1 string

	// DNS pushed to clients, split by address family
	DnsIPv4 string
	DnsIPv6 string

	// External interface for NAT (IPv4)
	ExternalInterface string

	// External interface for NDP proxy / IPv6 forwarding
	IPv6ExternalInterface string

	// PostUp/PostDown scripts (auto-generated but overridable)
	PostUp   string
	PostDown string

	// Endpoint that clients connect to (server public IP/domain)
	Endpoint string

	// Periodic traffic reset: "never", "daily", "weekly", "monthly"
	TrafficReset string

	// Route tunnel traffic into Xray via a dokodemo-door TPROXY inbound.
	RouteViaXray   bool
	XrayInboundTag string
	XrayTproxyPort int

	CreatedAt int64
	UpdatedAt int64
}

func (s *AwgServer) GetID() int                   { return s.ID }
func (s *AwgServer) SetID(v int)                  { s.ID = v }
func (s *AwgServer) GetEnable() bool              { return s.Enable }
func (s *AwgServer) SetEnable(v bool)             { s.Enable = v }
func (s *AwgServer) GetInterfaceName() string     { return s.InterfaceName }
func (s *AwgServer) SetInterfaceName(v string)    { s.InterfaceName = v }
func (s *AwgServer) GetListenPort() int           { return s.ListenPort }
func (s *AwgServer) SetListenPort(v int)          { s.ListenPort = v }
func (s *AwgServer) GetMTU() int                  { return s.MTU }
func (s *AwgServer) SetMTU(v int)                 { s.MTU = v }
func (s *AwgServer) GetPrivateKey() string        { return s.PrivateKey }
func (s *AwgServer) SetPrivateKey(v string)       { s.PrivateKey = v }
func (s *AwgServer) GetPublicKey() string         { return s.PublicKey }
func (s *AwgServer) SetPublicKey(v string)        { s.PublicKey = v }
func (s *AwgServer) GetIPv4Address() string       { return s.IPv4Address }
func (s *AwgServer) SetIPv4Address(v string)      { s.IPv4Address = v }
func (s *AwgServer) GetIPv4Pool() string          { return s.IPv4Pool }
func (s *AwgServer) SetIPv4Pool(v string)         { s.IPv4Pool = v }
func (s *AwgServer) GetIPv6Enabled() bool         { return s.IPv6Enabled }
func (s *AwgServer) SetIPv6Enabled(v bool)        { s.IPv6Enabled = v }
func (s *AwgServer) GetIPv6Address() string       { return s.IPv6Address }
func (s *AwgServer) SetIPv6Address(v string)      { s.IPv6Address = v }
func (s *AwgServer) GetIPv6Pool() string          { return s.IPv6Pool }
func (s *AwgServer) SetIPv6Pool(v string)         { s.IPv6Pool = v }
func (s *AwgServer) GetIPv6Gateway() string       { return s.IPv6Gateway }
func (s *AwgServer) SetIPv6Gateway(v string)      { s.IPv6Gateway = v }
func (s *AwgServer) GetJc() int                   { return s.Jc }
func (s *AwgServer) SetJc(v int)                  { s.Jc = v }
func (s *AwgServer) GetJmin() int                 { return s.Jmin }
func (s *AwgServer) SetJmin(v int)                { s.Jmin = v }
func (s *AwgServer) GetJmax() int                 { return s.Jmax }
func (s *AwgServer) SetJmax(v int)                { s.Jmax = v }
func (s *AwgServer) GetS1() int                   { return s.S1 }
func (s *AwgServer) SetS1(v int)                  { s.S1 = v }
func (s *AwgServer) GetS2() int                   { return s.S2 }
func (s *AwgServer) SetS2(v int)                  { s.S2 = v }
func (s *AwgServer) GetS3() int                   { return s.S3 }
func (s *AwgServer) SetS3(v int)                  { s.S3 = v }
func (s *AwgServer) GetS4() int                   { return s.S4 }
func (s *AwgServer) SetS4(v int)                  { s.S4 = v }
func (s *AwgServer) GetH1() string                { return s.H1 }
func (s *AwgServer) SetH1(v string)               { s.H1 = v }
func (s *AwgServer) GetH2() string                { return s.H2 }
func (s *AwgServer) SetH2(v string)               { s.H2 = v }
func (s *AwgServer) GetH3() string                { return s.H3 }
func (s *AwgServer) SetH3(v string)               { s.H3 = v }
func (s *AwgServer) GetH4() string                { return s.H4 }
func (s *AwgServer) SetH4(v string)               { s.H4 = v }
func (s *AwgServer) GetI1() string                { return s.I1 }
func (s *AwgServer) SetI1(v string)               { s.I1 = v }
func (s *AwgServer) GetDnsIPv4() string           { return s.DnsIPv4 }
func (s *AwgServer) SetDnsIPv4(v string)          { s.DnsIPv4 = v }
func (s *AwgServer) GetDnsIPv6() string           { return s.DnsIPv6 }
func (s *AwgServer) SetDnsIPv6(v string)          { s.DnsIPv6 = v }
func (s *AwgServer) GetExternalInterface() string { return s.ExternalInterface }
func (s *AwgServer) SetExternalInterface(v string){ s.ExternalInterface = v }
func (s *AwgServer) GetPostUp() string            { return s.PostUp }
func (s *AwgServer) SetPostUp(v string)           { s.PostUp = v }
func (s *AwgServer) GetPostDown() string          { return s.PostDown }
func (s *AwgServer) SetPostDown(v string)         { s.PostDown = v }
func (s *AwgServer) GetEndpoint() string          { return s.Endpoint }
func (s *AwgServer) SetEndpoint(v string)         { s.Endpoint = v }
func (s *AwgServer) GetTrafficReset() string      { return s.TrafficReset }
func (s *AwgServer) SetTrafficReset(v string)     { s.TrafficReset = v }
func (s *AwgServer) GetRouteViaXray() bool        { return s.RouteViaXray }
func (s *AwgServer) SetRouteViaXray(v bool)       { s.RouteViaXray = v }
func (s *AwgServer) GetXrayInboundTag() string    { return s.XrayInboundTag }
func (s *AwgServer) SetXrayInboundTag(v string)   { s.XrayInboundTag = v }
func (s *AwgServer) GetXrayTproxyPort() int       { return s.XrayTproxyPort }
func (s *AwgServer) SetXrayTproxyPort(v int)      { s.XrayTproxyPort = v }
func (s *AwgServer) GetCreatedAt() int64          { return s.CreatedAt }
func (s *AwgServer) GetUpdatedAt() int64          { return s.UpdatedAt }

// NewDefaultAwgServer returns an AwgServer with upstream defaults from awg.go.
// Source: 3ax-ui-main/database/model/awg.go GORM default tags.
func NewDefaultAwgServer() *AwgServer {
	return &AwgServer{
		Enable:         false,
		InterfaceName:  "awg0",
		ListenPort:     51820,
		MTU:            1420,
		IPv4Address:    "10.66.66.1/24",
		IPv4Pool:       "10.66.66.0/24",
		IPv6Enabled:    false,
		Jc:             4,
		Jmin:           50,
		Jmax:           1000,
		S1:             0,
		S2:             0,
		S3:             0,
		S4:             0,
		H1:             "1",
		H2:             "2",
		H3:             "3",
		H4:             "4",
		I1:             "",
		DnsIPv4:        "1.1.1.1",
		DnsIPv6:        "2606:4700:4700::1111",
		ExternalInterface: "",
		TrafficReset:   "never",
		RouteViaXray:   false,
		XrayInboundTag: "awg-tproxy-in",
		XrayTproxyPort: 12345,
	}
}

// AwgClient stores an AmneziaWG client (peer) configuration.
// Source: 3ax-ui-main/database/model/awg.go AwgClient
type AwgClient struct {
	ID       int
	ServerID int
	UUID     string
	Name     string
	Email    string
	Enable   bool
	Comment  string

	// Client keys
	PrivateKey   string
	PublicKey    string
	PresharedKey string

	// Allocated addresses
	IPv4Address string
	IPv6Address string

	// AllowedIPs on server side (routes to this client)
	AllowedIPs string

	// AllowedIPs on client side (routes through tunnel)
	ClientAllowedIPs string

	// Port forwarding: comma/semicolon-separated ports or ranges (e.g. "8000-8100")
	ForwardedPorts string

	PersistentKeepalive int

	// Traffic stats
	Upload   int64
	Download int64
	TotalGB  int64
	AllTime  int64

	// Internal baseline counters (not serialised)
	LastPeerUp   int64
	LastPeerDown int64

	ExpiryTime int64
	Reset      int

	LimitIP    int
	TgID       int64
	LastOnline int64
	LastIP     string

	CreatedAt int64
	UpdatedAt int64
}

func (c *AwgClient) GetID() int                        { return c.ID }
func (c *AwgClient) SetID(v int)                       { c.ID = v }
func (c *AwgClient) GetServerID() int                  { return c.ServerID }
func (c *AwgClient) SetServerID(v int)                 { c.ServerID = v }
func (c *AwgClient) GetUUID() string                   { return c.UUID }
func (c *AwgClient) SetUUID(v string)                  { c.UUID = v }
func (c *AwgClient) GetName() string                   { return c.Name }
func (c *AwgClient) SetName(v string)                  { c.Name = v }
func (c *AwgClient) GetEmail() string                  { return c.Email }
func (c *AwgClient) SetEmail(v string)                 { c.Email = v }
func (c *AwgClient) GetEnable() bool                   { return c.Enable }
func (c *AwgClient) SetEnable(v bool)                  { c.Enable = v }
func (c *AwgClient) GetComment() string                { return c.Comment }
func (c *AwgClient) SetComment(v string)               { c.Comment = v }
func (c *AwgClient) GetPrivateKey() string             { return c.PrivateKey }
func (c *AwgClient) SetPrivateKey(v string)            { c.PrivateKey = v }
func (c *AwgClient) GetPublicKey() string              { return c.PublicKey }
func (c *AwgClient) SetPublicKey(v string)             { c.PublicKey = v }
func (c *AwgClient) GetPresharedKey() string           { return c.PresharedKey }
func (c *AwgClient) SetPresharedKey(v string)          { c.PresharedKey = v }
func (c *AwgClient) GetIPv4Address() string            { return c.IPv4Address }
func (c *AwgClient) SetIPv4Address(v string)           { c.IPv4Address = v }
func (c *AwgClient) GetIPv6Address() string            { return c.IPv6Address }
func (c *AwgClient) SetIPv6Address(v string)           { c.IPv6Address = v }
func (c *AwgClient) GetAllowedIPs() string             { return c.AllowedIPs }
func (c *AwgClient) SetAllowedIPs(v string)            { c.AllowedIPs = v }
func (c *AwgClient) GetClientAllowedIPs() string       { return c.ClientAllowedIPs }
func (c *AwgClient) SetClientAllowedIPs(v string)      { c.ClientAllowedIPs = v }
func (c *AwgClient) GetForwardedPorts() string         { return c.ForwardedPorts }
func (c *AwgClient) SetForwardedPorts(v string)        { c.ForwardedPorts = v }
func (c *AwgClient) GetPersistentKeepalive() int       { return c.PersistentKeepalive }
func (c *AwgClient) SetPersistentKeepalive(v int)      { c.PersistentKeepalive = v }
func (c *AwgClient) GetUpload() int64                  { return c.Upload }
func (c *AwgClient) SetUpload(v int64)                 { c.Upload = v }
func (c *AwgClient) GetDownload() int64                { return c.Download }
func (c *AwgClient) SetDownload(v int64)               { c.Download = v }
func (c *AwgClient) GetTotalGB() int64                 { return c.TotalGB }
func (c *AwgClient) SetTotalGB(v int64)                { c.TotalGB = v }
func (c *AwgClient) GetAllTime() int64                 { return c.AllTime }
func (c *AwgClient) SetAllTime(v int64)                { c.AllTime = v }
func (c *AwgClient) GetExpiryTime() int64              { return c.ExpiryTime }
func (c *AwgClient) SetExpiryTime(v int64)             { c.ExpiryTime = v }
func (c *AwgClient) GetReset() int                     { return c.Reset }
func (c *AwgClient) SetReset(v int)                    { c.Reset = v }
func (c *AwgClient) GetLimitIP() int                   { return c.LimitIP }
func (c *AwgClient) SetLimitIP(v int)                  { c.LimitIP = v }
func (c *AwgClient) GetTgID() int64                    { return c.TgID }
func (c *AwgClient) SetTgID(v int64)                   { c.TgID = v }
func (c *AwgClient) GetLastOnline() int64              { return c.LastOnline }
func (c *AwgClient) SetLastOnline(v int64)             { c.LastOnline = v }
func (c *AwgClient) GetLastIP() string                 { return c.LastIP }
func (c *AwgClient) SetLastIP(v string)                { c.LastIP = v }
func (c *AwgClient) GetCreatedAt() int64               { return c.CreatedAt }
func (c *AwgClient) GetUpdatedAt() int64               { return c.UpdatedAt }
