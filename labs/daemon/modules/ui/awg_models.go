// Package ui implements admin panel models, wireguard obfuscation, and subscription services.
// Ported from: 3ax-ui-main (database/model/awg.go)
// Target path: server/internal/ui/awg_models.go

package ui

// UI_AwgServer stores AmneziaWG server interface configuration.
type UIAwgServer struct {
	ID                    int    `json:"id"`
	Enable                bool   `json:"enable"`
	InterfaceName         string `json:"interfaceName"`
	ListenPort            int    `json:"listenPort"`
	MTU                   int    `json:"mtu"`
	PrivateKey            string `json:"privateKey"`
	PublicKey             string `json:"publicKey"`
	IPv4Address           string `json:"ipv4Address"`
	IPv4Pool              string `json:"ipv4Pool"`
	IPv6Enabled           bool   `json:"ipv6Enabled"`
	IPv6Address           string `json:"ipv6Address"`
	IPv6Pool              string `json:"ipv6Pool"`
	IPv6Gateway           string `json:"ipv6Gateway"`
	Jc                    int    `json:"jc"`
	Jmin                  int    `json:"jmin"`
	Jmax                  int    `json:"jmax"`
	S1                    int    `json:"s1"`
	S2                    int    `json:"s2"`
	S3                    int    `json:"s3"`
	S4                    int    `json:"s4"`
	H1                    string `json:"h1"`
	H2                    string `json:"h2"`
	H3                    string `json:"h3"`
	H4                    string `json:"h4"`
	I1                    string `json:"i1"`
	DnsIpv4               string `json:"dnsIpv4"`
	DnsIpv6               string `json:"dnsIpv6"`
	ExternalInterface     string `json:"externalInterface"`
	IPv6ExternalInterface string `json:"ipv6ExternalInterface"`
	PostUp                string `json:"postUp"`
	PostDown              string `json:"postDown"`
	Endpoint              string `json:"endpoint"`
	TrafficReset          string `json:"trafficReset"`
	RouteViaXray          bool   `json:"routeViaXray"`
	XrayInboundTag        string `json:"xrayInboundTag"`
	XrayTproxyPort        int    `json:"xrayTproxyPort"`
	CreatedAt             int64  `json:"createdAt"`
	UpdatedAt             int64  `json:"updatedAt"`
}

// Getters & Setters for UIAwgServer
func (s *UIAwgServer) GetID() int { return s.ID }
func (s *UIAwgServer) SetID(v int) { s.ID = v }
func (s *UIAwgServer) GetInterfaceName() string { return s.InterfaceName }
func (s *UIAwgServer) SetInterfaceName(v string) { s.InterfaceName = v }
func (s *UIAwgServer) GetPrivateKey() string { return s.PrivateKey }
func (s *UIAwgServer) SetPrivateKey(v string) { s.PrivateKey = v }
func (s *UIAwgServer) GetEnable() bool { return s.Enable }
func (s *UIAwgServer) SetEnable(v bool) { s.Enable = v }
func (s *UIAwgServer) GetListenPort() int { return s.ListenPort }
func (s *UIAwgServer) SetListenPort(v int) { s.ListenPort = v }
func (s *UIAwgServer) GetMTU() int { return s.MTU }
func (s *UIAwgServer) SetMTU(v int) { s.MTU = v }
func (s *UIAwgServer) GetPublicKey() string { return s.PublicKey }
func (s *UIAwgServer) SetPublicKey(v string) { s.PublicKey = v }
func (s *UIAwgServer) GetIPv4Address() string { return s.IPv4Address }
func (s *UIAwgServer) SetIPv4Address(v string) { s.IPv4Address = v }
func (s *UIAwgServer) GetIPv6Enabled() bool { return s.IPv6Enabled }
func (s *UIAwgServer) SetIPv6Enabled(v bool) { s.IPv6Enabled = v }
func (s *UIAwgServer) GetJc() int { return s.Jc }
func (s *UIAwgServer) SetJc(v int) { s.Jc = v }
func (s *UIAwgServer) GetJmin() int { return s.Jmin }
func (s *UIAwgServer) SetJmin(v int) { s.Jmin = v }
func (s *UIAwgServer) GetJmax() int { return s.Jmax }
func (s *UIAwgServer) SetJmax(v int) { s.Jmax = v }
func (s *UIAwgServer) GetIPv4Pool() string { return s.IPv4Pool }
func (s *UIAwgServer) SetIPv4Pool(v string) { s.IPv4Pool = v }
func (s *UIAwgServer) GetIPv6Address() string { return s.IPv6Address }
func (s *UIAwgServer) SetIPv6Address(v string) { s.IPv6Address = v }
func (s *UIAwgServer) GetIPv6Pool() string { return s.IPv6Pool }
func (s *UIAwgServer) SetIPv6Pool(v string) { s.IPv6Pool = v }
func (s *UIAwgServer) GetIPv6Gateway() string { return s.IPv6Gateway }
func (s *UIAwgServer) SetIPv6Gateway(v string) { s.IPv6Gateway = v }
func (s *UIAwgServer) GetS1() int { return s.S1 }
func (s *UIAwgServer) SetS1(v int) { s.S1 = v }
func (s *UIAwgServer) GetS2() int { return s.S2 }
func (s *UIAwgServer) SetS2(v int) { s.S2 = v }
func (s *UIAwgServer) GetS3() int { return s.S3 }
func (s *UIAwgServer) SetS3(v int) { s.S3 = v }
func (s *UIAwgServer) GetS4() int { return s.S4 }
func (s *UIAwgServer) SetS4(v int) { s.S4 = v }
func (s *UIAwgServer) GetH1() string { return s.H1 }
func (s *UIAwgServer) SetH1(v string) { s.H1 = v }
func (s *UIAwgServer) GetH2() string { return s.H2 }
func (s *UIAwgServer) SetH2(v string) { s.H2 = v }
func (s *UIAwgServer) GetH3() string { return s.H3 }
func (s *UIAwgServer) SetH3(v string) { s.H3 = v }
func (s *UIAwgServer) GetH4() string { return s.H4 }
func (s *UIAwgServer) SetH4(v string) { s.H4 = v }
func (s *UIAwgServer) GetI1() string { return s.I1 }
func (s *UIAwgServer) SetI1(v string) { s.I1 = v }
func (s *UIAwgServer) GetDnsIpv4() string { return s.DnsIpv4 }
func (s *UIAwgServer) SetDnsIpv4(v string) { s.DnsIpv4 = v }
func (s *UIAwgServer) GetDnsIpv6() string { return s.DnsIpv6 }
func (s *UIAwgServer) SetDnsIpv6(v string) { s.DnsIpv6 = v }
func (s *UIAwgServer) GetExternalInterface() string { return s.ExternalInterface }
func (s *UIAwgServer) SetExternalInterface(v string) { s.ExternalInterface = v }
func (s *UIAwgServer) GetIPv6ExternalInterface() string { return s.IPv6ExternalInterface }
func (s *UIAwgServer) SetIPv6ExternalInterface(v string) { s.IPv6ExternalInterface = v }
func (s *UIAwgServer) GetPostUp() string { return s.PostUp }
func (s *UIAwgServer) SetPostUp(v string) { s.PostUp = v }
func (s *UIAwgServer) GetPostDown() string { return s.PostDown }
func (s *UIAwgServer) SetPostDown(v string) { s.PostDown = v }
func (s *UIAwgServer) GetEndpoint() string { return s.Endpoint }
func (s *UIAwgServer) SetEndpoint(v string) { s.Endpoint = v }
func (s *UIAwgServer) GetTrafficReset() string { return s.TrafficReset }
func (s *UIAwgServer) SetTrafficReset(v string) { s.TrafficReset = v }
func (s *UIAwgServer) GetRouteViaXray() bool { return s.RouteViaXray }
func (s *UIAwgServer) SetRouteViaXray(v bool) { s.RouteViaXray = v }
func (s *UIAwgServer) GetXrayInboundTag() string { return s.XrayInboundTag }
func (s *UIAwgServer) SetXrayInboundTag(v string) { s.XrayInboundTag = v }
func (s *UIAwgServer) GetXrayTproxyPort() int { return s.XrayTproxyPort }
func (s *UIAwgServer) SetXrayTproxyPort(v int) { s.XrayTproxyPort = v }

// UIAwgClient stores an AmneziaWG client (peer) configuration.
type UIAwgClient struct {
	ID                  int    `json:"id"`
	ServerID            int    `json:"serverId"`
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Email               string `json:"email"`
	Enable              bool   `json:"enable"`
	Comment             string `json:"comment"`
	PrivateKey          string `json:"privateKey"`
	PublicKey           string `json:"publicKey"`
	PresharedKey        string `json:"presharedKey"`
	IPv4Address         string `json:"ipv4Address"`
	IPv6Address         string `json:"ipv6Address"`
	AllowedIPs          string `json:"allowedIPs"`
	ClientAllowedIPs    string `json:"clientAllowedIPs"`
	ForwardedPorts      string `json:"forwardedPorts"`
	PersistentKeepalive int    `json:"persistentKeepalive"`
	Upload              int64  `json:"upload"`
	Download            int64  `json:"download"`
	TotalGB             int64  `json:"totalGB"`
	AllTime             int64  `json:"allTime"`
	LastPeerUp          int64  `json:"lastPeerUp"`
	LastPeerDown        int64  `json:"lastPeerDown"`
	ExpiryTime          int64  `json:"expiryTime"`
	Reset               int    `json:"reset"`
	LimitIp             int    `json:"limitIp"`
	TgID                int64  `json:"tgId"`
	LastOnline          int64  `json:"lastOnline"`
	LastIP              string `json:"lastIp"`
	CreatedAt           int64  `json:"createdAt"`
	UpdatedAt           int64  `json:"updatedAt"`
}

// Getters & Setters for UIAwgClient
func (c *UIAwgClient) GetID() int { return c.ID }
func (c *UIAwgClient) SetID(v int) { c.ID = v }
func (c *UIAwgClient) GetUUID() string { return c.UUID }
func (c *UIAwgClient) SetUUID(v string) { c.UUID = v }
func (c *UIAwgClient) GetEmail() string { return c.Email }
func (c *UIAwgClient) SetEmail(v string) { c.Email = v }
func (c *UIAwgClient) GetPublicKey() string { return c.PublicKey }
func (c *UIAwgClient) SetPublicKey(v string) { c.PublicKey = v }
func (c *UIAwgClient) GetServerID() int { return c.ServerID }
func (c *UIAwgClient) SetServerID(v int) { c.ServerID = v }
func (c *UIAwgClient) GetName() string { return c.Name }
func (c *UIAwgClient) SetName(v string) { c.Name = v }
func (c *UIAwgClient) GetEnable() bool { return c.Enable }
func (c *UIAwgClient) SetEnable(v bool) { c.Enable = v }
func (c *UIAwgClient) GetIPv4Address() string { return c.IPv4Address }
func (c *UIAwgClient) SetIPv4Address(v string) { c.IPv4Address = v }
func (c *UIAwgClient) GetIPv6Address() string { return c.IPv6Address }
func (c *UIAwgClient) SetIPv6Address(v string) { c.IPv6Address = v }
func (c *UIAwgClient) GetComment() string { return c.Comment }
func (c *UIAwgClient) SetComment(v string) { c.Comment = v }
func (c *UIAwgClient) GetPrivateKey() string { return c.PrivateKey }
func (c *UIAwgClient) SetPrivateKey(v string) { c.PrivateKey = v }
func (c *UIAwgClient) GetPresharedKey() string { return c.PresharedKey }
func (c *UIAwgClient) SetPresharedKey(v string) { c.PresharedKey = v }
func (c *UIAwgClient) GetAllowedIPs() string { return c.AllowedIPs }
func (c *UIAwgClient) SetAllowedIPs(v string) { c.AllowedIPs = v }
func (c *UIAwgClient) GetClientAllowedIPs() string { return c.ClientAllowedIPs }
func (c *UIAwgClient) SetClientAllowedIPs(v string) { c.ClientAllowedIPs = v }
func (c *UIAwgClient) GetForwardedPorts() string { return c.ForwardedPorts }
func (c *UIAwgClient) SetForwardedPorts(v string) { c.ForwardedPorts = v }
func (c *UIAwgClient) GetPersistentKeepalive() int { return c.PersistentKeepalive }
func (c *UIAwgClient) SetPersistentKeepalive(v int) { c.PersistentKeepalive = v }
func (c *UIAwgClient) GetUpload() int64 { return c.Upload }
func (c *UIAwgClient) SetUpload(v int64) { c.Upload = v }
func (c *UIAwgClient) GetDownload() int64 { return c.Download }
func (c *UIAwgClient) SetDownload(v int64) { c.Download = v }
func (c *UIAwgClient) GetTotalGB() int64 { return c.TotalGB }
func (c *UIAwgClient) SetTotalGB(v int64) { c.TotalGB = v }
func (c *UIAwgClient) GetAllTime() int64 { return c.AllTime }
func (c *UIAwgClient) SetAllTime(v int64) { c.AllTime = v }
func (c *UIAwgClient) GetLastPeerUp() int64 { return c.LastPeerUp }
func (c *UIAwgClient) SetLastPeerUp(v int64) { c.LastPeerUp = v }
func (c *UIAwgClient) GetLastPeerDown() int64 { return c.LastPeerDown }
func (c *UIAwgClient) SetLastPeerDown(v int64) { c.LastPeerDown = v }
func (c *UIAwgClient) GetExpiryTime() int64 { return c.ExpiryTime }
func (c *UIAwgClient) SetExpiryTime(v int64) { c.ExpiryTime = v }
func (c *UIAwgClient) GetReset() int { return c.Reset }
func (c *UIAwgClient) SetReset(v int) { c.Reset = v }
func (c *UIAwgClient) GetLimitIp() int { return c.LimitIp }
func (c *UIAwgClient) SetLimitIp(v int) { c.LimitIp = v }
func (c *UIAwgClient) GetTgID() int64 { return c.TgID }
func (c *UIAwgClient) SetTgID(v int64) { c.TgID = v }
func (c *UIAwgClient) GetLastOnline() int64 { return c.LastOnline }
func (c *UIAwgClient) SetLastOnline(v int64) { c.LastOnline = v }
func (c *UIAwgClient) GetLastIP() string { return c.LastIP }
func (c *UIAwgClient) SetLastIP(v string) { c.LastIP = v }
