// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: BPB-Worker-Panel-main
// Target path: server/internal/proxy/bpb_panel.go

package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// BPBProxySettings defines the complete set of parameters (from kv.ts).
type BPBProxySettings struct {
	RemoteDNS           string   `json:"remoteDNS"`
	RemoteDnsHost       string   `json:"remoteDnsHost"`
	LocalDNS            string   `json:"localDNS"`
	AntiSanctionDNS     string   `json:"antiSanctionDNS"`
	EnableIPv6          bool     `json:"enableIPv6"`
	FakeDNS             bool     `json:"fakeDNS"`
	LogLevel            string   `json:"logLevel"`
	AllowLANConnection  bool     `json:"allowLANConnection"`
	ProxyIPMode         string   `json:"proxyIPMode"`
	ProxyIPs            []string `json:"proxyIPs"`
	Prefixes            []string `json:"prefixes"`
	UpstreamProxy       string   `json:"upstreamProxy"`
	OutProxy            string   `json:"outProxy"`
	CleanIPs            []string `json:"cleanIPs"`
	CustomCdnAddrs      []string `json:"customCdnAddrs"`
	CustomCdnHost       string   `json:"customCdnHost"`
	CustomCdnSni        string   `json:"customCdnSni"`
	BestVLTRInterval    int      `json:"bestVLTRInterval"`
	VLConfigs           []string `json:"VLConfigs"`
	TRConfigs           []string `json:"TRConfigs"`
	Ports               []int    `json:"ports"`
	Fingerprint         string   `json:"fingerprint"`
	EnableTFO           bool     `json:"enableTFO"`
	FragmentMode        string   `json:"fragmentMode"`
	FragmentLengthMin   int      `json:"fragmentLengthMin"`
	FragmentLengthMax   int      `json:"fragmentLengthMax"`
	FragmentIntervalMin int      `json:"fragmentIntervalMin"`
	FragmentIntervalMax int      `json:"fragmentIntervalMax"`
	FragmentMaxSplitMin int      `json:"fragmentMaxSplitMin"`
	FragmentMaxSplitMax int      `json:"fragmentMaxSplitMax"`
	FragmentPackets     string   `json:"fragmentPackets"`
	EnableECH           bool     `json:"enableECH"`
	EchServerName       string   `json:"echServerName"`
	BypassIran          bool     `json:"bypassIran"`
	BypassChina         bool     `json:"bypassChina"`
	BypassRussia        bool     `json:"bypassRussia"`
}

// BPBPanel automates subscription profile building for CF Workers.
type BPBPanel struct {
	mu               sync.RWMutex
	domain           string
	uuid             string
	proxyConfigs     map[string]string
	ips              []string
	customDNSServers []string
	version          int
	vlessTemplate    string
	trojanTemplate   string
	warpTemplate     string
	subscribersCount int
	trafficLimit     uint64
	settings         BPBProxySettings
	secretKey        string
	password         string
}

// 1. NewBPBPanel initializes a new BPBPanel instance.
func NewBPBPanel() *BPBPanel {
	// Generate a dynamic 32-byte hex secret key (from auth.ts)
	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	secretKey := fmt.Sprintf("%x", keyBytes)

	return &BPBPanel{
		proxyConfigs:     make(map[string]string),
		ips:              make([]string, 0),
		customDNSServers: []string{"1.1.1.1", "8.8.8.8"},
		version:          1,
		vlessTemplate:    `{"type": "vless", "tag": "vless-cf"}`,
		trojanTemplate:   `{"type": "trojan", "tag": "trojan-cf"}`,
		warpTemplate:     `{"type": "warp", "tag": "warp-cf"}`,
		secretKey:        secretKey,
		password:         "admin",
		settings: BPBProxySettings{
			RemoteDNS:    "8.8.8.8",
			LocalDNS:     "1.1.1.1",
			EnableIPv6:   true,
			Fingerprint:  "chrome",
			FragmentMode: "random",
			BypassIran:   true,
		},
	}
}

// 2. BuildSubscriptionProfile generates a VLESS, Trojan, and Warp profile.
func (b *BPBPanel) BuildSubscriptionProfile(domain, uuid string) string {
	b.mu.Lock()
	b.domain = domain
	b.uuid = uuid
	b.subscribersCount++
	b.mu.Unlock()

	vless := fmt.Sprintf("vless://%s@%s:443?encryption=none&security=tls&type=ws#VLESS-CF", uuid, domain)
	trojan := fmt.Sprintf("trojan://%s@%s:443?security=tls&type=ws#Trojan-CF", uuid, domain)
	warp := fmt.Sprintf("warp://%s:2408/?ifp=10-20#WARP-CF", domain)

	raw := fmt.Sprintf("%s\n%s\n%s\n", vless, trojan, warp)
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

// 3. GetDomain returns current active domain.
func (b *BPBPanel) GetDomain() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.domain
}

// 4. SetDomain overrides current active domain.
func (b *BPBPanel) SetDomain(d string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.domain = d
}

// 5. GetUUID returns current active UUID.
func (b *BPBPanel) GetUUID() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.uuid
}

// 6. SetUUID overrides current active UUID.
func (b *BPBPanel) SetUUID(u string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.uuid = u
}

// 7. AddProxyConfig registers custom proxy config value.
func (b *BPBPanel) AddProxyConfig(key, val string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.proxyConfigs[key] = val
}

// 8. GetProxyConfig retrieves registered proxy config value.
func (b *BPBPanel) GetProxyConfig(key string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.proxyConfigs[key]
}

// 9. RemoveProxyConfig deletes custom proxy config by key.
func (b *BPBPanel) RemoveProxyConfig(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.proxyConfigs, key)
}

// 10. GetProxyConfigsCount returns total proxy configs.
func (b *BPBPanel) GetProxyConfigsCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.proxyConfigs)
}

// 11. ClearProxyConfigs resets proxy configurations map.
func (b *BPBPanel) ClearProxyConfigs() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.proxyConfigs = make(map[string]string)
}

// 12. AddIPAddress registers custom IP address.
func (b *BPBPanel) AddIPAddress(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ips = append(b.ips, ip)
}

// 13. RemoveIPAddress deletes custom IP address.
func (b *BPBPanel) RemoveIPAddress(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var updated []string
	for _, x := range b.ips {
		if x != ip {
			updated = append(updated, x)
		}
	}
	b.ips = updated
}

// 14. GetIPAddresses returns list of registered IPs.
func (b *BPBPanel) GetIPAddresses() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]string, len(b.ips))
	copy(copied, b.ips)
	return copied
}

// 15. ClearIPAddresses resets registered IPs list.
func (b *BPBPanel) ClearIPAddresses() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ips = make([]string, 0)
}

// 16. AddDNSServer registers custom DNS resolver IP.
func (b *BPBPanel) AddDNSServer(dns string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.customDNSServers = append(b.customDNSServers, dns)
}

// 17. RemoveDNSServer deletes custom DNS resolver IP.
func (b *BPBPanel) RemoveDNSServer(dns string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var updated []string
	for _, x := range b.customDNSServers {
		if x != dns {
			updated = append(updated, x)
		}
	}
	b.customDNSServers = updated
}

// 18. GetDNSServers returns list of DNS resolver IPs.
func (b *BPBPanel) GetDNSServers() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]string, len(b.customDNSServers))
	copy(copied, b.customDNSServers)
	return copied
}

// 19. ClearDNSServers resets custom DNS servers list.
func (b *BPBPanel) ClearDNSServers() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.customDNSServers = make([]string, 0)
}

// 20. GetVersion returns current schema version.
func (b *BPBPanel) GetVersion() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.version
}

// 21. SetVersion overrides current schema version.
func (b *BPBPanel) SetVersion(v int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.version = v
}

// 22. ValidateUUID validates formatting string rules.
func (b *BPBPanel) ValidateUUID(uuid string) bool {
	return len(uuid) >= 32
}

// 23. ValidateDomain validates domain string rules.
func (b *BPBPanel) ValidateDomain(domain string) bool {
	return len(domain) > 3 && strings.Contains(domain, ".")
}

// 24. ExportConfigJSON saves settings to JSON string format.
func (b *BPBPanel) ExportConfigJSON() (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	data, err := json.Marshal(b.proxyConfigs)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// 25. ImportConfigJSON loads settings from JSON string format.
func (b *BPBPanel) ImportConfigJSON(jsonStr string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return json.Unmarshal([]byte(jsonStr), &b.proxyConfigs)
}

// 26. GenerateVLESSLink formats parameters to standard VLESS URI string.
func (b *BPBPanel) GenerateVLESSLink(host, port, path, uuid, name string) string {
	return fmt.Sprintf("vless://%s@%s:%s?encryption=none&security=tls&type=ws&path=%s#%s", uuid, host, port, path, name)
}

// 27. GenerateTrojanLink formats parameters to standard Trojan URI string.
func (b *BPBPanel) GenerateTrojanLink(host, port, path, password, name string) string {
	return fmt.Sprintf("trojan://%s@%s:%s?security=tls&type=ws&path=%s#%s", password, host, port, path, name)
}

// 28. GenerateSSLink formats parameters to standard Shadowsocks URI string.
func (b *BPBPanel) GenerateSSLink(host, port, method, password, name string) string {
	return fmt.Sprintf("ss://%s:%s@%s:%s#%s", method, password, host, port, name)
}

// 29. GenerateHysteriaLink formats parameters to standard Hysteria2 URI string.
func (b *BPBPanel) GenerateHysteriaLink(host, port, auth, name string) string {
	return fmt.Sprintf("hysteria2://%s@%s:%s#%s", auth, host, port, name)
}

// 30. GenerateTuicLink formats parameters to standard TUIC URI.
func (b *BPBPanel) GenerateTuicLink(host, port, uuid, password, name string) string {
	return fmt.Sprintf("tuic://%s:%s@%s:%s#%s", uuid, password, host, port, name)
}

// 31. GenerateWarpLink formats parameters to Warp client URI.
func (b *BPBPanel) GenerateWarpLink(host, port, name string) string {
	return fmt.Sprintf("warp://%s:%s#%s", host, port, name)
}

// 32. GenerateSocksLink formats parameters to SOCKS URI.
func (b *BPBPanel) GenerateSocksLink(host, port, username, password, name string) string {
	return fmt.Sprintf("socks://%s:%s@%s:%s#%s", username, password, host, port, name)
}

// 33. GenerateHttpLink formats parameters to HTTP URI.
func (b *BPBPanel) GenerateHttpLink(host, port, username, password, name string) string {
	return fmt.Sprintf("http://%s:%s@%s:%s#%s", username, password, host, port, name)
}

// 34. GenerateWireguardLink formats parameters to Wireguard URI.
func (b *BPBPanel) GenerateWireguardLink(host, port, pubKey, name string) string {
	return fmt.Sprintf("wireguard://%s:%s?public_key=%s#%s", host, port, pubKey, name)
}

// 35. GetActiveIPsCount returns count of active IP overrides.
func (b *BPBPanel) GetActiveIPsCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.ips)
}

// 36. GetProxyConfigKeys returns slice of registered config keys.
func (b *BPBPanel) GetProxyConfigKeys() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var keys []string
	for k := range b.proxyConfigs {
		keys = append(keys, k)
	}
	return keys
}

// 37. HasProxyConfigKey checks key presence.
func (b *BPBPanel) HasProxyConfigKey(key string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	_, found := b.proxyConfigs[key]
	return found
}

// 38. IsIPRegistered checks IP presence.
func (b *BPBPanel) IsIPRegistered(ip string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, x := range b.ips {
		if x == ip {
			return true
		}
	}
	return false
}

// 39. IsDNSServerRegistered checks DNS presence.
func (b *BPBPanel) IsDNSServerRegistered(dns string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, x := range b.customDNSServers {
		if x == dns {
			return true
		}
	}
	return false
}

// 40. SetDefaultDNSServers restores defaults DNS.
func (b *BPBPanel) SetDefaultDNSServers() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.customDNSServers = []string{"1.1.1.1", "8.8.8.8"}
}

// 41. ResetBPBPanelPreset resets config settings to defaults.
func (b *BPBPanel) ResetBPBPanelPreset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.proxyConfigs = make(map[string]string)
	b.ips = make([]string, 0)
	b.customDNSServers = []string{"1.1.1.1", "8.8.8.8"}
	b.version = 1
	b.subscribersCount = 0
	b.trafficLimit = 0
}

// 42. VerifyBPBPanelPreset checks configuration integration status.
func (b *BPBPanel) VerifyBPBPanelPreset() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.customDNSServers) > 0 && b.version > 0
}

// 43. GetVLESSConfigTemplate returns VLESS schema string.
func (b *BPBPanel) GetVLESSConfigTemplate() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.vlessTemplate
}

// 44. GetTrojanConfigTemplate returns Trojan schema string.
func (b *BPBPanel) GetTrojanConfigTemplate() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.trojanTemplate
}

// 45. GetWarpConfigTemplate returns Warp schema string.
func (b *BPBPanel) GetWarpConfigTemplate() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.warpTemplate
}

// 46. SetVLESSConfigTemplate configures VLESS schema string.
func (b *BPBPanel) SetVLESSConfigTemplate(t string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.vlessTemplate = t
}

// 47. SetTrojanConfigTemplate configures Trojan schema string.
func (b *BPBPanel) SetTrojanConfigTemplate(t string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.trojanTemplate = t
}

// 48. SetWarpConfigTemplate configures Warp schema string.
func (b *BPBPanel) SetWarpConfigTemplate(t string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.warpTemplate = t
}

// 49. GenerateSubscriptionHeaders builds HTTP headers maps.
func (b *BPBPanel) GenerateSubscriptionHeaders(domain string) map[string]string {
	return map[string]string{
		"Content-Type":            "text/plain; charset=utf-8",
		"Subscription-Userinfo":   "upload=0; download=0; total=107374182400; expire=0",
		"Profile-Update-Interval": "24",
		"Profile-Web-Page-Url":    "https://" + domain,
	}
}

// 50. GetSubscribersCount returns subscribers counter.
func (b *BPBPanel) GetSubscribersCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.subscribersCount
}

// 51. IncrementSubscribers increments subscribers count.
func (b *BPBPanel) IncrementSubscribers() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribersCount++
}

// 52. ResetSubscribers zeroes subscribers count.
func (b *BPBPanel) ResetSubscribers() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribersCount = 0
}

// 53. GetTrafficLimit returns traffic allocation.
func (b *BPBPanel) GetTrafficLimit() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.trafficLimit
}

// 54. SetTrafficLimit configures traffic allocation limit.
func (b *BPBPanel) SetTrafficLimit(limit uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.trafficLimit = limit
}

// 55. CheckTrafficUsage returns true if usage falls under limit.
func (b *BPBPanel) CheckTrafficUsage(usage uint64) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.trafficLimit == 0 {
		return true
	}
	return usage < b.trafficLimit
}

// GetProxySettings returns the current proxy configuration structure (from kv.ts).
func (b *BPBPanel) GetProxySettings() BPBProxySettings {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings
}

// UpdateProxySettings updates the active proxy configuration structure (from kv.ts).
func (b *BPBPanel) UpdateProxySettings(s BPBProxySettings) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings = s
}

// GenerateJWTToken creates a secure payload signature token (from auth.ts generateJWTToken).
func (b *BPBPanel) GenerateJWTToken(password string) (string, error) {
	b.mu.RLock()
	expected := b.password
	secretKey := b.secretKey
	b.mu.RUnlock()

	if password != expected {
		return "", fmt.Errorf("wrong password")
	}

	// We create a simple HMAC-signed claims payload: "userID:<uuid>|exp:<unix>"
	expiration := time.Now().Add(24 * time.Hour).Unix()
	payload := fmt.Sprintf("userID:%s|exp:%d", b.uuid, expiration)

	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(payload))
	signature := mac.Sum(nil)

	// Combine payload and signature in base64url format
	tokenContent := fmt.Sprintf("%s.%s",
		base64.RawURLEncoding.EncodeToString([]byte(payload)),
		base64.RawURLEncoding.EncodeToString(signature),
	)
	return tokenContent, nil
}

// AuthenticateJWT checks if the token cookie has a valid signature and is not expired (from auth.ts Authenticate).
func (b *BPBPanel) AuthenticateJWT(token string) bool {
	b.mu.RLock()
	secretKey := b.secretKey
	b.mu.RUnlock()

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	// Verify HMAC-SHA256 signature
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(payloadBytes)
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal(signatureBytes, expectedSignature) {
		return false
	}

	// Verify expiration timestamp
	payloadStr := string(payloadBytes)
	fields := strings.Split(payloadStr, "|")
	for _, field := range fields {
		if strings.HasPrefix(field, "exp:") {
			var exp int64
			_, _ = fmt.Sscanf(field, "exp:%d", &exp)
			if time.Now().Unix() > exp {
				return false // Expired
			}
		}
	}

	return true
}

// ResetPassword overrides the admin dashboard password (from auth.ts resetPassword).
func (b *BPBPanel) ResetPassword(token, newPassword string) error {
	if !b.AuthenticateJWT(token) {
		return fmt.Errorf("unauthorized")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if newPassword == b.password {
		return fmt.Errorf("password must be different")
	}
	b.password = newPassword
	return nil
}

// SetRemoteDNS overrides settings remote DNS upstream (from kv.ts).
func (b *BPBPanel) SetRemoteDNS(dns string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.RemoteDNS = dns
}

// GetRemoteDNS retrieves settings remote DNS upstream.
func (b *BPBPanel) GetRemoteDNS() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.RemoteDNS
}

// SetLocalDNS overrides settings local DNS.
func (b *BPBPanel) SetLocalDNS(dns string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.LocalDNS = dns
}

// GetLocalDNS retrieves settings local DNS.
func (b *BPBPanel) GetLocalDNS() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.LocalDNS
}

// SetAntiSanctionDNS overrides anti-sanction DNS resolver.
func (b *BPBPanel) SetAntiSanctionDNS(dns string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.AntiSanctionDNS = dns
}

// GetAntiSanctionDNS retrieves anti-sanction DNS resolver.
func (b *BPBPanel) GetAntiSanctionDNS() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.AntiSanctionDNS
}

// SetEnableIPv6 overrides IPv6 toggle settings.
func (b *BPBPanel) SetEnableIPv6(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.EnableIPv6 = enabled
}

// GetEnableIPv6 retrieves IPv6 toggle settings.
func (b *BPBPanel) GetEnableIPv6() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.EnableIPv6
}

// SetFakeDNS overrides fake DNS resolver configuration.
func (b *BPBPanel) SetFakeDNS(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.FakeDNS = enabled
}

// GetFakeDNS retrieves fake DNS resolver configuration.
func (b *BPBPanel) GetFakeDNS() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.FakeDNS
}

// SetAllowLANConnection overrides LAN connections toggle settings.
func (b *BPBPanel) SetAllowLANConnection(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.AllowLANConnection = enabled
}

// GetAllowLANConnection retrieves LAN connections toggle settings.
func (b *BPBPanel) GetAllowLANConnection() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.AllowLANConnection
}

// SetProxyIPMode overrides proxy IP selection model.
func (b *BPBPanel) SetProxyIPMode(mode string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.ProxyIPMode = mode
}

// GetProxyIPMode retrieves proxy IP selection model.
func (b *BPBPanel) GetProxyIPMode() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.ProxyIPMode
}

// SetCustomCdnHost overrides CDN host parameter.
func (b *BPBPanel) SetCustomCdnHost(host string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.CustomCdnHost = host
}

// GetCustomCdnHost retrieves CDN host parameter.
func (b *BPBPanel) GetCustomCdnHost() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.CustomCdnHost
}

// SetCustomCdnSni overrides CDN SNI value.
func (b *BPBPanel) SetCustomCdnSni(sni string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.CustomCdnSni = sni
}

// GetCustomCdnSni retrieves CDN SNI value.
func (b *BPBPanel) GetCustomCdnSni() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.CustomCdnSni
}

// SetFingerprint overrides settings ClientHello fingerprint target.
func (b *BPBPanel) SetFingerprint(fp string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.Fingerprint = fp
}

// GetFingerprint retrieves settings ClientHello fingerprint target.
func (b *BPBPanel) GetFingerprint() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.Fingerprint
}

// SetEnableTFO overrides TCP Fast Open configuration.
func (b *BPBPanel) SetEnableTFO(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.EnableTFO = enabled
}

// GetEnableTFO retrieves TCP Fast Open configuration.
func (b *BPBPanel) GetEnableTFO() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.EnableTFO
}

// SetEnableECH overrides TLS Encrypted Client Hello config.
func (b *BPBPanel) SetEnableECH(enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.EnableECH = enabled
}

// GetEnableECH retrieves TLS Encrypted Client Hello config.
func (b *BPBPanel) GetEnableECH() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.EnableECH
}

// SetEchServerName overrides ECH destination SNI.
func (b *BPBPanel) SetEchServerName(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.EchServerName = name
}

// GetEchServerName retrieves ECH destination SNI.
func (b *BPBPanel) GetEchServerName() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.EchServerName
}

// SetRemoteDnsHost overrides remote DNS host parameter.
func (b *BPBPanel) SetRemoteDnsHost(host string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.RemoteDnsHost = host
}

// GetRemoteDnsHost retrieves remote DNS host parameter.
func (b *BPBPanel) GetRemoteDnsHost() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.RemoteDnsHost
}

// SetLogLevel overrides active log severity level.
func (b *BPBPanel) SetLogLevel(level string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.LogLevel = level
}

// GetLogLevel retrieves active log severity level.
func (b *BPBPanel) GetLogLevel() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.LogLevel
}

// SetProxyIPs overrides the configured proxy IPs array.
func (b *BPBPanel) SetProxyIPs(ips []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.ProxyIPs = ips
}

// GetProxyIPs retrieves the configured proxy IPs array.
func (b *BPBPanel) GetProxyIPs() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]string, len(b.settings.ProxyIPs))
	copy(copied, b.settings.ProxyIPs)
	return copied
}

// SetPrefixes overrides the configured routing prefixes.
func (b *BPBPanel) SetPrefixes(prefixes []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.Prefixes = prefixes
}

// GetPrefixes retrieves the configured routing prefixes.
func (b *BPBPanel) GetPrefixes() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]string, len(b.settings.Prefixes))
	copy(copied, b.settings.Prefixes)
	return copied
}

// SetUpstreamProxy overrides active upstream proxy.
func (b *BPBPanel) SetUpstreamProxy(proxy string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.UpstreamProxy = proxy
}

// GetUpstreamProxy retrieves active upstream proxy.
func (b *BPBPanel) GetUpstreamProxy() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.UpstreamProxy
}

// SetOutProxy overrides active outbound proxy.
func (b *BPBPanel) SetOutProxy(proxy string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.OutProxy = proxy
}

// GetOutProxy retrieves active outbound proxy.
func (b *BPBPanel) GetOutProxy() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.OutProxy
}

// SetCleanIPs overrides active clean IP addresses array.
func (b *BPBPanel) SetCleanIPs(ips []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.CleanIPs = ips
}

// GetCleanIPs retrieves active clean IP addresses array.
func (b *BPBPanel) GetCleanIPs() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]string, len(b.settings.CleanIPs))
	copy(copied, b.settings.CleanIPs)
	return copied
}

// SetCustomCdnAddrs overrides custom CDN endpoints.
func (b *BPBPanel) SetCustomCdnAddrs(addrs []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.CustomCdnAddrs = addrs
}

// GetCustomCdnAddrs retrieves custom CDN endpoints.
func (b *BPBPanel) GetCustomCdnAddrs() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]string, len(b.settings.CustomCdnAddrs))
	copy(copied, b.settings.CustomCdnAddrs)
	return copied
}

// SetBestVLTRInterval overrides optimization interval parameter.
func (b *BPBPanel) SetBestVLTRInterval(val int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.BestVLTRInterval = val
}

// GetBestVLTRInterval retrieves optimization interval parameter.
func (b *BPBPanel) GetBestVLTRInterval() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.BestVLTRInterval
}

// SetVLConfigs overrides VLESS templates list.
func (b *BPBPanel) SetVLConfigs(configs []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.VLConfigs = configs
}

// GetVLConfigs retrieves VLESS templates list.
func (b *BPBPanel) GetVLConfigs() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]string, len(b.settings.VLConfigs))
	copy(copied, b.settings.VLConfigs)
	return copied
}

// SetTRConfigs overrides Trojan templates list.
func (b *BPBPanel) SetTRConfigs(configs []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.TRConfigs = configs
}

// GetTRConfigs retrieves Trojan templates list.
func (b *BPBPanel) GetTRConfigs() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]string, len(b.settings.TRConfigs))
	copy(copied, b.settings.TRConfigs)
	return copied
}

// SetPorts overrides active listener ports.
func (b *BPBPanel) SetPorts(ports []int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.Ports = ports
}

// GetPorts retrieves active listener ports.
func (b *BPBPanel) GetPorts() []int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	copied := make([]int, len(b.settings.Ports))
	copy(copied, b.settings.Ports)
	return copied
}

// SetFragmentMode overrides TLS fragmentation strategy.
func (b *BPBPanel) SetFragmentMode(mode string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.FragmentMode = mode
}

// GetFragmentMode retrieves TLS fragmentation strategy.
func (b *BPBPanel) GetFragmentMode() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.FragmentMode
}

// SetFragmentLengthMin overrides min fragment size limit.
func (b *BPBPanel) SetFragmentLengthMin(val int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.FragmentLengthMin = val
}

// GetFragmentLengthMin retrieves min fragment size limit.
func (b *BPBPanel) GetFragmentLengthMin() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.FragmentLengthMin
}

// SetFragmentLengthMax overrides max fragment size limit.
func (b *BPBPanel) SetFragmentLengthMax(val int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.FragmentLengthMax = val
}

// GetFragmentLengthMax retrieves max fragment size limit.
func (b *BPBPanel) GetFragmentLengthMax() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.FragmentLengthMax
}

// SetFragmentIntervalMin overrides min fragment interval.
func (b *BPBPanel) SetFragmentIntervalMin(val int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.FragmentIntervalMin = val
}

// GetFragmentIntervalMin retrieves min fragment interval.
func (b *BPBPanel) GetFragmentIntervalMin() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.FragmentIntervalMin
}

// SetFragmentIntervalMax overrides max fragment interval.
func (b *BPBPanel) SetFragmentIntervalMax(val int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.FragmentIntervalMax = val
}

// GetFragmentIntervalMax retrieves max fragment interval.
func (b *BPBPanel) GetFragmentIntervalMax() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.FragmentIntervalMax
}

// SetFragmentMaxSplitMin overrides minimum splits limit.
func (b *BPBPanel) SetFragmentMaxSplitMin(val int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.FragmentMaxSplitMin = val
}

// GetFragmentMaxSplitMin retrieves minimum splits limit.
func (b *BPBPanel) GetFragmentMaxSplitMin() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.FragmentMaxSplitMin
}

// SetFragmentMaxSplitMax overrides maximum splits limit.
func (b *BPBPanel) SetFragmentMaxSplitMax(val int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.FragmentMaxSplitMax = val
}

// GetFragmentMaxSplitMax retrieves maximum splits limit.
func (b *BPBPanel) GetFragmentMaxSplitMax() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.FragmentMaxSplitMax
}

// SetFragmentPackets overrides target packets classification.
func (b *BPBPanel) SetFragmentPackets(p string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.FragmentPackets = p
}

// GetFragmentPackets retrieves target packets classification.
func (b *BPBPanel) GetFragmentPackets() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.FragmentPackets
}

// SetBypassIran overrides Iran routing rule filter.
func (b *BPBPanel) SetBypassIran(bypass bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.BypassIran = bypass
}

// GetBypassIran retrieves Iran routing rule filter.
func (b *BPBPanel) GetBypassIran() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.BypassIran
}

// SetBypassChina overrides China routing rule filter.
func (b *BPBPanel) SetBypassChina(bypass bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.BypassChina = bypass
}

// GetBypassChina retrieves China routing rule filter.
func (b *BPBPanel) GetBypassChina() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.BypassChina
}

// SetBypassRussia overrides Russia routing rule filter.
func (b *BPBPanel) SetBypassRussia(bypass bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.settings.BypassRussia = bypass
}

// GetBypassRussia retrieves Russia routing rule filter.
func (b *BPBPanel) GetBypassRussia() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.settings.BypassRussia
}
