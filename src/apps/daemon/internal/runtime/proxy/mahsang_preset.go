// Package proxy implements outbound protocols and obfuscation mechanisms.

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// FragmentSetting defines socket fragmentation limits per ISP network.
type FragmentSetting struct {
	ISP           string  `json:"ISP"`
	NumFragment   int     `json:"num_fragment"`
	FragmentSleep float64 `json:"fragment_sleep"`
	SocketTimeout int     `json:"socket_timeout"`
}

// OfflineDnsSetting manages local IP mapping tables.
type OfflineDnsSetting struct {
	CloudflareDns string `json:"cloudflare-dns.com"`
	DnsGoogle     string `json:"dns.google"`
	Instagram     string `json:"instagram.com"`
}

// FakeHostSetting overrides host headers for specific ISPs.
type FakeHostSetting struct {
	ISP    string `json:"ISP"`
	Header string `json:"header"`
	Value  string `json:"value"`
}

// CloudflareSetting restricts ports and IP list per ISP.
type CloudflareSetting struct {
	ISP    string   `json:"ISP"`
	Port   int      `json:"port"`
	IPList []string `json:"IP_LIST"`
}

// DoHSetting configures DoH endpoints per ISP.
type DoHSetting struct {
	ISP             string `json:"ISP"`
	DohURL          string `json:"doh_url"`
	DohIP           string `json:"doh_ip"`
	UseCloudflareIP bool   `json:"use_cludflare_ip"`
	UseFragment     bool   `json:"use_fragment"`
}

// MahsaNgPreset encapsulates fragmentation and DNS bypass settings.
type MahsaNgPreset struct {
	mu              sync.RWMutex
	Fragments       []FragmentSetting
	OfflineDns      OfflineDnsSetting
	dohQueryCount   uint64
	FakeHosts       []FakeHostSetting
	CfSettings      []CloudflareSetting
	DohSettings     []DoHSetting
	OfflineDNSMap   map[string]string
	proxyListenIP   string
	proxyListenPort int
	socketTimeout   int
}

// GetMahsaNgPreset instantiates a default MahsaNgPreset profile.
func GetMahsaNgPreset() *MahsaNgPreset {
	return &MahsaNgPreset{
		Fragments: []FragmentSetting{
			{ISP: "mci", NumFragment: 150, FragmentSleep: 0.005, SocketTimeout: 8},
			{ISP: "irancell", NumFragment: 14, FragmentSleep: 0.005, SocketTimeout: 8},
			{ISP: "tci", NumFragment: 200, FragmentSleep: 0.003, SocketTimeout: 8},
			{ISP: "any", NumFragment: 100, FragmentSleep: 0.008, SocketTimeout: 8},
		},
		OfflineDns: OfflineDnsSetting{
			CloudflareDns: "203.32.120.226",
			DnsGoogle:     "8.8.8.8",
			Instagram:     "163.70.128.174",
		},
		FakeHosts: []FakeHostSetting{
			{ISP: "any", Header: "hosthost", Value: "www.google.com"},
		},
		CfSettings: []CloudflareSetting{
			{ISP: "any", Port: 443, IPList: []string{"203.23.106.136", "discord.com"}},
		},
		DohSettings: []DoHSetting{
			{ISP: "any", DohURL: "https://cloudflare-dns.com/dns-query?name=", DohIP: "sciencedirect.com", UseCloudflareIP: true, UseFragment: true},
		},
		OfflineDNSMap: map[string]string{
			"cloudflare-dns.com": "203.32.120.226",
			"dns.google":         "8.8.8.8",
		},
		proxyListenIP:   "127.0.0.1",
		proxyListenPort: 0,
		socketTimeout:   8,
	}
}

// 1. GetFragmentSettingByISP returns settings matched to ISP name.
func (m *MahsaNgPreset) GetFragmentSettingByISP(isp string) (FragmentSetting, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, f := range m.Fragments {
		if f.ISP == isp {
			return f, true
		}
	}
	return FragmentSetting{}, false
}

// 2. AddFragmentSetting appends custom ISP definitions.
func (m *MahsaNgPreset) AddFragmentSetting(f FragmentSetting) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Fragments = append(m.Fragments, f)
}

// 3. RemoveFragmentSetting deletes custom ISP definitions.
func (m *MahsaNgPreset) RemoveFragmentSetting(isp string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var updated []FragmentSetting
	for _, f := range m.Fragments {
		if f.ISP != isp {
			updated = append(updated, f)
		}
	}
	m.Fragments = updated
}

// 4. UpdateFragmentSetting modifies specific configuration parameters.
func (m *MahsaNgPreset) UpdateFragmentSetting(isp string, num int, sleep float64, timeout int) error {
	m.mu.Lock()
	for idx, f := range m.Fragments {
		if f.ISP == isp {
			m.Fragments[idx].NumFragment = num
			m.Fragments[idx].FragmentSleep = sleep
			m.Fragments[idx].SocketTimeout = timeout
			m.mu.Unlock()
			return nil
		}
	}
	m.mu.Unlock()
	return fmt.Errorf("ISP %s not found", isp)
}

// 5. ClearFragmentSettings resets active configurations registry.
func (m *MahsaNgPreset) ClearFragmentSettings() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Fragments = make([]FragmentSetting, 0)
}

// 6. GetFragmentSettingsCount returns total configurations count.
func (m *MahsaNgPreset) GetFragmentSettingsCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.Fragments)
}

// 7. GetOfflineDNSInstagram returns Instagram override IPs.
func (m *MahsaNgPreset) GetOfflineDNSInstagram() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.OfflineDns.Instagram
}

// 8. SetOfflineDNSInstagram configures Instagram override IPs.
func (m *MahsaNgPreset) SetOfflineDNSInstagram(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OfflineDns.Instagram = ip
}

// 9. GetOfflineDNSGoogle returns Google DNS IPs.
func (m *MahsaNgPreset) GetOfflineDNSGoogle() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.OfflineDns.DnsGoogle
}

// 10. SetOfflineDNSGoogle configures Google DNS IPs.
func (m *MahsaNgPreset) SetOfflineDNSGoogle(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OfflineDns.DnsGoogle = ip
}

// 11. GetOfflineDNSCloudflare returns Cloudflare DNS IPs.
func (m *MahsaNgPreset) GetOfflineDNSCloudflare() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.OfflineDns.CloudflareDns
}

// 12. SetOfflineDNSCloudflare configures Cloudflare DNS IPs.
func (m *MahsaNgPreset) SetOfflineDNSCloudflare(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OfflineDns.CloudflareDns = ip
}

// 13. IsISPConfigured validates ISP registry keys presence.
func (m *MahsaNgPreset) IsISPConfigured(isp string) bool {
	_, found := m.GetFragmentSettingByISP(isp)
	return found
}

// 14. GetConfiguredISPs returns configurations keys list.
func (m *MahsaNgPreset) GetConfiguredISPs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []string
	for _, f := range m.Fragments {
		list = append(list, f.ISP)
	}
	return list
}

// 15. GetDefaultFragmentSetting returns fallback configuration parameters.
func (m *MahsaNgPreset) GetDefaultFragmentSetting() FragmentSetting {
	f, ok := m.GetFragmentSettingByISP("any")
	if !ok {
		return FragmentSetting{ISP: "any", NumFragment: 100, FragmentSleep: 0.008, SocketTimeout: 8}
	}
	return f
}

// 16. SetDefaultFragmentSetting overrides fallback parameters.
func (m *MahsaNgPreset) SetDefaultFragmentSetting(f FragmentSetting) {
	f.ISP = "any"
	m.RemoveFragmentSetting("any")
	m.AddFragmentSetting(f)
}

// 17. CalculateAverageFragments computes fragmentation averages.
func (m *MahsaNgPreset) CalculateAverageFragments() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := len(m.Fragments)
	if n == 0 {
		return 0.0
	}
	var sum int
	for _, f := range m.Fragments {
		sum += f.NumFragment
	}
	return float64(sum) / float64(n)
}

// 18. GetMaxFragmentCount returns absolute maximum parameters.
func (m *MahsaNgPreset) GetMaxFragmentCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.Fragments) == 0 {
		return 0
	}
	max := m.Fragments[0].NumFragment
	for _, f := range m.Fragments {
		if f.NumFragment > max {
			max = f.NumFragment
		}
	}
	return max
}

// 19. GetMinFragmentCount returns absolute minimum parameters.
func (m *MahsaNgPreset) GetMinFragmentCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.Fragments) == 0 {
		return 0
	}
	min := m.Fragments[0].NumFragment
	for _, f := range m.Fragments {
		if f.NumFragment < min {
			min = f.NumFragment
		}
	}
	return min
}

// 20. ValidatePreset validates target profile parameters.
func (m *MahsaNgPreset) ValidatePreset() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.OfflineDns.CloudflareDns != "" && m.OfflineDns.DnsGoogle != "" && len(m.Fragments) > 0
}

// 21. Clone copies preset structures.
func (m *MahsaNgPreset) Clone() *MahsaNgPreset {
	m.mu.RLock()
	defer m.mu.RUnlock()

	copiedFragments := make([]FragmentSetting, len(m.Fragments))
	copy(copiedFragments, m.Fragments)

	return &MahsaNgPreset{
		Fragments:  copiedFragments,
		OfflineDns: m.OfflineDns,
	}
}

// 22. ResetToDefaults restores default configurations.
func (m *MahsaNgPreset) ResetToDefaults() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.Fragments = []FragmentSetting{
		{ISP: "mci", NumFragment: 150, FragmentSleep: 0.005, SocketTimeout: 8},
		{ISP: "irancell", NumFragment: 14, FragmentSleep: 0.005, SocketTimeout: 8},
		{ISP: "tci", NumFragment: 200, FragmentSleep: 0.003, SocketTimeout: 8},
		{ISP: "any", NumFragment: 100, FragmentSleep: 0.008, SocketTimeout: 8},
	}
	m.OfflineDns = OfflineDnsSetting{
		CloudflareDns: "203.32.120.226",
		DnsGoogle:     "8.8.8.8",
		Instagram:     "163.70.128.174",
	}
}

// 23. ExportPresetJSON saves profiles to JSON.
func (m *MahsaNgPreset) ExportPresetJSON(filePath string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 24. ImportPresetJSON imports profiles from JSON.
func (m *MahsaNgPreset) ImportPresetJSON(filePath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var temp struct {
		Fragments  []FragmentSetting `json:"Fragments"`
		OfflineDns OfflineDnsSetting `json:"OfflineDns"`
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	m.Fragments = temp.Fragments
	m.OfflineDns = temp.OfflineDns
	return nil
}

// 25. VerifyPreset executes validation checks on target configurations.
func (m *MahsaNgPreset) VerifyPreset() bool {
	return m.ValidatePreset()
}

// 26. PickKRandomInts generates sorted random slice offsets.
func (m *MahsaNgPreset) PickKRandomInts(k, N int) []int {
	if k > N {
		k = N - 1
	}
	if k <= 0 {
		return nil
	}
	nums := make([]int, N)
	for i := 0; i < N; i++ {
		nums[i] = i + 1
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(nums), func(i, j int) {
		nums[i], nums[j] = nums[j], nums[i]
	})
	result := make([]int, k)
	copy(result, nums[:k])
	sort.Ints(result)
	return result
}

// 27. IsValidIPAddress asserts IPv4 format correctness.
func (m *MahsaNgPreset) IsValidIPAddress(ip string) bool {
	var ipRegex = regexp.MustCompile(`^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))$`)
	return ipRegex.MatchString(ip)
}

// 28. RunHTTPSFragmentorProxy starts an HTTP CONNECT splitting proxy.
func (m *MahsaNgPreset) RunHTTPSFragmentorProxy(ctx context.Context, listenAddr string, targetIP string, targetPort int, isFragment bool, numFragment int, fragmentSleep float64) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 8192)
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			req := string(buf[:n])
			if !regexp.MustCompile(`^CONNECT\s`).MatchString(req) {
				_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n"))
				return
			}

			backend, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, targetPort), 8*time.Second)
			if err != nil {
				_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nProxy-agent: MyProxy/1.0\r\n\r\n"))
				return
			}
			defer backend.Close()

			_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n"))

			go func() {
				first := isFragment
				for {
					rn, err := c.Read(buf)
					if err != nil {
						return
					}
					if first {
						first = false
						indices := m.PickKRandomInts(numFragment-1, rn)
						pre := 0
						for _, next := range indices {
							if next > pre && next <= rn {
								_, _ = backend.Write(buf[pre:next])
								time.Sleep(time.Duration(fragmentSleep * float64(time.Second)))
								pre = next
							}
						}
						_, _ = backend.Write(buf[pre:rn])
					} else {
						_, _ = backend.Write(buf[:rn])
					}
				}
			}()

			_, _ = io.Copy(c, backend)
		}(conn)
	}
}

// 29. QueryDoHOverFragment executes a DNS-over-HTTPS request through a fragmenting socket.
func (m *MahsaNgPreset) QueryDoHOverFragment(ctx context.Context, domain string, dohURL string, proxyAddr string) (string, error) {
	atomic.AddUint64(&m.dohQueryCount, 1)
	u, err := url.Parse(proxyAddr)
	if err != nil {
		return "", err
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(u),
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	req, err := http.NewRequestWithContext(ctx, "GET", dohURL+url.QueryEscape(domain)+"&type=A&ct=application/dns-json", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := readBoundedProxyHTTPBody(resp.Body, maxProxyControlHTTPBodyBytes, "DoH JSON response")
	if err != nil {
		return "", err
	}

	var dohResult struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &dohResult); err != nil {
		return "", err
	}
	for _, ans := range dohResult.Answer {
		if ans.Type == 1 { // A Record
			return ans.Data, nil
		}
	}
	return "", fmt.Errorf("no A record answer found")
}

// 30. GetDoHQueryCount returns total queries processed.
func (m *MahsaNgPreset) GetDoHQueryCount() uint64 {
	return atomic.LoadUint64(&m.dohQueryCount)
}

// 31. AddFakeHostSetting appends custom fake hosts headers.
func (m *MahsaNgPreset) AddFakeHostSetting(h FakeHostSetting) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FakeHosts = append(m.FakeHosts, h)
}

// 32. RemoveFakeHostSetting deletes fake hosts settings by ISP.
func (m *MahsaNgPreset) RemoveFakeHostSetting(isp string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var updated []FakeHostSetting
	for _, val := range m.FakeHosts {
		if val.ISP != isp {
			updated = append(updated, val)
		}
	}
	m.FakeHosts = updated
}

// 33. GetFakeHostSettings returns active fake hosts configurations.
func (m *MahsaNgPreset) GetFakeHostSettings() []FakeHostSetting {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]FakeHostSetting, len(m.FakeHosts))
	copy(copied, m.FakeHosts)
	return copied
}

// 34. ClearFakeHostSettings resets fake hosts configurations.
func (m *MahsaNgPreset) ClearFakeHostSettings() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FakeHosts = make([]FakeHostSetting, 0)
}

// 35. GetFakeHostSettingsCount returns count of active fake hosts.
func (m *MahsaNgPreset) GetFakeHostSettingsCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.FakeHosts)
}

// 36. AddCloudflareSetting registers custom ports and IPs limits.
func (m *MahsaNgPreset) AddCloudflareSetting(c CloudflareSetting) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CfSettings = append(m.CfSettings, c)
}

// 37. RemoveCloudflareSetting deletes custom limits by ISP.
func (m *MahsaNgPreset) RemoveCloudflareSetting(isp string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var updated []CloudflareSetting
	for _, val := range m.CfSettings {
		if val.ISP != isp {
			updated = append(updated, val)
		}
	}
	m.CfSettings = updated
}

// 38. GetCloudflareSettings returns active Cloudflare configurations.
func (m *MahsaNgPreset) GetCloudflareSettings() []CloudflareSetting {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]CloudflareSetting, len(m.CfSettings))
	copy(copied, m.CfSettings)
	return copied
}

// 39. ClearCloudflareSettings resets Cloudflare configurations.
func (m *MahsaNgPreset) ClearCloudflareSettings() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CfSettings = make([]CloudflareSetting, 0)
}

// 40. GetCloudflareSettingsCount returns count of active Cloudflare configurations.
func (m *MahsaNgPreset) GetCloudflareSettingsCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.CfSettings)
}

// 41. AddDoHSetting registers custom DoH endpoints.
func (m *MahsaNgPreset) AddDoHSetting(d DoHSetting) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DohSettings = append(m.DohSettings, d)
}

// 42. RemoveDoHSetting deletes custom DoH endpoints by ISP.
func (m *MahsaNgPreset) RemoveDoHSetting(isp string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var updated []DoHSetting
	for _, val := range m.DohSettings {
		if val.ISP != isp {
			updated = append(updated, val)
		}
	}
	m.DohSettings = updated
}

// 43. GetDoHSettings returns active DoH configurations.
func (m *MahsaNgPreset) GetDoHSettings() []DoHSetting {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]DoHSetting, len(m.DohSettings))
	copy(copied, m.DohSettings)
	return copied
}

// 44. ClearDoHSettings resets DoH configurations.
func (m *MahsaNgPreset) ClearDoHSettings() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DohSettings = make([]DoHSetting, 0)
}

// 45. GetDoHSettingsCount returns count of active DoH configurations.
func (m *MahsaNgPreset) GetDoHSettingsCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.DohSettings)
}

// 46. AddOfflineDNSSetting registers local domain overrides.
func (m *MahsaNgPreset) AddOfflineDNSSetting(domain, ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.OfflineDNSMap == nil {
		m.OfflineDNSMap = make(map[string]string)
	}
	m.OfflineDNSMap[domain] = ip
}

// 47. RemoveOfflineDNSSetting deletes local domain overrides.
func (m *MahsaNgPreset) RemoveOfflineDNSSetting(domain string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.OfflineDNSMap, domain)
}

// 48. GetOfflineDNSSettings returns active domain overrides registry map.
func (m *MahsaNgPreset) GetOfflineDNSSettings() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make(map[string]string)
	for k, v := range m.OfflineDNSMap {
		copied[k] = v
	}
	return copied
}

// 49. ClearOfflineDNSSettings resets domain overrides registry.
func (m *MahsaNgPreset) ClearOfflineDNSSettings() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.OfflineDNSMap = make(map[string]string)
}

// 50. GetOfflineDNSSettingsCount returns count of active domain overrides.
func (m *MahsaNgPreset) GetOfflineDNSSettingsCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.OfflineDNSMap)
}

// 51. GetListenIP returns the active local proxy listen IP.
func (m *MahsaNgPreset) GetListenIP() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.proxyListenIP
}

// 52. GetListenPort returns the active local proxy listen port.
func (m *MahsaNgPreset) GetListenPort() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.proxyListenPort
}

// 53. GetSocketTimeout returns default timeout limits.
func (m *MahsaNgPreset) GetSocketTimeout() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.socketTimeout
}

// 54. SetSocketTimeout configures default timeout limits.
func (m *MahsaNgPreset) SetSocketTimeout(timeout int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.socketTimeout = timeout
}

// 55. SetListenParams configures local proxy listen properties.
func (m *MahsaNgPreset) SetListenParams(ip string, port int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.proxyListenIP = ip
	m.proxyListenPort = port
}
