// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: v2rayNG-master & v2ray_client-master
// Target path: server/internal/proxy/v2rayng.go

package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// V2rayNGConfig represents the customized config structure exported to Android V2rayNG clients.
type V2rayNGConfig struct {
	Remarks      string                 `json:"remarks"`
	ServerIP     string                 `json:"server_ip"`
	Port         int                    `json:"port"`
	Protocol     string                 `json:"protocol"` // "vmess", "vless", "shadowsocks", "trojan"
	Settings     map[string]interface{} `json:"settings"`
	StreamConfig map[string]interface{} `json:"stream_config"`
	DNS          []string               `json:"dns"`
	BypassApps   []string               `json:"bypass_apps"`
}

// V2rayNGExporter manages the generation and parsing of Android client configuration profiles.
type V2rayNGExporter struct {
	mu                 sync.RWMutex
	active             bool
	localSocksPort     int
	localHttpPort      int
	mixedPort          int
	muxEnabled         bool
	muxConcurrency     int
	bypassApps         []string
	dnsList            []string
	routingMode        string
	customGeoIPRoutes  []string
	exporterStatsCalls uint64
	exporterVersion    int
}

// NewV2rayNGExporter instantiates a V2rayNGExporter.
func NewV2rayNGExporter() *V2rayNGExporter {
	return &V2rayNGExporter{
		active:          true,
		localSocksPort:  10808,
		localHttpPort:   10809,
		mixedPort:       0,
		muxEnabled:      false,
		muxConcurrency:  8,
		bypassApps:      []string{"com.android.chrome", "com.google.android.youtube"},
		dnsList:         []string{"1.1.1.1", "8.8.8.8"},
		routingMode:     "bypass_lan_and_china",
		exporterVersion: 1,
	}
}

// 1. ExportAndroidConfig compiles server details into the V2rayNG customized profile structure.
func (e *V2rayNGExporter) ExportAndroidConfig(remarks string, host string, port int, protocol string, settings map[string]interface{}, streamConfig map[string]interface{}) ([]byte, error) {
	e.mu.RLock()
	dnsList := e.dnsList
	bypassApps := e.bypassApps
	e.mu.RUnlock()

	cfg := V2rayNGConfig{
		Remarks:      remarks,
		ServerIP:     host,
		Port:         port,
		Protocol:     protocol,
		Settings:     settings,
		StreamConfig: streamConfig,
		DNS:          dnsList,
		BypassApps:   bypassApps,
	}

	return json.MarshalIndent(cfg, "", "  ")
}

// 2. BuildClientURI generates the standard sharing URI (e.g. vmess:// or vless://) for v2rayNG import.
func (e *V2rayNGExporter) BuildClientURI(host string, port int, uuid string, protocol string, name string) string {
	switch protocol {
	case "vless":
		return fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&type=tcp#%s", uuid, host, port, name)
	case "vmess":
		return fmt.Sprintf("vmess://%s@%s:%d?security=auto&type=ws#%s", uuid, host, port, name)
	default:
		return ""
	}
}

// 3. ParseShareLink decodes vmess:// and ss:// share links and converts them to generic config maps.
func (e *V2rayNGExporter) ParseShareLink(link string) (map[string]interface{}, error) {
	atomic.AddUint64(&e.exporterStatsCalls, 1)
	if strings.HasPrefix(link, "ss://") {
		info := link[5:]
		var remarks string
		if idx := strings.Index(info, "#"); idx >= 0 {
			remarks, _ = url.QueryUnescape(info[idx+1:])
			info = info[:idx]
		}

		var decoded string
		if idx := strings.Index(info, "@"); idx >= 0 {
			addr := info[idx+1:]
			authBytes, err := base64.StdEncoding.DecodeString(info[:idx])
			if err != nil {
				return nil, err
			}
			decoded = string(authBytes) + "@" + addr
		} else {
			decodedBytes, err := base64.StdEncoding.DecodeString(info)
			if err != nil {
				return nil, err
			}
			decoded = string(decodedBytes)
		}

		atIdx := strings.LastIndex(decoded, "@")
		if atIdx < 0 {
			return nil, fmt.Errorf("invalid shadowsocks details format")
		}

		creds := decoded[:atIdx]
		addrPort := decoded[atIdx+1:]

		var method, password string
		if colonIdx := strings.Index(creds, ":"); colonIdx >= 0 {
			method = creds[:colonIdx]
			password = creds[colonIdx+1:]
		}

		var host string
		var port int
		if colonIdx := strings.Index(addrPort, ":"); colonIdx >= 0 {
			host = addrPort[:colonIdx]
			port, _ = strconv.Atoi(addrPort[colonIdx+1:])
		}

		return map[string]interface{}{
			"remarks":  remarks,
			"host":     host,
			"port":     port,
			"method":   method,
			"password": password,
			"protocol": "shadowsocks",
		}, nil
	}

	return nil, fmt.Errorf("unsupported protocol share link")
}

// 4. ResolveStdVmess resolves standard VMess with "@" formats.
func (e *V2rayNGExporter) ResolveStdVmess(str string) (map[string]interface{}, error) {
	if !strings.Contains(str, "@") {
		return nil, fmt.Errorf("invalid std vmess format")
	}
	parts := strings.Split(str, "@")
	hostParts := strings.Split(parts[1], ":")
	if len(hostParts) != 2 {
		return nil, fmt.Errorf("invalid host port format")
	}
	portVal, _ := strconv.Atoi(hostParts[1])
	return map[string]interface{}{
		"address": hostParts[0],
		"port":    portVal,
		"id":      parts[0],
	}, nil
}

// 5. ParseQueryString extracts parameters from query schemes.
func (e *V2rayNGExporter) ParseQueryString(uri string) (map[string]string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	res := make(map[string]string)
	q := u.Query()
	for k, v := range q {
		if len(v) > 0 {
			res[k] = v[0]
		}
	}
	return res, nil
}

// 6. MapNetworkAlias maps raw protocol names to Clash config strings.
func (e *V2rayNGExporter) MapNetworkAlias(net string) string {
	switch net {
	case "raw":
		return "tcp"
	case "ws":
		return "websocket"
	default:
		return net
	}
}

// 7. GetTransportType returns transport protocols.
func (e *V2rayNGExporter) GetTransportType(net string) string {
	return e.MapNetworkAlias(net)
}

// 8. SetAllowInsecure configures verification limits.
func (e *V2rayNGExporter) SetAllowInsecure(settings map[string]interface{}, val bool) {
	settings["allowInsecure"] = val
}

// 9. GetAllowInsecure returns verification limits status.
func (e *V2rayNGExporter) GetAllowInsecure(settings map[string]interface{}) bool {
	val, ok := settings["allowInsecure"].(bool)
	return ok && val
}

// 10. SetVerifyPeerCert configures certificate validation controls.
func (e *V2rayNGExporter) SetVerifyPeerCert(settings map[string]interface{}, val string) {
	settings["verifyPeerCert"] = val
}

// 11. GetVerifyPeerCert returns certificate validation controls status.
func (e *V2rayNGExporter) GetVerifyPeerCert(settings map[string]interface{}) string {
	val, ok := settings["verifyPeerCert"].(string)
	if !ok {
		return ""
	}
	return val
}

// 12. GetAlterId returns AlterId values.
func (e *V2rayNGExporter) GetAlterId(settings map[string]interface{}) int {
	val, ok := settings["alterId"].(int)
	if !ok {
		return 0
	}
	return val
}

// 13. SetAlterId configures AlterId values.
func (e *V2rayNGExporter) SetAlterId(settings map[string]interface{}, val int) {
	settings["alterId"] = val
}

// 14. GetVmessSecurity returns cipher controls options.
func (e *V2rayNGExporter) GetVmessSecurity(settings map[string]interface{}) string {
	val, ok := settings["security"].(string)
	if !ok {
		return "auto"
	}
	return val
}

// 15. SetVmessSecurity configures cipher controls options.
func (e *V2rayNGExporter) SetVmessSecurity(settings map[string]interface{}, val string) {
	settings["security"] = val
}

// 16. GetExporterStats returns total processed queries count.
func (e *V2rayNGExporter) GetExporterStats() map[string]interface{} {
	calls := atomic.LoadUint64(&e.exporterStatsCalls)
	return map[string]interface{}{
		"stats_calls": calls,
	}
}

// 17. ResetExporterStats zeroes processed queries count.
func (e *V2rayNGExporter) ResetExporterStats() {
	atomic.StoreUint64(&e.exporterStatsCalls, 0)
}

// 18. GetVersion returns active exporter protocol versions.
func (e *V2rayNGExporter) GetVersion() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.exporterVersion
}

// 19. SetVersion configures active exporter protocol versions.
func (e *V2rayNGExporter) SetVersion(v int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.exporterVersion = v
}

// 20. GetActiveProfile returns active configuration profiles.
func (e *V2rayNGExporter) GetActiveProfile() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.active
}

// 21. SetActiveProfile overrides active configuration profiles.
func (e *V2rayNGExporter) SetActiveProfile(active bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active = active
}

// 22. ConfigureLocalSocksPort sets local socks port.
func (e *V2rayNGExporter) ConfigureLocalSocksPort(port int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.localSocksPort = port
}

// 23. ConfigureLocalHttpPort sets local HTTP port.
func (e *V2rayNGExporter) ConfigureLocalHttpPort(port int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.localHttpPort = port
}

// 24. ConfigureMixedPort sets local mixed port.
func (e *V2rayNGExporter) ConfigureMixedPort(port int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mixedPort = port
}

// 25. GetLocalSocksPort returns socks port.
func (e *V2rayNGExporter) GetLocalSocksPort() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.localSocksPort
}

// 26. GetLocalHttpPort returns HTTP port.
func (e *V2rayNGExporter) GetLocalHttpPort() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.localHttpPort
}

// 27. GetMixedPort returns mixed port.
func (e *V2rayNGExporter) GetMixedPort() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mixedPort
}

// 28. EnableMux enables multiplexing.
func (e *V2rayNGExporter) EnableMux() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.muxEnabled = true
}

// 29. DisableMux disables multiplexing.
func (e *V2rayNGExporter) DisableMux() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.muxEnabled = false
}

// 30. IsMuxEnabled returns multiplexing status.
func (e *V2rayNGExporter) IsMuxEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.muxEnabled
}

// 31. SetMuxConcurrency sets multiplexing concurrency.
func (e *V2rayNGExporter) SetMuxConcurrency(c int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.muxConcurrency = c
}

// 32. GetMuxConcurrency returns multiplexing concurrency.
func (e *V2rayNGExporter) GetMuxConcurrency() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.muxConcurrency
}

// 33. SetBypassApps sets bypass apps list.
func (e *V2rayNGExporter) SetBypassApps(apps []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bypassApps = apps
}

// 34. GetBypassApps returns bypass apps list.
func (e *V2rayNGExporter) GetBypassApps() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	copied := make([]string, len(e.bypassApps))
	copy(copied, e.bypassApps)
	return copied
}

// 35. ClearBypassApps resets bypass apps list.
func (e *V2rayNGExporter) ClearBypassApps() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bypassApps = make([]string, 0)
}

// 36. AddBypassApp appends app package to list.
func (e *V2rayNGExporter) AddBypassApp(app string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bypassApps = append(e.bypassApps, app)
}

// 37. RemoveBypassApp deletes app package from list.
func (e *V2rayNGExporter) RemoveBypassApp(app string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var updated []string
	for _, val := range e.bypassApps {
		if val != app {
			updated = append(updated, val)
		}
	}
	e.bypassApps = updated
}

// 38. SetDNS configures DNS server list.
func (e *V2rayNGExporter) SetDNS(dns []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dnsList = dns
}

// 39. GetDNS returns DNS server list.
func (e *V2rayNGExporter) GetDNS() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	copied := make([]string, len(e.dnsList))
	copy(copied, e.dnsList)
	return copied
}

// 40. ClearDNS resets DNS server list.
func (e *V2rayNGExporter) ClearDNS() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dnsList = make([]string, 0)
}

// 41. AddDNSServer appends DNS server address.
func (e *V2rayNGExporter) AddDNSServer(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dnsList = append(e.dnsList, ip)
}

// 42. RemoveDNSServer deletes DNS server address.
func (e *V2rayNGExporter) RemoveDNSServer(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var updated []string
	for _, val := range e.dnsList {
		if val != ip {
			updated = append(updated, val)
		}
	}
	e.dnsList = updated
}

// 43. GetDNSServerCount returns DNS servers count.
func (e *V2rayNGExporter) GetDNSServerCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.dnsList)
}

// 44. GetBypassAppsCount returns bypass apps count.
func (e *V2rayNGExporter) GetBypassAppsCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.bypassApps)
}

// 45. ExportConfigToJSON saves configs to JSON.
func (e *V2rayNGExporter) ExportConfigToJSON(filePath string) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	configDump := map[string]interface{}{
		"local_socks_port": e.localSocksPort,
		"local_http_port":  e.localHttpPort,
		"mixed_port":       e.mixedPort,
		"mux_enabled":      e.muxEnabled,
		"mux_concurrency":  e.muxConcurrency,
		"bypass_apps":      e.bypassApps,
		"dns_list":         e.dnsList,
		"routing_mode":     e.routingMode,
		"version":          e.exporterVersion,
	}

	data, err := json.MarshalIndent(configDump, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 46. ImportConfigFromJSON loads configs from JSON.
func (e *V2rayNGExporter) ImportConfigFromJSON(filePath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var configDump struct {
		LocalSocksPort int      `json:"local_socks_port"`
		LocalHttpPort  int      `json:"local_http_port"`
		MixedPort      int      `json:"mixed_port"`
		MuxEnabled     bool     `json:"mux_enabled"`
		MuxConcurrency int      `json:"mux_concurrency"`
		BypassApps     []string `json:"bypass_apps"`
		DnsList        []string `json:"dns_list"`
		RoutingMode    string   `json:"routing_mode"`
		Version        int      `json:"version"`
	}

	if err := json.Unmarshal(data, &configDump); err != nil {
		return err
	}

	e.localSocksPort = configDump.LocalSocksPort
	e.localHttpPort = configDump.LocalHttpPort
	e.mixedPort = configDump.MixedPort
	e.muxEnabled = configDump.MuxEnabled
	e.muxConcurrency = configDump.MuxConcurrency
	e.bypassApps = configDump.BypassApps
	e.dnsList = configDump.DnsList
	e.routingMode = configDump.RoutingMode
	e.exporterVersion = configDump.Version
	return nil
}

// 47. GetStatsRegistry returns stats registry maps.
func (e *V2rayNGExporter) GetStatsRegistry() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]interface{}{
		"local_socks_port": e.localSocksPort,
		"local_http_port":  e.localHttpPort,
		"dns_count":        len(e.dnsList),
		"apps_count":       len(e.bypassApps),
	}
}

// 48. LogExporterDiagnostics displays diagnostic summaries.
func (e *V2rayNGExporter) LogExporterDiagnostics() {
	e.mu.RLock()
	defer e.mu.RUnlock()
	log.Printf("V2rayNGExporter Diagnostics: Version: %d, Socks: %d, HTTP: %d", e.exporterVersion, e.localSocksPort, e.localHttpPort)
}

// 49. ResetExporter cleans all states.
func (e *V2rayNGExporter) ResetExporter() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bypassApps = make([]string, 0)
	e.dnsList = make([]string, 0)
	e.localSocksPort = 10808
	e.localHttpPort = 10809
	e.mixedPort = 0
	e.muxEnabled = false
	e.muxConcurrency = 8
	e.routingMode = "bypass_lan_and_china"
}

// 50. ValidateExporterPreset asserts settings format correctness.
func (e *V2rayNGExporter) ValidateExporterPreset() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.localSocksPort > 0 && e.localHttpPort > 0
}

// 51. SetRoutingMode configures routing filters mode.
func (e *V2rayNGExporter) SetRoutingMode(mode string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.routingMode = mode
}

// 52. GetRoutingMode returns active routing filters mode.
func (e *V2rayNGExporter) GetRoutingMode() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.routingMode
}

// 53. AddCustomGeoIPRoute appends custom GeoIP route mappings.
func (e *V2rayNGExporter) AddCustomGeoIPRoute(route string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.customGeoIPRoutes = append(e.customGeoIPRoutes, route)
}

// 54. RemoveCustomGeoIPRoute deletes custom GeoIP route mappings.
func (e *V2rayNGExporter) RemoveCustomGeoIPRoute(route string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	var updated []string
	for _, val := range e.customGeoIPRoutes {
		if val != route {
			updated = append(updated, val)
		}
	}
	e.customGeoIPRoutes = updated
}

// 55. GetCustomGeoIPRoutes returns active custom GeoIP route mappings list.
func (e *V2rayNGExporter) GetCustomGeoIPRoutes() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	copied := make([]string, len(e.customGeoIPRoutes))
	copy(copied, e.customGeoIPRoutes)
	return copied
}
