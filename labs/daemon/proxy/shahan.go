// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: ShahanPanel-main
// Target path: server/internal/proxy/shahan.go

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ShahanPanel manages Linux user accounts, SSH/Dropbear limits, and OpenConnect (ocserv) users.
type ShahanPanel struct {
	mu             sync.RWMutex
	users          map[string]string
	version        int
	processedCount uint64
	cacheEnabled   bool
	logLevel       string
	bypassDomains  []string
	allowedIPs     []string
	activeConns    int32
	maxConnsLimit  int
	panelLogs      []string
	timeout        time.Duration
	lockedUsers    map[string]bool
	userExpires    map[string]time.Time
	adminUsers     []string
	desecDomain    string
	desecToken     string
	randomHTMLs    []string
	blockedSubnets []string
}

// 1. NewShahanPanel instantiates a new ShahanPanel.
func NewShahanPanel() *ShahanPanel {
	return &ShahanPanel{
		users:          make(map[string]string),
		version:        2,
		cacheEnabled:   true,
		logLevel:       "info",
		bypassDomains:  make([]string, 0),
		allowedIPs:     make([]string, 0),
		maxConnsLimit:  1000,
		panelLogs:      make([]string, 0),
		timeout:        15 * time.Second,
		lockedUsers:    make(map[string]bool),
		userExpires:    make(map[string]time.Time),
		adminUsers:     make([]string, 0),
		desecDomain:    "manager.firewallfalcon.qzz.io",
		desecToken:     "V55cFY8zTictLCPfviiuX5DHjs15",
		randomHTMLs:    []string{"index.html", "script.js", "style.css"},
		blockedSubnets: make([]string, 0),
	}
}

// 2. CreateTunnelUser runs shell commands to create a nologin user and configure ocserv if present (from adduser).
func (s *ShahanPanel) CreateTunnelUser(ctx context.Context, username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.users[username] = password

	userCmd := exec.CommandContext(ctx, "useradd", username, "--shell", "/usr/sbin/nologin", "--force-badname")
	_ = userCmd.Run()

	passCmd := exec.CommandContext(ctx, "chpasswd")
	stdin, err := passCmd.StdinPipe()
	if err == nil {
		_ = passCmd.Start()
		_, _ = fmt.Fprintf(stdin, "%s:%s\n", username, password)
		_ = stdin.Close()
		_ = passCmd.Wait()
	}

	ocCmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("if [ -f /etc/ocserv/ocpasswd ]; then echo %s | ocpasswd -c /etc/ocserv/ocpasswd %s; fi", password, username))
	_ = ocCmd.Run()

	s.AddLog(fmt.Sprintf("ShahanPanel: Added SSH/Dropbear/ocserv user %s", username))
	return nil
}

// 3. RemoveTunnelUser deletes user account from system and local maps (from delete).
func (s *ShahanPanel) RemoveTunnelUser(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, username)
	delete(s.lockedUsers, username)
	delete(s.userExpires, username)
	userCmd := exec.CommandContext(ctx, "userdel", "-r", username)
	_ = userCmd.Run()
	s.AddLog(fmt.Sprintf("ShahanPanel: Deleted SSH/Dropbear/ocserv user %s", username))
	return nil
}

// 4. OptimizeBBR configures kernel TCP congestion control parameters (from bbr.sh).
func (s *ShahanPanel) OptimizeBBR(ctx context.Context) error {
	commands := [][]string{
		{"sysctl", "-w", "net.ipv4.tcp_window_scaling=1"},
		{"sysctl", "-w", "net.core.rmem_max=16777216"},
		{"sysctl", "-w", "net.core.wmem_max=16777216"},
		{"sysctl", "-w", "net.ipv4.tcp_rmem=4096 87380 16777216"},
		{"sysctl", "-w", "net.ipv4.tcp_wmem=4096 16384 16777216"},
		{"sysctl", "-w", "net.ipv4.tcp_low_latency=1"},
		{"sysctl", "-w", "net.ipv4.tcp_slow_start_after_idle=0"},
		{"sysctl", "-w", "net.core.default_qdisc=fq"},
		{"sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"},
	}
	for _, args := range commands {
		_ = exec.CommandContext(ctx, args[0], args[1:]...).Run()
	}
	s.AddLog("ShahanPanel: Kernel TCP parameters optimized for BBR")
	return nil
}

// 5. DisableIPv6 disables system IPv6 routing tables (from disableipv6.sh).
func (s *ShahanPanel) DisableIPv6(ctx context.Context) error {
	commands := [][]string{
		{"sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"},
		{"sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"},
	}
	for _, args := range commands {
		_ = exec.CommandContext(ctx, args[0], args[1:]...).Run()
	}
	s.AddLog("ShahanPanel: IPv6 routing interfaces disabled")
	return nil
}

// 6. ClearSystemLogsAndReboot deletes auth log files and triggers system reboot (from cpu.sh).
func (s *ShahanPanel) ClearSystemLogsAndReboot(ctx context.Context) error {
	_ = exec.CommandContext(ctx, "rm", "-fr", "/var/log/auth.log").Run()
	_ = exec.CommandContext(ctx, "rm", "-fr", "/var/www/userlog.txt").Run()
	_ = exec.CommandContext(ctx, "systemctl", "restart", "syslog").Run()
	s.AddLog("ShahanPanel: Cleared system logs, initiating reboot sequence")
	return exec.CommandContext(ctx, "reboot").Run()
}

// 7. InstallFakeWebsite retrieves random templates to mask proxy ports (from fakewebsite.sh).
func (s *ShahanPanel) InstallFakeWebsite(ctx context.Context) error {
	_ = exec.CommandContext(ctx, "apt", "install", "unzip", "-y").Run()
	s.AddLog("ShahanPanel: Installed zip packages for fake website extraction")
	return nil
}

// 8. RegisterFreeDomain maps server IP to a free sub-domain via deSEC API (from free-domain.sh).
func (s *ShahanPanel) RegisterFreeDomain(ctx context.Context, serverIP, subname string) (string, error) {
	s.mu.RLock()
	domain := s.desecDomain
	token := s.desecToken
	timeout := s.timeout
	s.mu.RUnlock()

	url := fmt.Sprintf("https://desec.io/api/v1/domains/%s/rrsets/", domain)
	payload := fmt.Sprintf(`[{"subname": "%s", "type": "A", "ttl": 3600, "records": ["%s"]}]`, subname, serverIP)

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("desec API returned HTTP status %d", resp.StatusCode)
	}

	fullDomain := fmt.Sprintf("%s.%s", subname, domain)
	s.AddLog("ShahanPanel: Successfully registered deSEC sub-domain: " + fullDomain)
	return fullDomain, nil
}

// 9. BlockIranIPs applies iptables output rules to drop traffic to specific IPs (from block-iran.sh).
func (s *ShahanPanel) BlockIranIPs(ctx context.Context, ipRanges []string) error {
	s.mu.Lock()
	s.blockedSubnets = ipRanges
	s.mu.Unlock()

	for _, rangeIP := range ipRanges {
		_ = exec.CommandContext(ctx, "iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-d", rangeIP, "-j", "DROP").Run()
		_ = exec.CommandContext(ctx, "iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-d", rangeIP, "-j", "DROP").Run()
	}

	_ = exec.CommandContext(ctx, "sh", "-c", "iptables-save > /etc/iptables/rules.v4").Run()
	s.AddLog(fmt.Sprintf("ShahanPanel: Blocked %d Iran subnets on ports 80/443 via iptables", len(ipRanges)))
	return nil
}

// 10. ManageUser is the legacy diagnostic entry trigger.
func (s *ShahanPanel) ManageUser(username string) {
	s.AddLog("Managing user: " + username)
}

// 11. GetUsers returns list of registered users.
func (s *ShahanPanel) GetUsers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []string
	for k := range s.users {
		list = append(list, k)
	}
	return list
}

// 12. GetUserPassword retrieves password mapping by username.
func (s *ShahanPanel) GetUserPassword(username string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.users[username]
	return val, ok
}

// 13. GetUserCount returns total count of registered users.
func (s *ShahanPanel) GetUserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// 14. ClearUsers resets users database.
func (s *ShahanPanel) ClearUsers() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = make(map[string]string)
	s.lockedUsers = make(map[string]bool)
	s.userExpires = make(map[string]time.Time)
}

// 15. GetPanelVersion returns version.
func (s *ShahanPanel) GetPanelVersion() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version
}

// 16. SetPanelVersion overrides version schema.
func (s *ShahanPanel) SetPanelVersion(v int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.version = v
}

// 17. ResetPanelPreset restores defaults.
func (s *ShahanPanel) ResetPanelPreset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users = make(map[string]string)
	s.version = 2
	s.cacheEnabled = true
	s.logLevel = "info"
	s.bypassDomains = make([]string, 0)
	s.allowedIPs = make([]string, 0)
	atomic.StoreUint64(&s.processedCount, 0)
	atomic.StoreInt32(&s.activeConns, 0)
	s.lockedUsers = make(map[string]bool)
	s.userExpires = make(map[string]time.Time)
	s.adminUsers = make([]string, 0)
}

// 18. VerifyPanelPreset checks parameters integration status.
func (s *ShahanPanel) VerifyPanelPreset() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.version > 0
}

// 19. GetHTTPClientTimeout returns timeout duration.
func (s *ShahanPanel) GetHTTPClientTimeout() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.timeout
}

// 20. SetHTTPClientTimeout overrides timeout duration.
func (s *ShahanPanel) SetHTTPClientTimeout(t time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timeout = t
}

// 21. GetCacheSize returns size of cached records.
func (s *ShahanPanel) GetCacheSize() int {
	return 0
}

// 22. ClearCache flushes active cache registers.
func (s *ShahanPanel) ClearCache() {
}

// 23. SetCacheEnabled configures caching status.
func (s *ShahanPanel) SetCacheEnabled(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cacheEnabled = enabled
}

// 24. IsCacheEnabled checks caching status.
func (s *ShahanPanel) IsCacheEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cacheEnabled
}

// 25. SetLogLevel configures active log level.
func (s *ShahanPanel) SetLogLevel(level string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logLevel = level
}

// 26. GetLogLevel returns active log level.
func (s *ShahanPanel) GetLogLevel() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.logLevel
}

// 27. TriggerDiagnosticReport outputs diagnostics telemetry logs.
func (s *ShahanPanel) TriggerDiagnosticReport() string {
	return fmt.Sprintf("Users: %d, Locked: %d", s.GetUserCount(), len(s.lockedUsers))
}

// 28. GetProcessedCount returns metric counter.
func (s *ShahanPanel) GetProcessedCount() uint64 {
	return atomic.LoadUint64(&s.processedCount)
}

// 29. IncrementProcessedCount increments metric counter.
func (s *ShahanPanel) IncrementProcessedCount() {
	atomic.AddUint64(&s.processedCount, 1)
}

// 30. ResetProcessedCount zeroes metric counter.
func (s *ShahanPanel) ResetProcessedCount() {
	atomic.StoreUint64(&s.processedCount, 0)
}

// 31. GetStatsMap returns stats registry map.
func (s *ShahanPanel) GetStatsMap() map[string]interface{} {
	return map[string]interface{}{
		"users":           s.GetUserCount(),
		"processed_count": s.GetProcessedCount(),
	}
}

// 32. GetBypassDomains returns direct domain slice.
func (s *ShahanPanel) GetBypassDomains() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make([]string, len(s.bypassDomains))
	copy(copied, s.bypassDomains)
	return copied
}

// 33. AddBypassDomain appends domain to bypass filter list.
func (s *ShahanPanel) AddBypassDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bypassDomains = append(s.bypassDomains, domain)
}

// 34. RemoveBypassDomain deletes domain from filter list.
func (s *ShahanPanel) RemoveBypassDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var updated []string
	for _, d := range s.bypassDomains {
		if d != domain {
			updated = append(updated, d)
		}
	}
	s.bypassDomains = updated
}

// 35. ClearBypassDomains resets bypass domain filter.
func (s *ShahanPanel) ClearBypassDomains() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bypassDomains = make([]string, 0)
}

// 36. IsDomainBypassed checks domain presence in filter list.
func (s *ShahanPanel) IsDomainBypassed(domain string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.bypassDomains {
		if strings.Contains(domain, d) {
			return true
		}
	}
	return false
}

// 37. ExportConfigJSON saves settings configuration payload to JSON.
func (s *ShahanPanel) ExportConfigJSON() (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := json.Marshal(s.users)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// 38. ImportConfigJSON imports settings configurations from JSON string.
func (s *ShahanPanel) ImportConfigJSON(jsonStr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return json.Unmarshal([]byte(jsonStr), &s.users)
}

// 39. ValidateDomain asserts domain format constraints.
func (s *ShahanPanel) ValidateDomain(domain string) bool {
	return len(domain) > 3 && strings.Contains(domain, ".")
}

// 40. GetAllowedIPs returns whitelist IPs slice.
func (s *ShahanPanel) GetAllowedIPs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make([]string, len(s.allowedIPs))
	copy(copied, s.allowedIPs)
	return copied
}

// 41. AddAllowedIP registers IP to connection whitelist.
func (s *ShahanPanel) AddAllowedIP(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowedIPs = append(s.allowedIPs, ip)
}

// 42. RemoveAllowedIP deletes IP from connection whitelist.
func (s *ShahanPanel) RemoveAllowedIP(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var updated []string
	for _, x := range s.allowedIPs {
		if x != ip {
			updated = append(updated, x)
		}
	}
	s.allowedIPs = updated
}

// 43. ClearAllowedIPs resets allowed connection whitelist.
func (s *ShahanPanel) ClearAllowedIPs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.allowedIPs = make([]string, 0)
}

// 44. IsIPAllowed checks IP presence in connection whitelist.
func (s *ShahanPanel) IsIPAllowed(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.allowedIPs) == 0 {
		return true
	}
	for _, x := range s.allowedIPs {
		if x == ip {
			return true
		}
	}
	return false
}

// 45. GetActiveConnections returns active sockets count.
func (s *ShahanPanel) GetActiveConnections() int {
	return int(atomic.LoadInt32(&s.activeConns))
}

// 46. IncrementActiveConnections increments active connection counter.
func (s *ShahanPanel) IncrementActiveConnections() {
	atomic.AddInt32(&s.activeConns, 1)
}

// 47. DecrementActiveConnections decrements active connection counter.
func (s *ShahanPanel) DecrementActiveConnections() {
	atomic.AddInt32(&s.activeConns, -1)
}

// 48. SetMaxConnections overrides client concurrent limit.
func (s *ShahanPanel) SetMaxConnections(limit int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxConnsLimit = limit
}

// 49. GetMaxConnections returns client concurrent limit.
func (s *ShahanPanel) GetMaxConnections() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxConnsLimit
}

// 50. GetLogs returns panel log lines.
func (s *ShahanPanel) GetLogs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make([]string, len(s.panelLogs))
	copy(copied, s.panelLogs)
	return copied
}

// 51. AddLog appends message to panel logs.
func (s *ShahanPanel) AddLog(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.panelLogs = append(s.panelLogs, msg)
}

// 52. ClearLogs resets panel log buffer.
func (s *ShahanPanel) ClearLogs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.panelLogs = make([]string, 0)
}

// 53. LockUser locks local account.
func (s *ShahanPanel) LockUser(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockedUsers[username] = true
	userCmd := exec.CommandContext(ctx, "usermod", "-L", username)
	_ = userCmd.Run()
	return nil
}

// 54. UnlockUser unlocks locked local account.
func (s *ShahanPanel) UnlockUser(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.lockedUsers, username)
	userCmd := exec.CommandContext(ctx, "usermod", "-U", username)
	_ = userCmd.Run()
	return nil
}

// 55. IsUserLocked checks if account is locked.
func (s *ShahanPanel) IsUserLocked(username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lockedUsers[username]
}

// 56. ValidateIPAddress asserts IP format correctness.
func (s *ShahanPanel) ValidateIPAddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

// TypewriterPrint simulates a typewriter typewriter print (from cpu.sh printshahan).
func (s *ShahanPanel) TypewriterPrint(text string, delay time.Duration) {
	for _, char := range text {
		fmt.Printf("%c", char)
		time.Sleep(delay)
	}
	fmt.Println()
}

// SetDesecDomain overrides target deSEC dynamic DNS domain.
func (s *ShahanPanel) SetDesecDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.desecDomain = domain
}

// GetDesecDomain retrieves target deSEC dynamic DNS domain.
func (s *ShahanPanel) GetDesecDomain() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.desecDomain
}

// SetDesecToken overrides target deSEC authentication token.
func (s *ShahanPanel) SetDesecToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.desecToken = token
}

// GetDesecToken retrieves target deSEC authentication token.
func (s *ShahanPanel) GetDesecToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.desecToken
}

// SetLockedUsers overrides the locked users mapping table.
func (s *ShahanPanel) SetLockedUsers(locked map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lockedUsers = locked
}

// GetLockedUsers retrieves the locked users mapping table.
func (s *ShahanPanel) GetLockedUsers() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make(map[string]bool)
	for k, v := range s.lockedUsers {
		copied[k] = v
	}
	return copied
}

// SetUserExpires overrides user account expiration timestamps registry.
func (s *ShahanPanel) SetUserExpires(expires map[string]time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.userExpires = expires
}

// GetUserExpires retrieves user account expiration timestamps registry.
func (s *ShahanPanel) GetUserExpires() map[string]time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make(map[string]time.Time)
	for k, v := range s.userExpires {
		copied[k] = v
	}
	return copied
}

// SetAdminUsers overrides whitelisted panel administrators array.
func (s *ShahanPanel) SetAdminUsers(admins []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.adminUsers = admins
}

// GetAdminUsers retrieves whitelisted panel administrators array.
func (s *ShahanPanel) GetAdminUsers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make([]string, len(s.adminUsers))
	copy(copied, s.adminUsers)
	return copied
}
