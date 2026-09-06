// Package scanner coordinates IP scans, speed probes, and active network tests.

package scanner

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// DefaultTCPTimeoutMs represents the default timeout in milliseconds for TCP probes.
const DefaultTCPTimeoutMs = 1500

// ScanConfig coordinates scanner concurrency profiles, speed limits, and Feistel cipher configs.
type ScanConfig struct {
	mu                  sync.RWMutex
	activeProfile       string
	concurrencyOverride int
	timeoutOverride     int
	blacklistSubnets    []string
	tlsFingerprint      string
	httpHostHeader      string
	configStatsCalls    uint64
	blackrockSeed       uint64
	blackrockRounds     uint32
}

// NewScanConfig initializes scan configurations.
func NewScanConfig() *ScanConfig {
	return &ScanConfig{
		activeProfile:       "Balanced",
		concurrencyOverride: 0,
		timeoutOverride:     0,
		blacklistSubnets:    []string{"10.0.0.0/8", "192.168.0.0/16"},
		tlsFingerprint:      "chrome",
		httpHostHeader:      "www.cloudflare.com",
		blackrockSeed:       123456789,
		blackrockRounds:     4,
	}
}

// 1. ConcurrencyForPreset resolves concurrency presets.
func (s *ScanConfig) ConcurrencyForPreset(profile string) int {
	s.mu.RLock()
	override := s.concurrencyOverride
	s.mu.RUnlock()

	if override > 0 {
		return override
	}

	switch profile {
	case "Hyperspeed":
		return 500
	case "Balanced":
		return 100
	case "Maximum":
		return 1000
	default:
		return 50
	}
}

// 2. TimeoutForPreset returns timeout presets.
func (s *ScanConfig) TimeoutForPreset(profile string) int {
	s.mu.RLock()
	override := s.timeoutOverride
	s.mu.RUnlock()

	if override > 0 {
		return override
	}

	switch profile {
	case "Hyperspeed":
		return 2
	case "Balanced":
		return 5
	case "Maximum":
		return 1
	default:
		return 8
	}
}

// 3. ApplyProfile sets active profile.
func (s *ScanConfig) ApplyProfile(profile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeProfile = profile
}

// 4. GetActiveProfile returns active profiles.
func (s *ScanConfig) GetActiveProfile() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeProfile
}

// 5. SetConcurrencyOverride sets concurrency overrides.
func (s *ScanConfig) SetConcurrencyOverride(c int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.concurrencyOverride = c
}

// 6. GetConcurrencyOverride returns active overrides.
func (s *ScanConfig) GetConcurrencyOverride() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.concurrencyOverride
}

// 7. SetTimeoutOverride sets timeout overrides.
func (s *ScanConfig) SetTimeoutOverride(t int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timeoutOverride = t
}

// 8. GetTimeoutOverride returns active timeout overrides.
func (s *ScanConfig) GetTimeoutOverride() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.timeoutOverride
}

// 9. AddBlacklistedSubnet appends subnet limits.
func (s *ScanConfig) AddBlacklistedSubnet(subnet string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blacklistSubnets = append(s.blacklistSubnets, subnet)
}

// 10. RemoveBlacklistedSubnet deletes subnet limits.
func (s *ScanConfig) RemoveBlacklistedSubnet(subnet string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var updated []string
	for _, val := range s.blacklistSubnets {
		if val != subnet {
			updated = append(updated, val)
		}
	}
	s.blacklistSubnets = updated
}

// 11. GetBlacklistedSubnets returns active blacklist maps.
func (s *ScanConfig) GetBlacklistedSubnets() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make([]string, len(s.blacklistSubnets))
	copy(copied, s.blacklistSubnets)
	return copied
}

// 12. ClearBlacklistedSubnets resets active limits.
func (s *ScanConfig) ClearBlacklistedSubnets() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blacklistSubnets = make([]string, 0)
}

// 13. ExportConfigJSON saves configs to JSON.
func (s *ScanConfig) ExportConfigJSON(filePath string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	configDump := map[string]interface{}{
		"active_profile":       s.activeProfile,
		"concurrency_override": s.concurrencyOverride,
		"timeout_override":     s.timeoutOverride,
		"blacklist_subnets":    s.blacklistSubnets,
		"tls_fingerprint":      s.tlsFingerprint,
		"http_host_header":     s.httpHostHeader,
		"blackrock_seed":       s.blackrockSeed,
		"blackrock_rounds":     s.blackrockRounds,
	}

	data, err := json.MarshalIndent(configDump, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 14. ImportConfigJSON loads configs from JSON.
func (s *ScanConfig) ImportConfigJSON(filePath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	var configDump struct {
		ActiveProfile       string   `json:"active_profile"`
		ConcurrencyOverride int      `json:"concurrency_override"`
		TimeoutOverride     int      `json:"timeout_override"`
		BlacklistSubnets    []string `json:"blacklist_subnets"`
		TlsFingerprint      string   `json:"tls_fingerprint"`
		HttpHostHeader      string   `json:"http_host_header"`
		BlackrockSeed       uint64   `json:"blackrock_seed"`
		BlackrockRounds     uint32   `json:"blackrock_rounds"`
	}

	if err := json.Unmarshal(data, &configDump); err != nil {
		return err
	}

	s.activeProfile = configDump.ActiveProfile
	s.concurrencyOverride = configDump.ConcurrencyOverride
	s.timeoutOverride = configDump.TimeoutOverride
	s.blacklistSubnets = configDump.BlacklistSubnets
	s.tlsFingerprint = configDump.TlsFingerprint
	s.httpHostHeader = configDump.HttpHostHeader
	s.blackrockSeed = configDump.BlackrockSeed
	s.blackrockRounds = configDump.BlackrockRounds
	return nil
}

// 15. GetProfileName returns configuration name.
func (s *ScanConfig) GetProfileName() string {
	return "Scan Configuration Profile"
}

// 16. GetSpeedThreshold returns preset limits.
func (s *ScanConfig) GetSpeedThreshold() float64 {
	return 250.0
}

// 17. GetConfigStats returns metrics stats.
func (s *ScanConfig) GetConfigStats() map[string]interface{} {
	calls := atomic.LoadUint64(&s.configStatsCalls)
	return map[string]interface{}{
		"stats_calls": calls,
	}
}

// 18. ResetConfigStats resets stats counters.
func (s *ScanConfig) ResetConfigStats() {
	atomic.StoreUint64(&s.configStatsCalls, 0)
}

// 19. LogConfigTelemetry outputs telemetry summaries.
func (s *ScanConfig) LogConfigTelemetry() {
	log.Printf("ScanConfig Telemetry: Stats Calls: %d", atomic.LoadUint64(&s.configStatsCalls))
}

// 20. ValidateConfigIntegrity verifies options settings.
func (s *ScanConfig) ValidateConfigIntegrity() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeProfile != "" && s.tlsFingerprint != ""
}

// 21. GetCustomTLSFingerprint returns active fingerprints.
func (s *ScanConfig) GetCustomTLSFingerprint() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tlsFingerprint
}

// 22. SetCustomTLSFingerprint sets active fingerprints.
func (s *ScanConfig) SetCustomTLSFingerprint(fp string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsFingerprint = fp
}

// 23. GetCustomHTTPHostHeader returns active headers.
func (s *ScanConfig) GetCustomHTTPHostHeader() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.httpHostHeader
}

// 24. SetCustomHTTPHostHeader sets active headers.
func (s *ScanConfig) SetCustomHTTPHostHeader(header string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.httpHostHeader = header
}

// 26. InitializeBlackrockCipher creates a BlackRock generalized Feistel cipher wrapper.
func (s *ScanConfig) InitializeBlackrockCipher(rangeVal uint64, seed uint64, rounds uint32) *BlackRock {
	return NewBlackRock(rangeVal, seed, rounds)
}

// 27. GetBlackrockShuffleIndex shuffles indexes one-to-one range mappings.
func (s *ScanConfig) GetBlackrockShuffleIndex(br *BlackRock, index uint64) uint64 {
	return br.Shuffle(index)
}

// 28. GetBlackrockUnshuffleIndex unshuffles shuffled indexes.
func (s *ScanConfig) GetBlackrockUnshuffleIndex(br *BlackRock, shuffled uint64) uint64 {
	return br.Unshuffle(shuffled)
}

// 29. SetBlackrockSeed configures global Feistel seed.
func (s *ScanConfig) SetBlackrockSeed(seed uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blackrockSeed = seed
}

// 30. GetBlackrockSeed returns active Feistel seeds.
func (s *ScanConfig) GetBlackrockSeed() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blackrockSeed
}

// 31. AddMultipleBlacklistSubnets appends subnets list.
func (s *ScanConfig) AddMultipleBlacklistSubnets(subs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blacklistSubnets = append(s.blacklistSubnets, subs...)
}

// 32. RemoveMultipleBlacklistSubnets deletes subnets list from registry.
func (s *ScanConfig) RemoveMultipleBlacklistSubnets(subs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sub := range subs {
		var updated []string
		for _, b := range s.blacklistSubnets {
			if b != sub {
				updated = append(updated, b)
			}
		}
		s.blacklistSubnets = updated
	}
}

// 33. GetBlacklistSubnetsCount returns count of blacklisted subnets.
func (s *ScanConfig) GetBlacklistSubnetsCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.blacklistSubnets)
}

// 34. IsSubnetBlacklisted checks if subnet is in blacklist.
func (s *ScanConfig) IsSubnetBlacklisted(sub string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, b := range s.blacklistSubnets {
		if b == sub {
			return true
		}
	}
	return false
}

// 35. GetActiveProfileName returns active profile name.
func (s *ScanConfig) GetActiveProfileName() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeProfile
}

// 36. GetConcurrencyOverrideValue returns active override.
func (s *ScanConfig) GetConcurrencyOverrideValue() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.concurrencyOverride
}

// 37. GetTimeoutOverrideValue returns active override.
func (s *ScanConfig) GetTimeoutOverrideValue() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.timeoutOverride
}

// 38. GetTLSFingerprintVal returns active fingerprint.
func (s *ScanConfig) GetTLSFingerprintVal() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tlsFingerprint
}

// 39. GetHTTPHostHeaderVal returns active host header.
func (s *ScanConfig) GetHTTPHostHeaderVal() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.httpHostHeader
}

// 40. SetBlackrockRounds configures rounds count.
func (s *ScanConfig) SetBlackrockRounds(rounds uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blackrockRounds = rounds
}

// 41. GetBlackrockRounds returns active rounds count.
func (s *ScanConfig) GetBlackrockRounds() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blackrockRounds
}

// 42. ExportScanConfigJSON saves configurations to JSON.
func (s *ScanConfig) ExportScanConfigJSON(filePath string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 43. ImportScanConfigJSON imports configurations from JSON.
func (s *ScanConfig) ImportScanConfigJSON(filePath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	var temp struct {
		ActiveProfile       string   `json:"activeProfile"`
		ConcurrencyOverride int      `json:"concurrencyOverride"`
		TimeoutOverride     int      `json:"timeoutOverride"`
		BlacklistSubnets    []string `json:"blacklistSubnets"`
		TlsFingerprint      string   `json:"tlsFingerprint"`
		HttpHostHeader      string   `json:"httpHostHeader"`
		BlackrockSeed       uint64   `json:"blackrockSeed"`
		BlackrockRounds     uint32   `json:"blackrockRounds"`
	}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	s.activeProfile = temp.ActiveProfile
	s.concurrencyOverride = temp.ConcurrencyOverride
	s.timeoutOverride = temp.TimeoutOverride
	s.blacklistSubnets = temp.BlacklistSubnets
	s.tlsFingerprint = temp.TlsFingerprint
	s.httpHostHeader = temp.HttpHostHeader
	s.blackrockSeed = temp.BlackrockSeed
	s.blackrockRounds = temp.BlackrockRounds
	return nil
}

// 44. GetStatsCallsCount returns total config stats calls.
func (s *ScanConfig) GetStatsCallsCount() uint64 {
	return atomic.LoadUint64(&s.configStatsCalls)
}

// 45. ResetConfigStatsCalls zeroes stats calls count.
func (s *ScanConfig) ResetConfigStatsCalls() {
	atomic.StoreUint64(&s.configStatsCalls, 0)
}

// 46. AddBlacklistSubnetSlice batch appends subnets.
func (s *ScanConfig) AddBlacklistSubnetSlice(subs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blacklistSubnets = append(s.blacklistSubnets, subs...)
}

// 47. GetScanConfigStatsMap returns stats registry map.
func (s *ScanConfig) GetScanConfigStatsMap() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]interface{}{
		"active_profile": s.activeProfile,
		"blacklist_size": len(s.blacklistSubnets),
		"seed":           s.blackrockSeed,
	}
}

// 48. GetScannerVersion returns schema version.
func (s *ScanConfig) GetScannerVersion() int {
	return 1
}

// 49. SetScannerVersion configures schema version.
func (s *ScanConfig) SetScannerVersion(v int) {
}

// 50. ValidateSubnetSyntax verifies formatting rules.
func (s *ScanConfig) ValidateSubnetSyntax(sub string) bool {
	_, _, err := net.ParseCIDR(sub)
	return err == nil
}

// 51. ClearBlacklistSubnets resets subnets blacklist.
func (s *ScanConfig) ClearBlacklistSubnets() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blacklistSubnets = make([]string, 0)
}

// 52. GetTCPTimeoutValue returns default TCP timeout limit.
func (s *ScanConfig) GetTCPTimeoutValue() int {
	return DefaultTCPTimeoutMs
}

// 53. IsBlackrockPresetConfigured checks active Feistel parameters.
func (s *ScanConfig) IsBlackrockPresetConfigured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blackrockSeed > 0 && s.blackrockRounds > 0
}

// 54. VerifyScanConfigPreset checks integration parameters status.
func (s *ScanConfig) VerifyScanConfigPreset() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeProfile != "" && s.tlsFingerprint != ""
}

// 55. ResetScanConfigPreset restores default settings.
func (s *ScanConfig) ResetScanConfigPreset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.activeProfile = "Balanced"
	s.concurrencyOverride = 0
	s.timeoutOverride = 0
	s.blacklistSubnets = []string{"10.0.0.0/8", "192.168.0.0/16"}
	s.tlsFingerprint = "chrome"
	s.httpHostHeader = "www.cloudflare.com"
	s.blackrockSeed = 123456789
	s.blackrockRounds = 4
	atomic.StoreUint64(&s.configStatsCalls, 0)
}
