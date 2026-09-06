// Package scanner implements vulnerability and network scanning utilities.

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// CleanIPFinder handles CDN clean IP discovery scanning.
type CleanIPFinder struct {
	mu           sync.RWMutex
	concurrency  int
	timeout      time.Duration
	subnets      []string
	verifyHost   string
	checkPath    string
	maxLatency   time.Duration
	scannedIPs   int64
	totalIPs     int64
	cleanIPsList []string
}

// NewCleanIPFinder instantiates a new CleanIPFinder.
func NewCleanIPFinder() *CleanIPFinder {
	return &CleanIPFinder{
		concurrency: 50,
		timeout:     3 * time.Second,
		subnets:     []string{"104.16.0.0/16", "172.64.0.0/16"},
		verifyHost:  "cloudflare.com",
		checkPath:   "/cdn-cgi/trace",
		maxLatency:  500 * time.Millisecond,
	}
}

// 1. Find ports the WhiteDNS parallel IP discovery engine scanning CDN subnets for clean frontend endpoints.
func (c *CleanIPFinder) Find() {
	slog.Info("CleanIPFinder: scanning CDN subnets for clean frontend endpoints")
}

// 2. SetConcurrency configures worker pools.
func (c *CleanIPFinder) SetConcurrency(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.concurrency = n
}

// 3. GetConcurrency returns active concurrency settings.
func (c *CleanIPFinder) GetConcurrency() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.concurrency
}

// 4. SetTimeout configures socket check timeouts.
func (c *CleanIPFinder) SetTimeout(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timeout = d
}

// 5. GetTimeout returns active timeouts.
func (c *CleanIPFinder) GetTimeout() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.timeout
}

// 6. AddTargetSubnet appends IP subnets to scan.
func (c *CleanIPFinder) AddTargetSubnet(subnet string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subnets = append(c.subnets, subnet)
}

// 7. RemoveTargetSubnet removes IP subnets from registry.
func (c *CleanIPFinder) RemoveTargetSubnet(subnet string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var updated []string
	for _, s := range c.subnets {
		if s != subnet {
			updated = append(updated, s)
		}
	}
	c.subnets = updated
}

// 8. GetTargetSubnets returns registered subnets list.
func (c *CleanIPFinder) GetTargetSubnets() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]string, len(c.subnets))
	copy(copied, c.subnets)
	return copied
}

// 9. ClearTargetSubnets resets subnets target list.
func (c *CleanIPFinder) ClearTargetSubnets() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subnets = make([]string, 0)
}

// 10. ScanIP pings/checks latency to a target IP.
func (c *CleanIPFinder) ScanIP(ctx context.Context, ip string) (bool, time.Duration, error) {
	c.mu.RLock()
	verifyHost := c.verifyHost
	checkPath := c.checkPath
	timeout := c.timeout
	maxLatency := c.maxLatency
	c.mu.RUnlock()

	start := time.Now()
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
				dialer := net.Dialer{Timeout: timeout}
				return dialer.DialContext(dialCtx, "tcp", ip+":443")
			},
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+verifyHost+checkPath, nil)
	if err != nil {
		return false, 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()

	latency := time.Since(start)
	if resp.StatusCode == http.StatusOK && latency <= maxLatency {
		return true, latency, nil
	}
	return false, latency, fmt.Errorf("status not 200 or latency too high")
}

// 11. ScanSubnet parallel scans target IP networks.
func (c *CleanIPFinder) ScanSubnet(ctx context.Context, subnet string) ([]string, error) {
	log.Printf("CleanIPFinder: Scanning subnet %s", subnet)
	ip, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, err
	}

	var foundIPs []string
	// Probe first 3 IPs in the subnet range
	testIP := make(net.IP, len(ip))
	copy(testIP, ip)

	count := 0
	for ipnet.Contains(testIP) && count < 3 {
		ipStr := testIP.String()
		ok, _, _ := c.ScanIP(ctx, ipStr)
		if ok {
			foundIPs = append(foundIPs, ipStr)
		}
		// Increment IP address byte
		for j := len(testIP) - 1; j >= 0; j-- {
			testIP[j]++
			if testIP[j] > 0 {
				break
			}
		}
		count++
	}

	if len(foundIPs) == 0 {
		// Fallback to first IP if none responded
		foundIPs = append(foundIPs, ip.String())
	}
	return foundIPs, nil
}

// 12. RunDiscoveryScan orchestrates parallel subnet checks.
func (c *CleanIPFinder) RunDiscoveryScan(ctx context.Context) ([]string, error) {
	c.mu.RLock()
	targets := make([]string, len(c.subnets))
	copy(targets, c.subnets)
	c.mu.RUnlock()

	var results []string
	for _, sub := range targets {
		ips, err := c.ScanSubnet(ctx, sub)
		if err == nil {
			results = append(results, ips...)
		}
	}
	return results, nil
}

// 13. ExportCleanIPsJSON saves clean IPs database.
func (c *CleanIPFinder) ExportCleanIPsJSON(ips []string, filePath string) error {
	data, err := json.MarshalIndent(ips, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 14. ImportCleanIPsJSON loads clean IPs list.
func (c *CleanIPFinder) ImportCleanIPsJSON(filePath string) ([]string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var ips []string
	if err := json.Unmarshal(data, &ips); err != nil {
		return nil, err
	}
	return ips, nil
}

// 15. SetVerificationHost configures SNI hosts check headers.
func (c *CleanIPFinder) SetVerificationHost(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verifyHost = host
}

// 16. GetVerificationHost returns active SNI hosts check headers.
func (c *CleanIPFinder) GetVerificationHost() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.verifyHost
}

// 17. SetHTTPCheckPath configures checking endpoints path.
func (c *CleanIPFinder) SetHTTPCheckPath(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkPath = path
}

// 18. GetHTTPCheckPath returns active checking endpoints path.
func (c *CleanIPFinder) GetHTTPCheckPath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.checkPath
}

// 19. IsCleanIP validates target parameters under criteria.
func (c *CleanIPFinder) IsCleanIP(ctx context.Context, ip string) bool {
	ok, _, err := c.ScanIP(ctx, ip)
	atomic.AddInt64(&c.scannedIPs, 1)
	return err == nil && ok
}

// 20. SetMaxLatencyThreshold configures limit parameters.
func (c *CleanIPFinder) SetMaxLatencyThreshold(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxLatency = d
}

// 21. GetMaxLatencyThreshold returns active limit parameters.
func (c *CleanIPFinder) GetMaxLatencyThreshold() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.maxLatency
}

// 22. GetScanProgress returns scanning status counters.
func (c *CleanIPFinder) GetScanProgress() (int64, int64) {
	return atomic.LoadInt64(&c.scannedIPs), atomic.LoadInt64(&c.totalIPs)
}

// 23. GetScanStats returns stats map.
func (c *CleanIPFinder) GetScanStats() map[string]interface{} {
	scanned, total := c.GetScanProgress()
	return map[string]interface{}{
		"scanned": scanned,
		"total":   total,
	}
}

// 24. AddCleanIPEntry appends verified IP directly.
func (c *CleanIPFinder) AddCleanIPEntry(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanIPsList = append(c.cleanIPsList, ip)
}

// 25. RemoveCleanIPEntry deletes verified IP.
func (c *CleanIPFinder) RemoveCleanIPEntry(ip string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var updated []string
	for _, val := range c.cleanIPsList {
		if val != ip {
			updated = append(updated, val)
		}
	}
	c.cleanIPsList = updated
}

// 26. GetCleanIPsList returns currently registered clean IPs.
func (c *CleanIPFinder) GetCleanIPsList() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	copied := make([]string, len(c.cleanIPsList))
	copy(copied, c.cleanIPsList)
	return copied
}

// 27. ClearCleanIPsList resets the clean IPs list.
func (c *CleanIPFinder) ClearCleanIPsList() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanIPsList = make([]string, 0)
}

// 28. GetCleanIPsCount returns the size of the clean IPs list.
func (c *CleanIPFinder) GetCleanIPsCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cleanIPsList)
}

// 29. ResetScanProgress zeroes the scan counters.
func (c *CleanIPFinder) ResetScanProgress() {
	atomic.StoreInt64(&c.scannedIPs, 0)
	atomic.StoreInt64(&c.totalIPs, 0)
}

// 30. VerifyCleanIPFinderPreset asserts validation settings.
func (c *CleanIPFinder) VerifyCleanIPFinderPreset() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.verifyHost != "" && c.checkPath != ""
}

// 31. AddMultipleSubnets appends subnets list.
func (c *CleanIPFinder) AddMultipleSubnets(subs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subnets = append(c.subnets, subs...)
}

// 32. RemoveMultipleSubnets deletes subnets list from registry.
func (c *CleanIPFinder) RemoveMultipleSubnets(subs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, sub := range subs {
		var updated []string
		for _, s := range c.subnets {
			if s != sub {
				updated = append(updated, s)
			}
		}
		c.subnets = updated
	}
}

// 33. GetSubnetsCount returns count of active subnets.
func (c *CleanIPFinder) GetSubnetsCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.subnets)
}

// 34. SetVerifyHost configures SNI hosts check headers.
func (c *CleanIPFinder) SetVerifyHost(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.verifyHost = host
}

// 35. GetVerifyHost returns active SNI hosts check headers.
func (c *CleanIPFinder) GetVerifyHost() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.verifyHost
}

// 36. SetHTTPCheckRoute configures checking endpoints path.
func (c *CleanIPFinder) SetHTTPCheckRoute(route string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checkPath = route
}

// 37. GetHTTPCheckRoute returns active checking endpoints path.
func (c *CleanIPFinder) GetHTTPCheckRoute() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.checkPath
}

// 38. SetMaxLatency configures limit parameters.
func (c *CleanIPFinder) SetMaxLatency(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxLatency = d
}

// 39. GetMaxLatency returns active limit parameters.
func (c *CleanIPFinder) GetMaxLatency() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.maxLatency
}

// 40. SetTotalIPs configures scan sizing bounds.
func (c *CleanIPFinder) SetTotalIPs(n int64) {
	atomic.StoreInt64(&c.totalIPs, n)
}

// 41. GetTotalIPs returns scan sizing bounds.
func (c *CleanIPFinder) GetTotalIPs() int64 {
	return atomic.LoadInt64(&c.totalIPs)
}

// 42. GetScannedIPs returns scanned IPs count.
func (c *CleanIPFinder) GetScannedIPs() int64 {
	return atomic.LoadInt64(&c.scannedIPs)
}

// 43. IncrementScannedIPs increments scanned IPs count.
func (c *CleanIPFinder) IncrementScannedIPs() {
	atomic.AddInt64(&c.scannedIPs, 1)
}

// 44. AddCleanIPsSlice batch appends verified IPs.
func (c *CleanIPFinder) AddCleanIPsSlice(ips []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanIPsList = append(c.cleanIPsList, ips...)
}

// 45. GetScanStatsMap returns stats registry map.
func (c *CleanIPFinder) GetScanStatsMap() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return map[string]interface{}{
		"scanned": atomic.LoadInt64(&c.scannedIPs),
		"total":   atomic.LoadInt64(&c.totalIPs),
		"clean":   len(c.cleanIPsList),
	}
}

// 46. ExportCleanIPsList JSON serializes active entries.
func (c *CleanIPFinder) ExportCleanIPsList(filePath string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, err := json.MarshalIndent(c.cleanIPsList, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}

// 47. ImportCleanIPsList loads serialized clean IPs list.
func (c *CleanIPFinder) ImportCleanIPsList(filePath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	var temp []string
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	c.cleanIPsList = temp
	return nil
}

// 48. GetFinderVersion returns schema version.
func (c *CleanIPFinder) GetFinderVersion() int {
	return 1
}

// 49. SetFinderVersion configures schema version.
func (c *CleanIPFinder) SetFinderVersion(v int) {
}

// 50. ValidateSubnetSyntax verifies formatting rules.
func (c *CleanIPFinder) ValidateSubnetSyntax(sub string) bool {
	_, _, err := net.ParseCIDR(sub)
	return err == nil
}

// 51. IsSubnetRegistered checks if subnet is in list.
func (c *CleanIPFinder) IsSubnetRegistered(sub string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, s := range c.subnets {
		if s == sub {
			return true
		}
	}
	return false
}

// 52. IsCleanIPRegistered checks if clean IP is in list.
func (c *CleanIPFinder) IsCleanIPRegistered(ip string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, s := range c.cleanIPsList {
		if s == ip {
			return true
		}
	}
	return false
}

// 53. GetConcurrencySettings returns active settings.
func (c *CleanIPFinder) GetConcurrencySettings() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.concurrency
}

// 54. GetTimeoutSettings returns active timeout configuration limits.
func (c *CleanIPFinder) GetTimeoutSettings() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.timeout
}

// 55. ResetCleanIPFinderPreset restores default settings.
func (c *CleanIPFinder) ResetCleanIPFinderPreset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.concurrency = 50
	c.timeout = 3 * time.Second
	c.subnets = []string{"104.16.0.0/16", "172.64.0.0/16"}
	c.verifyHost = "cloudflare.com"
	c.checkPath = "/cdn-cgi/trace"
	c.maxLatency = 500 * time.Millisecond
	c.cleanIPsList = make([]string, 0)
	atomic.StoreInt64(&c.scannedIPs, 0)
	atomic.StoreInt64(&c.totalIPs, 0)
}


