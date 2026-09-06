// Package scanner implements host and dns probing operations.

package scanner

import (
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─── IP Range Parsing & Ranges ────────────────────────────────────────────────

// IPRange represents a parseable IP range (single IP, CIDR, or IP-IP).
type IPRange struct {
	Start net.IP
	End   net.IP
	Size  int64
}

// ParseIPRanges parses mixed IP input (single IPs, CIDR ranges, IP-IP ranges).
// Maps to upstream ParseIPRanges().
func ParseIPRanges(input []string) []IPRange {
	var ranges []IPRange
	for _, item := range input {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		// Try CIDR notation first
		if strings.Contains(item, "/") {
			if r, err := parseCIDR(item); err == nil {
				ranges = append(ranges, r)
				continue
			}
		}

		// Try IP-IP range
		if strings.Contains(item, "-") {
			parts := strings.Split(item, "-")
			if len(parts) == 2 {
				startIP := net.ParseIP(strings.TrimSpace(parts[0]))
				endIP := net.ParseIP(strings.TrimSpace(parts[1]))
				if startIP != nil && endIP != nil {
					ranges = append(ranges, IPRange{Start: startIP, End: endIP, Size: calculateIPRange(startIP, endIP)})
					continue
				}
			}
		}

		// Try single IP
		if ip := net.ParseIP(item); ip != nil {
			ranges = append(ranges, IPRange{Start: ip, End: ip, Size: 1})
		}
	}
	return ranges
}

func parseCIDR(cidr string) (IPRange, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return IPRange{}, err
	}
	start := ipnet.IP
	end := calculateBroadcastAddr(ipnet)
	size := calculateIPRange(start, end)
	return IPRange{Start: start, End: end, Size: size}, nil
}

func calculateBroadcastAddr(ipnet *net.IPNet) net.IP {
	broadcast := make(net.IP, len(ipnet.IP))
	copy(broadcast, ipnet.IP)
	for i := 0; i < len(ipnet.Mask); i++ {
		broadcast[len(ipnet.IP)-len(ipnet.Mask)+i] |= ^ipnet.Mask[i]
	}
	return broadcast
}

func calculateIPRange(start, end net.IP) int64 {
	if start == nil || end == nil {
		return 1
	}
	start4 := start.To4()
	end4 := end.To4()
	if start4 == nil || end4 == nil {
		return 1
	}
	startInt := ipv4ToInt(start4)
	endInt := ipv4ToInt(end4)
	if endInt < startInt {
		return 1
	}
	return int64(endInt-startInt) + 1
}

func ipv4ToInt(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// ─── Scanner Structures & Types ────────────────────────────────────────────────

// CleanIPProbeResult represents a single endpoint probe outcome.
type CleanIPProbeResult struct {
	Endpoint      string
	Domain        string
	Success       bool
	StatusCode    int
	Latency       time.Duration
	Error         string
	Timestamp     time.Time
	DomainScore   int
	DomainTotal   int
	DomainsTested int
}

// CleanIPEndpointStats tracks health metrics per endpoint.
type CleanIPEndpointStats struct {
	mu                  sync.RWMutex
	SuccessCount        int
	FailCount           int
	LastOKTime          time.Time
	LastFailTime        time.Time
	AvgLatencyMs        float64
	ConsecutiveFailures int
	QuarantineUntil     time.Time
	QuarantineReason    string
	LastFailReason      string
}

// Getters & Setters for CleanIPEndpointStats
func (e *CleanIPEndpointStats) GetSuccessCount() int { e.mu.RLock(); defer e.mu.RUnlock(); return e.SuccessCount }
func (e *CleanIPEndpointStats) SetSuccessCount(v int) { e.mu.Lock(); defer e.mu.Unlock(); e.SuccessCount = v }
func (e *CleanIPEndpointStats) GetFailCount() int { e.mu.RLock(); defer e.mu.RUnlock(); return e.FailCount }
func (e *CleanIPEndpointStats) SetFailCount(v int) { e.mu.Lock(); defer e.mu.Unlock(); e.FailCount = v }

// CleanIPScannerConfig holds cleanip scanner tuning parameters.
type CleanIPScannerConfig struct {
	ProbeTimeout                    time.Duration
	ProbeRetries                    int
	MaxConcurrentProbes             int
	ProbeIntervalMs                 int
	HealthCheckIntervalMs           int
	QuarantineTTLSec                float64
	MasscanRate                     int
	MasscanRetries                  int
	MasscanWaitSec                  int
	NmapTiming                      string
	NmapRetries                     int
	NmapMinRate                     int
	NmapMaxRate                     int
	ProbeDomainsExtra               []string
	TargetPorts                     []int
	ProbeRequireHTMLForDomainTokens bool
	ProbeAcceptOnCertMatch          bool
}

// CleanIPScanner manages concurrent endpoint probing.
type CleanIPScanner struct {
	mu               sync.RWMutex
	endpoints        map[string]*CleanIPEndpointStats
	config           *CleanIPScannerConfig
	activeProbes     int
	probeSem         chan struct{}
	resultsChan      chan CleanIPProbeResult
	cancelChan       chan struct{}
	wg               sync.WaitGroup
	paused           int32
	netGuardActive   int32
	verboseProbeLogs int32
	stopped          int32
	logCb            func(string)
	proxyProgressCb  func(processed, total, hits int, currentIP string, totalIPs int)
	logFile          *os.File
	logMutex         sync.Mutex
	logFileOwned     bool
	dialer           *net.Dialer
	tlsSessionCache  tls.ClientSessionCache
	httpClient       *http.Client
}

// NewCleanIPScanner creates and initializes a new CleanIPScanner.
func NewCleanIPScanner(cfg *CleanIPScannerConfig) *CleanIPScanner {
	if cfg == nil {
		cfg = &CleanIPScannerConfig{
			ProbeTimeout:        5 * time.Second,
			MaxConcurrentProbes: 100,
		}
	}
	return &CleanIPScanner{
		endpoints:   make(map[string]*CleanIPEndpointStats),
		config:      cfg,
		probeSem:    make(chan struct{}, cfg.MaxConcurrentProbes),
		resultsChan: make(chan CleanIPProbeResult, 1000),
		cancelChan:  make(chan struct{}),
		dialer:      &net.Dialer{Timeout: cfg.ProbeTimeout},
	}
}

// SetLogCallback registers a callback that receives scanner debug strings.
func (s *CleanIPScanner) SetLogCallback(cb func(string)) {
	s.logCb = cb
}

// SetProxyProgressCallback registers a callback that receives progress reports.
func (s *CleanIPScanner) SetProxyProgressCallback(cb func(processed, total, hits int, currentIP string, totalIPs int)) {
	s.proxyProgressCb = cb
}

// SetTargetPorts updates the scanner's active target ports.
func (s *CleanIPScanner) SetTargetPorts(ports []int) {
	if s == nil || s.config == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config.TargetPorts = append([]int(nil), ports...)
}

// GetTargetPorts returns a copy of the scanner's current target ports.
func (s *CleanIPScanner) GetTargetPorts() []int {
	if s == nil || s.config == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]int(nil), s.config.TargetPorts...)
}

// SetPaused toggles paused state.
func (s *CleanIPScanner) SetPaused(paused bool) {
	if paused {
		atomic.StoreInt32(&s.paused, 1)
	} else {
		atomic.StoreInt32(&s.paused, 0)
	}
}

// SetStopped toggles stopped/cancelled state.
func (s *CleanIPScanner) SetStopped(stopped bool) {
	if stopped {
		atomic.StoreInt32(&s.stopped, 1)
	} else {
		atomic.StoreInt32(&s.stopped, 0)
	}
}

func (s *CleanIPScanner) waitWhilePaused() bool {
	if s == nil {
		return true
	}
	for atomic.LoadInt32(&s.paused) == 1 {
		if atomic.LoadInt32(&s.stopped) == 1 {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
	return atomic.LoadInt32(&s.stopped) == 0
}
