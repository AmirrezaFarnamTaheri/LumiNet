// Package security handles intrusion detection and firewall hooks.
// Ported from: HackingDetectingSystemOfUnauthorizedLoginDevices-master
// Target path: server/internal/security/anomaly_detector.go

package security

import (
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"
)

// GeoLocation represents coordinates
type GeoLocation struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// LoginRecord represents a historical sign-in event
type LoginRecord struct {
	IPAddress    string       `json:"ip_address"`
	DeviceType   string       `json:"device_type"`
	Browser      string       `json:"browser"`
	OS           string       `json:"os"`
	UserAgent    string       `json:"user_agent"`
	TimestampSec int64        `json:"timestamp_sec"`
	Location     *GeoLocation `json:"location,omitempty"`
	IsVPN        bool         `json:"is_vpn"`
}

// AnomalyScore is the result of analysis
type AnomalyScore struct {
	RiskScore    int      `json:"risk_score"`
	Reasons      []string `json:"reasons"`
	IsSuspicious bool     `json:"is_suspicious"`
}

// DetectionConfig holds bounds for security checks
type DetectionConfig struct {
	MaxFailedAttempts        int           `json:"max_failed_attempts"`
	FailedAttemptWindow      time.Duration `json:"failed_attempt_window"`
	RapidLoginCount          int           `json:"rapid_login_count"`
	RapidLoginWindow         time.Duration `json:"rapid_login_window"`
	UnusualHourStart         int           `json:"unusual_hour_start"` // 0-23
	UnusualHourEnd           int           `json:"unusual_hour_end"`   // 0-23
	HistoryLookupLimit       int           `json:"history_lookup_limit"`
	LockoutDuration          time.Duration `json:"lockout_duration"`
	ImpossibleTravelSpeedKPH float64       `json:"impossible_travel_speed_kph"`
}

// DefaultConfig returns default limits
func DefaultConfig() DetectionConfig {
	return DetectionConfig{
		MaxFailedAttempts:        3,
		FailedAttemptWindow:      30 * time.Minute,
		RapidLoginCount:          3,
		RapidLoginWindow:         10 * time.Minute,
		UnusualHourStart:         0,
		UnusualHourEnd:           5,
		HistoryLookupLimit:       50,
		LockoutDuration:          30 * time.Minute,
		ImpossibleTravelSpeedKPH: 900.0,
	}
}

// LockoutTracker manages brute-force account lockout status
type LockoutTracker struct {
	mu             sync.Mutex
	failedAttempts map[string][]int64 // map key to attempt timestamps
	lockedUntil    map[string]int64   // map key to lockout expiration epoch
}

// NewLockoutTracker initializes tracker
func NewLockoutTracker() *LockoutTracker {
	return &LockoutTracker{
		failedAttempts: make(map[string][]int64),
		lockedUntil:    make(map[string]int64),
	}
}

func (t *LockoutTracker) RegisterFail(key string, now int64, config DetectionConfig) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.isLockedLocked(key, now) {
		return false
	}

	attempts := t.failedAttempts[key]
	attempts = append(attempts, now)

	// Filter old attempts outside the window
	windowStart := now - int64(config.FailedAttemptWindow.Seconds())
	var validAttempts []int64
	for _, ts := range attempts {
		if ts >= windowStart {
			validAttempts = append(validAttempts, ts)
		}
	}
	t.failedAttempts[key] = validAttempts

	if len(validAttempts) >= config.MaxFailedAttempts {
		unlockTime := now + int64(config.LockoutDuration.Seconds())
		t.lockedUntil[key] = unlockTime
		return true
	}
	return false
}

func (t *LockoutTracker) IsLocked(key string, now int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.isLockedLocked(key, now)
}

func (t *LockoutTracker) isLockedLocked(key string, now int64) bool {
	until, ok := t.lockedUntil[key]
	if !ok {
		return false
	}
	if now < until {
		return true
	}
	return false
}

func (t *LockoutTracker) Clear(key string) {
	t.mu.Lock()
	delete(t.failedAttempts, key)
	delete(t.lockedUntil, key)
}

// AnomalyDetector implements HDS R1-R9 anomaly checks.
type AnomalyDetector struct {
	config DetectionConfig
}

func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		config: DefaultConfig(),
	}
}

// NewAnomalyDetectorWithConfig constructs detector with custom config
func NewAnomalyDetectorWithConfig(cfg DetectionConfig) *AnomalyDetector {
	return &AnomalyDetector{
		config: cfg,
	}
}

// Detect executes login security logging status
func (a *AnomalyDetector) Detect() {
	slog.Info("AnomalyDetector: active and monitoring logins")
}

// Analyze evaluates current login against user history
func (a *AnomalyDetector) Analyze(current LoginRecord, history []LoginRecord) AnomalyScore {
	var reasons []string
	riskScore := 0

	if len(history) > 0 {
		// R1: New IP Address
		knownIPs := make(map[string]bool)
		for _, r := range history {
			knownIPs[r.IPAddress] = true
		}
		if !knownIPs[current.IPAddress] {
			reasons = append(reasons, fmt.Sprintf("New IP address: %s", current.IPAddress))
			riskScore += 20
		}

		// R2: New Device Type
		knownDevices := make(map[string]bool)
		for _, r := range history {
			if r.DeviceType != "" {
				knownDevices[r.DeviceType] = true
			}
		}
		if current.DeviceType != "" && !knownDevices[current.DeviceType] {
			reasons = append(reasons, fmt.Sprintf("New device type: %s", current.DeviceType))
			riskScore += 15
		}

		// R3: New Browser Family
		knownBrowsers := make(map[string]bool)
		for _, r := range history {
			fam := a.getFamily(r.Browser)
			if fam != "" {
				knownBrowsers[fam] = true
			}
		}
		currBrowserFam := a.getFamily(current.Browser)
		if currBrowserFam != "" && !knownBrowsers[currBrowserFam] {
			reasons = append(reasons, fmt.Sprintf("New browser: %s", current.Browser))
			riskScore += 10
		}

		// R4: New OS Family
		knownOS := make(map[string]bool)
		for _, r := range history {
			fam := a.getFamily(r.OS)
			if fam != "" {
				knownOS[fam] = true
			}
		}
		currOSFam := a.getFamily(current.OS)
		if currOSFam != "" && !knownOS[currOSFam] {
			reasons = append(reasons, fmt.Sprintf("New operating system: %s", current.OS))
			riskScore += 10
		}

		// R6: Rapid Multiple Logins
		since := current.TimestampSec - int64(a.config.RapidLoginWindow.Seconds())
		rapidCount := 0
		for _, r := range history {
			if r.TimestampSec >= since {
				rapidCount++
			}
		}
		if rapidCount >= a.config.RapidLoginCount {
			reasons = append(reasons, fmt.Sprintf(
				"Multiple logins in short period: %d successful logins in the last %d minutes",
				rapidCount,
				int(a.config.RapidLoginWindow.Minutes()),
			))
			riskScore += 25
		}

		// R7: Impossible Travel
		if current.Location != nil {
			var lastGeo *LoginRecord
			for _, r := range history {
				if r.Location != nil {
					lastGeo = &r
					break
				}
			}

			if lastGeo != nil && current.TimestampSec > lastGeo.TimestampSec {
				diffSec := current.TimestampSec - lastGeo.TimestampSec
				hours := float64(diffSec) / 3600.0
				if hours > 0.25 { // 15 mins threshold
					dist := a.haversine(*lastGeo.Location, *current.Location)
					speed := dist / hours
					if speed > a.config.ImpossibleTravelSpeedKPH {
						reasons = append(reasons, fmt.Sprintf(
							"Impossible travel: %.0f km in %.1f h (%.0f km/h) from previous login location",
							dist, hours, speed,
						))
						riskScore += 45
					}
				}
			}
		}
	}

	// R5: Unusual Hour
	t := time.Unix(current.TimestampSec, 0).UTC()
	hour := t.Hour()
	if hour >= a.config.UnusualHourStart && hour < a.config.UnusualHourEnd {
		reasons = append(reasons, fmt.Sprintf(
			"Login during unusual hours: %02d:00 UTC (between %02d:00 and %02d:00)",
			hour, a.config.UnusualHourStart, a.config.UnusualHourEnd,
		))
		riskScore += 15
	}

	// R8: VPN / Proxy
	if current.IsVPN {
		reasons = append(reasons, "VPN / proxy / TOR exit node detected: login may be masking true location")
		riskScore += 30
	}

	// R9: Bot / Scripted User Agent
	if a.isBot(current.UserAgent) {
		reasons = append(reasons, "Automated client detected: user agent matches bot/script pattern")
		riskScore += 35
	}

	if riskScore > 100 {
		riskScore = 100
	}

	return AnomalyScore{
		RiskScore:    riskScore,
		Reasons:      reasons,
		IsSuspicious: riskScore > 30,
	}
}

func (a *AnomalyDetector) getFamily(val string) string {
	fields := strings.Fields(val)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(fields[0])
}

func (a *AnomalyDetector) haversine(loc1, loc2 GeoLocation) float64 {
	const R = 6371.0 // Earth radius in km
	dLat := (loc2.Latitude - loc1.Latitude) * math.Pi / 180.0
	dLon := (loc2.Longitude - loc1.Longitude) * math.Pi / 180.0
	lat1 := loc1.Latitude * math.Pi / 180.0
	lat2 := loc2.Latitude * math.Pi / 180.0

	valA := math.Sin(dLat/2.0)*math.Sin(dLat/2.0) +
		math.Cos(lat1)*math.Cos(lat2)*math.Sin(dLon/2.0)*math.Sin(dLon/2.0)
	c := 2.0 * math.Atan2(math.Sqrt(valA), math.Sqrt(1.0-valA))
	return R * c
}

func (a *AnomalyDetector) isBot(ua string) bool {
	uaLower := strings.ToLower(ua)
	botSigs := []string{
		"headlesschrome", "phantomjs", "selenium", "webdriver",
		"python-requests", "python-urllib", "curl/", "wget/",
		"scrapy", "httpx", "aiohttp", "go-http-client",
		"libwww-perl", "lwp-trivial", "java/1.",
	}
	for _, sig := range botSigs {
		if strings.Contains(uaLower, sig) {
			return true
		}
	}
	return false
}

