// Ported from: HackingDetectingSystemOfUnauthorizedLoginDevices
// Target path: server/internal/auth/login_anomaly.go

package auth

import (
	"math"
	"net"
	"sync"
	"time"
)

// LoginAttempt represents a single login attempt metadata.
type LoginAttempt struct {
	Username  string
	IP        string
	Timestamp time.Time
	Success   bool
}

// LoginAnomalyDetector checks for anomalous login behavior based on heuristics.
type LoginAnomalyDetector struct {
	mu           sync.RWMutex
	history      map[string][]LoginAttempt // username -> attempts
	failedCounts map[string]int            // IP -> failed count
	threshold    int
	window       time.Duration
}

// NewLoginAnomalyDetector creates a new anomaly detector.
func NewLoginAnomalyDetector(threshold int, window time.Duration) *LoginAnomalyDetector {
	return &LoginAnomalyDetector{
		history:      make(map[string][]LoginAttempt),
		failedCounts: make(map[string]int),
		threshold:    threshold,
		window:       window,
	}
}

// RecordAttempt stores a login attempt and checks if it constitutes an anomaly.
// Returns true if an anomaly is detected.
func (d *LoginAnomalyDetector) RecordAttempt(attempt LoginAttempt) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Clean up stale history
	now := time.Now()
	d.history[attempt.Username] = d.filterStale(d.history[attempt.Username], now)

	// Add new attempt
	d.history[attempt.Username] = append(d.history[attempt.Username], attempt)

	if !attempt.Success {
		d.failedCounts[attempt.IP]++
	} else {
		// Reset failed count on success from this IP for this user session heuristic
		d.failedCounts[attempt.IP] = 0
	}

	return d.checkAnomalies(attempt)
}

func (d *LoginAnomalyDetector) filterStale(attempts []LoginAttempt, now time.Time) []LoginAttempt {
	var valid []LoginAttempt
	for _, a := range attempts {
		if now.Sub(a.Timestamp) <= d.window {
			valid = append(valid, a)
		}
	}
	return valid
}

func (d *LoginAnomalyDetector) checkAnomalies(current LoginAttempt) bool {
	// Heuristic 1: Bruteforce check (high number of failed attempts in a short window from the same IP)
	if d.failedCounts[current.IP] >= d.threshold {
		return true
	}

	attempts := d.history[current.Username]
	if len(attempts) < 2 {
		return false
	}

	// Heuristic 2: Impossible travel speed check
	for _, prev := range attempts {
		if prev.IP == current.IP {
			continue
		}
		dist := d.estimateDistance(prev.IP, current.IP)
		timeDiff := current.Timestamp.Sub(prev.Timestamp).Hours()
		if timeDiff > 0 {
			speed := dist / timeDiff
			if speed > 1000.0 { // Faster than 1000 km/h is highly anomalous
				return true
			}
		}
	}

	// Heuristic 3: Suspicious time (e.g. login during unusual night hours for this user)
	// For simplicity, we flag logins between 1 AM and 5 AM if the user has no history of such logins.
	hour := current.Timestamp.Hour()
	if hour >= 1 && hour <= 5 {
		hasNightHistory := false
		for _, prev := range attempts {
			if prev.Timestamp != current.Timestamp {
				h := prev.Timestamp.Hour()
				if h >= 1 && h <= 5 && prev.Success {
					hasNightHistory = true
					break
				}
			}
		}
		if !hasNightHistory && current.Success {
			return true // First time login at night
		}
	}

	return false
}

// estimateDistance returns estimated distance in km between two IPs.
// Uses a mock GeoIP heuristic based on IP octet prefix mismatch.
func (d *LoginAnomalyDetector) estimateDistance(ip1, ip2 string) float64 {
	parsed1 := net.ParseIP(ip1)
	parsed2 := net.ParseIP(ip2)
	if parsed1 == nil || parsed2 == nil {
		return 0
	}
	v4_1 := parsed1.To4()
	v4_2 := parsed2.To4()
	if v4_1 == nil || v4_2 == nil {
		return 5000.0 // Default high distance for IPv6/mismatches
	}
	// Heuristic distance: difference in octets
	diff := 0
	for i := 0; i < 4; i++ {
		diff += int(math.Abs(float64(int(v4_1[i]) - int(v4_2[i]))))
	}
	return float64(diff) * 10.0
}
