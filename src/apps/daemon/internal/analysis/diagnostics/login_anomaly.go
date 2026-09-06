package diagnostics

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// Login-anomaly heuristics
// LoginDevices (unlicensed; rules re-expressed as pure functions).
//
// Seven rules, evaluated in order: new IP, new device, new browser family,
// new OS family, unusual UTC hour, rapid successful logins, impossible travel
// (haversine distance over elapsed time exceeding a km/h ceiling with a 15
// minute same-session noise floor).

// LoginRecord is one authentication event as supplied by the caller's store.
type LoginRecord struct {
	ID            string
	UserID        string
	IP            string
	DeviceID      string
	BrowserFamily string // normalised family, e.g. "firefox"
	OSFamily      string // e.g. "windows"
	Lat           *float64
	Lon           *float64
	LoginAt       time.Time
	Success       bool
}

// LoginAnomalyConfig carries the tunable thresholds; zero values take the
// upstream defaults.
type LoginAnomalyConfig struct {
	UnusualHourStartUTC int
	UnusualHourEndUTC   int // exclusive; window may wrap midnight when start > end
	RapidWindow         time.Duration
	RapidThreshold      int
	MaxTravelKmPerH     float64
	MinTravelInterval   time.Duration
}

// DefaultLoginAnomalyConfig mirrors the upstream configuration defaults.
func DefaultLoginAnomalyConfig() LoginAnomalyConfig {
	return LoginAnomalyConfig{
		UnusualHourStartUTC: 0,
		UnusualHourEndUTC:   5,
		RapidWindow:         10 * time.Minute,
		RapidThreshold:      3,
		MaxTravelKmPerH:     900,
		MinTravelInterval:   15 * time.Minute,
	}
}

// DetectLoginAnomalies evaluates current against prior history and returns
// one human-readable reason per triggered rule. Only successful logins count;
// the current record itself must not appear in history.
func DetectLoginAnomalies(current LoginRecord, history []LoginRecord, cfg LoginAnomalyConfig) []string {
	var reasons []string

	prev := previousFor(current.UserID, history)
	if prev != nil {
		if current.IP != "" && prev.IP != "" && current.IP != prev.IP {
			reasons = append(reasons, fmt.Sprintf("login from new IP %s (previous %s)", current.IP, prev.IP))
		}
		if current.DeviceID != "" && prev.DeviceID != "" && current.DeviceID != prev.DeviceID {
			reasons = append(reasons, "login from new device")
		}
		if current.BrowserFamily != "" && prev.BrowserFamily != "" &&
			!strings.EqualFold(current.BrowserFamily, prev.BrowserFamily) {
			reasons = append(reasons, fmt.Sprintf("new browser family %s", current.BrowserFamily))
		}
		if current.OSFamily != "" && prev.OSFamily != "" &&
			!strings.EqualFold(current.OSFamily, prev.OSFamily) {
			reasons = append(reasons, fmt.Sprintf("new OS family %s", current.OSFamily))
		}
	}

	hour := current.LoginAt.UTC().Hour()
	start, end := cfg.UnusualHourStartUTC, cfg.UnusualHourEndUTC
	inWindow := start < end && hour >= start && hour < end ||
		start > end && (hour >= start || hour < end) // wraps midnight
	if inWindow {
		reasons = append(reasons, fmt.Sprintf("login during unusual hours %02d:00-%02d:00 UTC", start, end))
	}

	successCount := 0
	windowStart := time.Now().UTC().Add(-cfg.RapidWindow)
	for _, h := range history {
		if !h.Success || h.ID == current.ID {
			continue
		}
		if h.LoginAt.After(windowStart) {
			successCount++
		}
	}
	if successCount >= cfg.RapidThreshold {
		reasons = append(reasons, fmt.Sprintf("%d successful logins within the last %s",
			successCount, cfg.RapidWindow))
	}

	if reason := impossibleTravelReason(current, history, cfg); reason != "" {
		reasons = append(reasons, reason)
	}
	return reasons
}

// previousFor picks the most recent earlier record for the same user.
func previousFor(userID string, history []LoginRecord) *LoginRecord {
	var best *LoginRecord
	for i := range history {
		h := history[i]
		if h.UserID != userID || h.ID == "" {
			continue
		}
		if best == nil || h.LoginAt.After(best.LoginAt) {
			best = &history[i]
		}
	}
	return best
}

func impossibleTravelReason(current LoginRecord, history []LoginRecord, cfg LoginAnomalyConfig) string {
	maxSpeed := cfg.MaxTravelKmPerH
	if maxSpeed <= 0 {
		maxSpeed = 900
	}
	minInterval := cfg.MinTravelInterval
	if minInterval <= 0 {
		minInterval = 15 * time.Minute
	}
	if current.Lat == nil || current.Lon == nil {
		return ""
	}
	var chosen *LoginRecord
	for i := range history {
		p := &history[i]
		if p.UserID != current.UserID || p.Lat == nil || p.Lon == nil {
			continue
		}
		if chosen == nil || p.LoginAt.After(chosen.LoginAt) {
			chosen = p
		}
	}
	if chosen == nil {
		return ""
	}
	elapsedHours := current.LoginAt.Sub(chosen.LoginAt).Hours()
	if elapsedHours <= minInterval.Hours() {
		return "" // same-session noise
	}
	distKM := haversineKM(*current.Lat, *current.Lon, *chosen.Lat, *chosen.Lon)
	speed := distKM / elapsedHours
	if speed <= maxSpeed {
		return ""
	}
	return fmt.Sprintf("impossible travel: %.0f km in %.1f h (%.0f km/h) from previous login location",
		distKM, elapsedHours, speed)
}

// haversineKM is the great-circle distance between two decimal-degree points.
func haversineKM(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKM = 6371.0
	rad := func(deg float64) float64 { return deg * math.Pi / 180 }
	phi1, phi2 := rad(lat1), rad(lat2)
	dPhi := rad(lat2 - lat1)
	dLambda := rad(lon2 - lon1)
	a := math.Sin(dPhi/2)*math.Sin(dPhi/2) +
		math.Cos(phi1)*math.Cos(phi2)*math.Sin(dLambda/2)*math.Sin(dLambda/2)
	return 2 * earthRadiusKM * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}
