package security

import (
	"math"
	"strings"
	"testing"
)

func TestHaversine(t *testing.T) {
	detector := NewAnomalyDetector()
	paris := GeoLocation{Latitude: 48.8566, Longitude: 2.3522}
	london := GeoLocation{Latitude: 51.5074, Longitude: -0.1278}

	dist := detector.haversine(paris, london)
	if math.Abs(dist-344.0) > 5.0 {
		t.Errorf("Expected distance between Paris and London to be around 344km, got %f", dist)
	}
}

func TestLockoutTracker(t *testing.T) {
	config := DefaultConfig()
	tracker := NewLockoutTracker()
	key := "test_user"

	if tracker.IsLocked(key, 1000) {
		t.Error("Expected user to not be locked initially")
	}

	// Register 2 failures
	if tracker.RegisterFail(key, 1000, config) {
		t.Error("Should not trigger lockout yet")
	}
	if tracker.RegisterFail(key, 1010, config) {
		t.Error("Should not trigger lockout yet")
	}

	// 3rd failure triggers lockout
	if !tracker.RegisterFail(key, 1020, config) {
		t.Error("Should trigger lockout on 3rd fail")
	}

	if !tracker.IsLocked(key, 1025) {
		t.Error("User should be locked")
	}

	// Lockout expires after duration
	expiry := 1020 + int64(config.LockoutDuration.Seconds())
	if tracker.IsLocked(key, expiry+1) {
		t.Error("Lockout should have expired")
	}
}

func TestAnomalyCheck(t *testing.T) {
	detector := NewAnomalyDetector()

	history := []LoginRecord{
		{
			IPAddress:    "192.168.1.50",
			DeviceType:   "PC",
			Browser:      "Chrome 120",
			OS:           "Windows 11",
			UserAgent:    "Mozilla/5.0 Chrome/120",
			TimestampSec: 1700000000,
			Location:     &GeoLocation{Latitude: 40.7128, Longitude: -74.0060}, // New York
			IsVPN:        false,
		},
	}

	// Normal login matching history (using 1700036000 = UTC 08:13 normal hour)
	normal := LoginRecord{
		IPAddress:    "192.168.1.50",
		DeviceType:   "PC",
		Browser:      "Chrome 120",
		OS:           "Windows 11",
		UserAgent:    "Mozilla/5.0 Chrome/120",
		TimestampSec: 1700036000,
		Location:     &GeoLocation{Latitude: 40.7128, Longitude: -74.0060},
		IsVPN:        false,
	}

	res := detector.Analyze(normal, history)
	if res.IsSuspicious {
		t.Errorf("Normal login should not be suspicious, reasons: %v", res.Reasons)
	}
	if res.RiskScore != 0 {
		t.Errorf("Expected risk score 0, got %d", res.RiskScore)
	}

	// Anomaly: Impossible travel (New York to Tokyo in 1 hour)
	anomaly := LoginRecord{
		IPAddress:    "10.0.0.1",
		DeviceType:   "PC",
		Browser:      "Chrome 120",
		OS:           "Windows 11",
		UserAgent:    "Mozilla/5.0 Chrome/120",
		TimestampSec: 1700003600, // 1 hour later
		Location:     &GeoLocation{Latitude: 35.6762, Longitude: 139.6503}, // Tokyo
		IsVPN:        false,
	}

	res = detector.Analyze(anomaly, history)
	if !res.IsSuspicious {
		t.Error("Impossible travel login should be suspicious")
	}

	hasImpossibleTravel := false
	for _, reason := range res.Reasons {
		if strings.Contains(reason, "Impossible travel") {
			hasImpossibleTravel = true
		}
	}
	if !hasImpossibleTravel {
		t.Error("Expected 'Impossible travel' reason")
	}
}
