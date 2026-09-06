package diagnostics

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func baseTime() time.Time { return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) }

func rec(id string, at time.Time, lat, lon *float64, mods ...func(*LoginRecord)) LoginRecord {
	r := LoginRecord{ID: id, UserID: "user-1", IP: "1.2.3.4", DeviceID: "dev-a",
		BrowserFamily: "firefox", OSFamily: "windows", LoginAt: at, Success: true,
		Lat: lat, Lon: lon}
	for _, m := range mods {
		m(&r)
	}
	return r
}

func ptr[T any](v T) *T { return &v }

func TestNewIPRule(t *testing.T) {
	prev := rec("p", baseTime().Add(-time.Hour), nil, nil)
	curr := rec("c", baseTime(), nil, nil)
	curr.IP = "9.9.9.9"
	reasons := DetectLoginAnomalies(curr, []LoginRecord{prev}, DefaultLoginAnomalyConfig())
	joined := strings.Join(reasons, "; ")
	if !strings.Contains(joined, "new IP 9.9.9.9") {
		t.Fatalf("reasons = %v", reasons)
	}
}

func TestImpossibleTravelTriggeredAndSkipped(t *testing.T) {
	cfg := DefaultLoginAnomalyConfig()
	tehranLat, tehranLon := 35.7, 51.4
	berlinLat, berlinLon := 52.5, 13.4

	prev := rec("p", baseTime().Add(-30*time.Minute), ptr(tehranLat), ptr(tehranLon))
	curr := rec("c", baseTime(), ptr(berlinLat), ptr(berlinLon))
	reasons := DetectLoginAnomalies(curr, []LoginRecord{prev}, cfg)
	if len(reasons) == 0 || !strings.Contains(reasons[len(reasons)-1], "impossible travel") {
		t.Fatalf("expected impossible travel, got %v", reasons)
	}

	// Under the 15-minute noise floor the same jump is ignored.
	fast := rec("f", baseTime().Add(-10*time.Minute), ptr(tehranLat), ptr(tehranLon))
	currFast := rec("c2", baseTime(), ptr(berlinLat), ptr(berlinLon))
	if reasons := DetectLoginAnomalies(currFast, []LoginRecord{fast}, cfg); len(reasons) != 0 {
		t.Fatalf("noise floor violated: %v", reasons)
	}
}

func TestUnusualHourWindow(t *testing.T) {
	cfg := DefaultLoginAnomalyConfig() // 00:00–05:00 UTC
	odd := rec("odd", time.Date(2026, 8, 25, 3, 0, 0, 0, time.UTC), nil, nil)
	if reasons := DetectLoginAnomalies(odd, nil, cfg); len(reasons) == 0 {
		t.Fatal("03:00 should trigger unusual-hour rule")
	}
	daytime := rec("day", time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC), nil, nil)
	if reasons := DetectLoginAnomalies(daytime, nil, cfg); len(reasons) != 0 {
		t.Fatalf("14:00 must not trigger: %v", reasons)
	}
}

func TestRapidLoginThreshold(t *testing.T) {
	cfg := DefaultLoginAnomalyConfig()
	history := []LoginRecord{}
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		r := rec(fmt.Sprintf("h%d", i), now.Add(-time.Duration(i+1)*time.Minute), nil, nil)
		history = append(history, r)
	}
	current := rec("current", now, nil, nil)
	reasons := DetectLoginAnomalies(current, history, cfg)
	found := false
	for _, r := range reasons {
		if strings.Contains(r, "successful logins") {
			found = true
		}
	}
	if !found {
		t.Fatalf("rapid-login rule not triggered: %v", reasons)
	}
}

func TestHaversineKnownDistance(t *testing.T) {
	// Tehran → Berlin ≈ 3430 km great-circle.
	got := haversineKM(35.7, 51.4, 52.5, 13.4)
	if got < 3300 || got > 3600 {
		t.Fatalf("tehran-berlin distance = %.0f km", got)
	}
}
