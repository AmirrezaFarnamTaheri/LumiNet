package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUptimeMonitorHTTP(t *testing.T) {
	// Create mock HTTP server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer mockServer.Close()

	monitor := GetUptimeMonitor()
	target := UptimeTarget{
		ID:       "test_http_target",
		Type:     "http",
		Target:   mockServer.URL,
		Interval: 100 * time.Millisecond,
		Timeout:  50 * time.Millisecond,
	}

	monitor.AddTarget(target)
	monitor.Start(context.Background())
	defer monitor.Stop()

	// Wait for a couple of probes
	time.Sleep(300 * time.Millisecond)

	stats := monitor.GetUptimeStats()
	results, ok := stats[target.ID]
	if !ok || len(results) == 0 {
		t.Fatal("No uptime stats recorded for test HTTP target")
	}

	lastResult := results[len(results)-1]
	if lastResult.State != ProbeStateUp {
		t.Errorf("Expected probe state UP, got: %s (err: %s)", lastResult.State, lastResult.Error)
	}

	monitor.RemoveTarget(target.ID)
}

func TestUptimeMonitorDown(t *testing.T) {
	monitor := GetUptimeMonitor()
	target := UptimeTarget{
		ID:       "test_down_target",
		Type:     "tcp",
		Target:   "127.0.0.1:9999", // Unused port to guarantee failure
		Interval: 50 * time.Millisecond,
		Timeout:  10 * time.Millisecond,
	}

	monitor.AddTarget(target)
	monitor.Start(context.Background())
	defer monitor.Stop()

	time.Sleep(150 * time.Millisecond)

	stats := monitor.GetUptimeStats()
	results := stats[target.ID]
	if len(results) == 0 {
		t.Fatal("No uptime stats recorded for down target")
	}

	lastResult := results[len(results)-1]
	if lastResult.State != ProbeStateDown {
		t.Errorf("Expected probe state DOWN, got: %s", lastResult.State)
	}

	monitor.RemoveTarget(target.ID)
}
