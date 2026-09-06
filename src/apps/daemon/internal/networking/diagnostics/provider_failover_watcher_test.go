package diagnostics

import (
	"testing"
)

func TestProviderFailoverWatcher(t *testing.T) {
	watcher := NewProviderFailoverWatcher(3)
	watcher.RegisterProvider("primary-vpn", true)
	watcher.RegisterProvider("standby-vpn", false)

	if watcher.ActiveProvider() != "primary-vpn" {
		t.Fatalf("expected primary-vpn, got %s", watcher.ActiveProvider())
	}

	watcher.RecordHeartbeat("primary-vpn", 500, false)
	watcher.RecordHeartbeat("primary-vpn", 500, false)

	h, ok := watcher.GetHealth("primary-vpn")
	if !ok || h.Status != ProviderStatusUnstable {
		t.Fatalf("expected unstable, got %v", h)
	}

	failover := watcher.RecordHeartbeat("primary-vpn", 500, false)
	if failover != "standby-vpn" {
		t.Fatalf("expected failover to standby-vpn, got %s", failover)
	}

	if watcher.ActiveProvider() != "standby-vpn" {
		t.Fatalf("expected active provider standby-vpn, got %s", watcher.ActiveProvider())
	}

	h2, ok2 := watcher.GetHealth("primary-vpn")
	if !ok2 || h2.Status != ProviderStatusFailed {
		t.Fatalf("expected primary-vpn failed, got %v", h2)
	}
}
