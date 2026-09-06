package safety

import (
	"testing"
)

func TestBandwidthQuotaEnforcer(t *testing.T) {
	enforcer := NewBandwidthQuotaEnforcer()
	enforcer.RegisterUser("user-alice", 1000)

	if alert := enforcer.RecordTraffic("user-alice", 500); alert != QuotaNormal {
		t.Fatalf("expected QuotaNormal, got %v", alert)
	}
	if !enforcer.IsUserAllowed("user-alice") {
		t.Fatal("user should be allowed")
	}

	if alert := enforcer.RecordTraffic("user-alice", 350); alert != QuotaWarning80 {
		t.Fatalf("expected QuotaWarning80, got %v", alert)
	}
	if !enforcer.IsUserAllowed("user-alice") {
		t.Fatal("user should be allowed in warning state")
	}

	if alert := enforcer.RecordTraffic("user-alice", 200); alert != QuotaExhausted {
		t.Fatalf("expected QuotaExhausted, got %v", alert)
	}
	if enforcer.IsUserAllowed("user-alice") {
		t.Fatal("user should not be allowed after exhaustion")
	}
}
