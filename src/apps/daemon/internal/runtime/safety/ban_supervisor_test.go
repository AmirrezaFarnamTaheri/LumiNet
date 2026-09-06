package safety

import (
	"testing"
)

func TestClientBanSupervisor(t *testing.T) {
	sup := NewClientBanSupervisor(3, 60, 10.0, 1.0)
	ip := "192.0.2.1"

	dec, _ := sup.CheckAccess(ip, 100)
	if dec != AccessAllowed {
		t.Fatalf("expected access allowed")
	}

	sup.RecordAuthResult(ip, false, 100)
	sup.RecordAuthResult(ip, false, 101)
	if sup.IsBanned(ip, 101) {
		t.Fatalf("should not be banned yet")
	}

	sup.RecordAuthResult(ip, false, 102) // 3rd failure -> ban
	if !sup.IsBanned(ip, 102) {
		t.Fatalf("should be banned after 3 failures")
	}

	decBanned, remaining := sup.CheckAccess(ip, 103)
	if decBanned != AccessBanned || remaining != 59 {
		t.Fatalf("expected ban with 59s remaining, got %d, %d", decBanned, remaining)
	}

	sup.Unban(ip)
	if sup.IsBanned(ip, 103) {
		t.Fatalf("should be unbanned")
	}
}
