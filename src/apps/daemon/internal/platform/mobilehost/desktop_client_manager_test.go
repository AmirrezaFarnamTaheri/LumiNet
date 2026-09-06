package mobilehost

import (
	"testing"
)

func TestDesktopClientManager(t *testing.T) {
	mgr := NewDesktopClientManager(7890, 7891)
	st := mgr.GetStatus()
	if st.Mode != ProxyModeDirect || st.IsConnected {
		t.Fatalf("unexpected initial status: %+v", st)
	}

	_, err := mgr.HandleIPCCommand("set_mode", map[string]interface{}{
		"mode": "global",
	})
	if err != nil {
		t.Fatalf("set_mode failed: %v", err)
	}
	if mgr.GetStatus().Mode != ProxyModeGlobal {
		t.Fatalf("expected mode global")
	}

	_, err = mgr.HandleIPCCommand("switch_profile", map[string]interface{}{
		"profile": "fast_tokyo",
	})
	if err != nil {
		t.Fatalf("switch_profile failed: %v", err)
	}
	if mgr.GetStatus().ActiveProfile != "fast_tokyo" {
		t.Fatalf("expected profile fast_tokyo")
	}
}
