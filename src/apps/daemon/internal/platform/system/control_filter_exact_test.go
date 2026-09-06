package system

import "testing"

func TestControlFilterRequiresWholeCommandMatch(t *testing.T) {
	filter, err := NewControlFilter("127.0.0.1:0", "127.0.0.1:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	allowed := []string{
		"SIGNAL NEWNYM",
		"GETINFO status/bootstrap-phase",
		"AUTHCHALLENGE SAFECOOKIE aabbccdd",
		"TAKEOWNERSHIP",
	}
	for _, cmd := range allowed {
		if !filter.allowed(cmd) {
			t.Errorf("expected allowed: %q", cmd)
		}
	}
	rejected := []string{
		"SIGNAL NEWNYM extra",
		"GETINFO version status/bootstrap-phase",
		"TAKEOWNERSHIP anything",
		"AUTHENTICATE aabb trailing",
		"QUIT NOW",
	}
	for _, cmd := range rejected {
		if filter.allowed(cmd) {
			t.Errorf("unsafe suffix matched whitelist: %q", cmd)
		}
	}
}
