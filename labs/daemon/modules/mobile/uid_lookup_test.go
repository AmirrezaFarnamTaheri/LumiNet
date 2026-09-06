package mobile

import "testing"

func TestNonTorList(t *testing.T) {
	list := NonTorList()
	if len(list) == 0 {
		t.Error("NonTorList returned empty list")
	}

	foundCGNAT := false
	foundIPv6 := false

	for _, item := range list {
		if item.Address == "100.64.0.0" && item.Prefix == 10 {
			foundCGNAT = true
		}
		if item.Address == "ff02::1" && item.Prefix == 128 {
			foundIPv6 = true
		}
	}

	if !foundCGNAT {
		t.Error("CGNAT address 100.64.0.0/10 not found in NonTorList")
	}
	if !foundIPv6 {
		t.Error("IPv6 multicast address ff02::1/128 not found in NonTorList")
	}
}

func TestCanFilter(t *testing.T) {
	// Should not panic, and on Windows/macOS/etc. without procfs it should be false.
	res := CanFilter()
	t.Logf("CanFilter returned: %v", res)
}
