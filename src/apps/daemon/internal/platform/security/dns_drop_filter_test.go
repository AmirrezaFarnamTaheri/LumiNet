package security

import "testing"

func TestDnsDropFilter(t *testing.T) {
	filter := NewDnsDropFilter()

	// IP ID == 0 should drop
	pass, reason := filter.InspectPacket(0, 0, 53, make([]byte, 12))
	if pass {
		t.Errorf("expected drop for IP ID 0, got pass: %s", reason)
	}

	// frag_off == 0x0040 should drop
	pass, _ = filter.InspectPacket(100, 0x0040, 53, make([]byte, 12))
	if pass {
		t.Errorf("expected drop for frag_off 0x0040")
	}

	// Normal packet should pass
	normalPayload := make([]byte, 12)
	normalPayload[7] = 2 // 2 answers
	pass, _ = filter.InspectPacket(100, 0, 53, normalPayload)
	if !pass {
		t.Errorf("expected pass for normal packet")
	}
}
