package security

import (
	"net"
	"testing"
)

func TestDnsPoisonFilter(t *testing.T) {
	filter := NewDnsPoisonFilter()

	bogus := net.ParseIP("74.125.127.102")
	valid := net.ParseIP("8.8.8.8")

	if !filter.IsBogus(bogus) {
		t.Fatalf("expected 74.125.127.102 recognized as bogus")
	}

	clean := filter.FilterIPs([]net.IP{bogus, valid})
	if len(clean) != 1 || clean[0].String() != "8.8.8.8" {
		t.Fatalf("expected only 8.8.8.8 retained, got %v", clean)
	}

	dropped, accepted := filter.Stats()
	if dropped != 1 || accepted != 1 {
		t.Fatalf("expected dropped=1 accepted=1, got dropped=%d accepted=%d", dropped, accepted)
	}
}
