package scanner

import (
	"net/netip"
	"testing"
)

func TestIsReservedOrUnsafeAddrUsesCanonicalLocalRanges(t *testing.T) {
	for _, raw := range []string{"100.64.0.1", "169.254.1.2", "fc00::1", "fe80::1"} {
		addr := netip.MustParseAddr(raw)
		if !IsReservedOrUnsafeAddr(addr) {
			t.Fatalf("%s was treated as a safe external target", raw)
		}
	}
	if IsReservedOrUnsafeAddr(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("1.1.1.1 was treated as reserved")
	}
}
