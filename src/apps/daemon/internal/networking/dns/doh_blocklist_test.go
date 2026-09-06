package dns

import "testing"

func TestDoHBlocklistDomainBoundary(t *testing.T) {
	if !IsDoHBlockedDomain("x.doubleclick.net") {
		t.Fatal("expected blocked subdomain")
	}
	if IsDoHBlockedDomain("notdoubleclick.net") {
		t.Fatal("suffix must respect label boundary")
	}
}
