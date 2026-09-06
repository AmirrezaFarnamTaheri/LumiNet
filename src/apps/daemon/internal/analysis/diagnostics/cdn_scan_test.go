package diagnostics

import "testing"

func TestGenerateCdnIPs(t *testing.T) {
	ips, err := GenerateCdnIPs([]string{"192.168.1.0/24"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("len=%d", len(ips))
	}
	ipsFull, err := GenerateCdnIPs([]string{"192.168.1.0/24"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ipsFull) != 254 {
		t.Fatalf("full len=%d", len(ipsFull))
	}
}

func TestPostRefactor225GenerateCdnIPsRejectsExplosiveRangeBeforeAllocation(t *testing.T) {
	if _, err := GenerateCdnIPs([]string{"10.0.0.0/8"}, 16); err == nil {
		t.Fatal("explosive /8 admitted")
	}
	if _, err := GenerateCdnIPs([]string{"10.0.0.0/16"}, 0); err == nil {
		t.Fatal("full /16 admitted beyond candidate bound")
	}
}

func TestPostRefactor225GenerateCdnIPsDeduplicates(t *testing.T) {
	ips, err := GenerateCdnIPs([]string{"192.0.2.1", "192.0.2.1"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "192.0.2.1" {
		t.Fatalf("ips=%v", ips)
	}
}
