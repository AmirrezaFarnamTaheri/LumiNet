package scanner

import "testing"

func TestDivideCIDRSubnets(t *testing.T) {
	got, err := divideCIDRSubnets("10.0.0.0/24", 26)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"}
	if len(got) != len(want) {
		t.Fatalf("got %d subnets, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("subnet %d = %q, want %q", i, got[i], want[i])
		}
	}
}
