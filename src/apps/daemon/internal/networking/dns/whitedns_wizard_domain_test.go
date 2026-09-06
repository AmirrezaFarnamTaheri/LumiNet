package dns

import "testing"

func TestWhiteDNSBypassUsesDomainBoundaries(t *testing.T) {
	w := NewWhiteDNSWizard()
	w.AddBypassDomain("example.com")
	w.AddBypassDomain("")

	for _, domain := range []string{"example.com", "api.example.com", "API.Example.COM."} {
		if !w.IsDomainBypassed(domain) {
			t.Fatalf("%q should match example.com bypass rule", domain)
		}
	}
	for _, domain := range []string{"badexample.com", "example.com.evil", "unrelated.test"} {
		if w.IsDomainBypassed(domain) {
			t.Fatalf("%q incorrectly matched example.com bypass rule", domain)
		}
	}
}
