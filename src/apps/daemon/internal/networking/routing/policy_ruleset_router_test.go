package routing

import (
	"testing"
)

func TestPolicyRulesetRouter(t *testing.T) {
	router := NewPolicyRulesetRouter(PolicyVerdictDirect)
	router.AddExactDomain("ads.google.com", PolicyVerdictReject)
	router.AddSuffixDomain("google.com", PolicyVerdictProxy)
	router.AddKeyword("telegram", PolicyVerdictProxy)
	router.AddCidr([4]byte{10, 0, 0, 0}, 8, PolicyVerdictDirect)

	if router.ResolveDomain("ads.google.com") != PolicyVerdictReject {
		t.Fatal("expected ads.google.com to be rejected")
	}
	if router.ResolveDomain("mail.google.com") != PolicyVerdictProxy {
		t.Fatal("expected mail.google.com to be proxied")
	}
	if router.ResolveDomain("telegram.org") != PolicyVerdictProxy {
		t.Fatal("expected telegram.org to be proxied")
	}
	if router.ResolveDomain("wikipedia.org") != PolicyVerdictDirect {
		t.Fatal("expected wikipedia.org to be direct")
	}

	if router.ResolveIP([4]byte{10, 1, 2, 3}) != PolicyVerdictDirect {
		t.Fatal("expected 10.1.2.3 to be direct")
	}
	if router.ResolveIP([4]byte{1, 1, 1, 1}) != PolicyVerdictDirect {
		t.Fatal("expected 1.1.1.1 to default to direct")
	}
}
