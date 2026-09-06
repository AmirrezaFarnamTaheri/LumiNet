package safety

import (
	"testing"
)

func TestIdentityPolicyEvaluator(t *testing.T) {
	eval := NewIdentityPolicyEvaluator()
	eval.AddPolicy(RoutePolicy{
		PathPrefix:     "/admin",
		AllowedDomains: []string{"luminet.internal"},
		RequiredGroups: []string{"infra-admin"},
	})

	admin := &IdentitySession{
		Email:  "alice@luminet.internal",
		Domain: "luminet.internal",
		Groups: []string{"infra-admin"},
	}
	if !eval.IsAuthorized("/admin/status", admin) {
		t.Fatal("admin should be authorized")
	}

	guest := &IdentitySession{
		Email:  "bob@other.com",
		Domain: "other.com",
		Groups: []string{"guest"},
	}
	if eval.IsAuthorized("/admin/status", guest) {
		t.Fatal("guest should be denied")
	}
}
