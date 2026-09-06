package proxyconfig

import (
	"testing"
)

func TestMitmTrafficRewriter(t *testing.T) {
	rewriter := NewMitmTrafficRewriter()

	rewriter.AddRule(&RewriteRule{
		RuleID:        "rule-1",
		DomainPattern: "api.target.com",
		PathPrefix:    "/v1/auth",
		IsActive:      true,
		ActionType:    ActionSetHeader,
		HeaderName:    "X-Forwarded-Lumi",
		HeaderValue:   "Active",
	})

	rewriter.AddRule(&RewriteRule{
		RuleID:        "rule-2",
		DomainPattern: "*.target.com",
		PathPrefix:    "/page",
		IsActive:      true,
		ActionType:    ActionReplaceBody,
		BodyPattern:   "BLOCKED",
		BodyReplace:   "UNBLOCKED",
	})

	headers := make(map[string]string)
	path := "/v1/auth/user"
	rewritten := rewriter.RewriteRequest("api.target.com", &path, headers)
	if rewritten == nil || headers["X-Forwarded-Lumi"] != "Active" {
		t.Fatalf("expected header X-Forwarded-Lumi=Active, got %v", headers)
	}

	body := []byte("Content: BLOCKED by firewall")
	newBody := rewriter.RewriteResponseBody("cdn.target.com", "/page/index.html", body)
	if string(newBody) != "Content: UNBLOCKED by firewall" {
		t.Fatalf("expected body rewrite, got %s", string(newBody))
	}
}
