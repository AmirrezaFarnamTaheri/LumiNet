package routing

import (
	"testing"
	"testing/fstest"
)

func TestMatchDomainSupportsAllDeclaredRuleTypes(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		rule   DomainRule
		want   bool
	}{
		{"full", "www.example.com", DomainRule{Pattern: "www.example.com", Type: RuleFull}, true},
		{"domain subdomain", "www.example.com", DomainRule{Pattern: "example.com", Type: RuleDomain}, true},
		{"domain boundary", "notexample.com", DomainRule{Pattern: "example.com", Type: RuleDomain}, false},
		{"keyword", "ads.example.com", DomainRule{Pattern: "ads", Type: RuleKeyword}, true},
		{"regexp", "node-42.example.com", DomainRule{Pattern: `^node-[0-9]+\.example\.com$`, Type: RuleRegexp}, true},
		{"invalid regexp", "node-42.example.com", DomainRule{Pattern: "[", Type: RuleRegexp}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := matchDomain(test.domain, test.rule); got != test.want {
				t.Fatalf("matchDomain(%q, %+v) = %v, want %v", test.domain, test.rule, got, test.want)
			}
		})
	}
}

func TestNewRouterLoadsEmbeddedCategoryData(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatal(err)
	}
	if got := r.CategoryCount("category-ads"); got == 0 {
		t.Fatal("category-ads loaded zero rules; embedded .txt data is not active")
	}
	if action, _ := r.Lookup("1rx.io"); action != RouteBlock {
		t.Fatalf("Lookup(1rx.io) = %v, want RouteBlock", action)
	}
}

func TestLoadCategoryExpandsEmbeddedIncludesAndStripsAttributes(t *testing.T) {
	rules, err := loadCategory("category-ads-all", RouteBlock)
	if err != nil {
		t.Fatal(err)
	}
	if !containsDomainRule(rules, "51.la") {
		t.Fatal("category-ads-all did not inherit category-ads via include")
	}
	if !containsDomainRule(rules, "1rx.io") {
		t.Fatal("attribute-suffixed rule 1rx.io @ads was not normalized")
	}
}

func TestLoadCategoryFromFSCyclesTerminateAndDedupe(t *testing.T) {
	fsys := fstest.MapFS{
		"a.txt": {Data: []byte("include:b\nexample.com\n")},
		"b.txt": {Data: []byte("include:a\nexample.com\nother.example\n")},
	}
	rules, err := loadCategoryFromFS(fsys, "a", RouteProxy)
	if err != nil {
		t.Fatal(err)
	}
	if countDomainRule(rules, "example.com") != 1 {
		t.Fatalf("example.com count = %d, want 1", countDomainRule(rules, "example.com"))
	}
	if countDomainRule(rules, "other.example") != 1 {
		t.Fatalf("other.example count = %d, want 1", countDomainRule(rules, "other.example"))
	}
}

func containsDomainRule(rules []DomainRule, pattern string) bool {
	return countDomainRule(rules, pattern) > 0
}

func countDomainRule(rules []DomainRule, pattern string) int {
	count := 0
	for _, rule := range rules {
		if rule.Pattern == pattern {
			count++
		}
	}
	return count
}

func TestServiceAccessCorpusOverridesGeographicRouting(t *testing.T) {
	r, err := NewRouter()
	if err != nil {
		t.Fatal(err)
	}
	action, category := r.Lookup("chatgpt.com")
	if action != RouteProxy || category != "category-service-access" {
		t.Fatalf("Lookup(chatgpt.com) = (%v, %q), want (RouteProxy, category-service-access)", action, category)
	}
}
