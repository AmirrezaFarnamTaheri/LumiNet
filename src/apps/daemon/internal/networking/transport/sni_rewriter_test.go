package transport

import (
	"testing"
)

func TestSniHostnameRewriter(t *testing.T) {
	rewriter := NewSniHostnameRewriter()
	rewriter.AddSniRule("wikipedia.org", "upload.wikimedia.org", []string{"*.wikipedia.org", "wikimedia.org"}, false)
	rewriter.AddHttpRedirect("pixiv.net/", "www.pixiv.net/")

	sni, rule := rewriter.ResolveSNI("wikipedia.org")
	if sni != "upload.wikimedia.org" || rule == nil {
		t.Fatalf("expected upload.wikimedia.org, got %s", sni)
	}

	valid := rewriter.CheckSanValidity(rule, []string{"en.wikipedia.org"})
	if !valid {
		t.Fatalf("expected en.wikipedia.org to match *.wikipedia.org")
	}

	redirect := rewriter.CheckHttpRedirect("pixiv.net/art/123")
	if redirect != "https://www.pixiv.net/" {
		t.Fatalf("expected redirect to https://www.pixiv.net/, got %s", redirect)
	}
}
