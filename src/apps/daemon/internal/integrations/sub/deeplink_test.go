package sub

import (
	"strings"
	"testing"
)

func TestParseDeepLinkImportAcceptsBoundedHTTPSProposal(t *testing.T) {
	got, err := ParseDeepLinkImport("luminet://import?url=https%3A%2F%2Fprovider.example%2Fsub%2Fabc&name=Primary%20Provider")
	if err != nil {
		t.Fatalf("ParseDeepLinkImport: %v", err)
	}
	if got.URL != "https://provider.example/sub/abc" || got.Name != "Primary Provider" {
		t.Fatalf("unexpected proposal: %+v", got)
	}
}

func TestParseDeepLinkImportDefaultsNameToHostname(t *testing.T) {
	got, err := ParseDeepLinkImport("luminet://import?url=https%3A%2F%2Fprovider.example%2Fsub")
	if err != nil {
		t.Fatalf("ParseDeepLinkImport: %v", err)
	}
	if got.Name != "provider.example" {
		t.Fatalf("name=%q", got.Name)
	}
}

func TestParseDeepLinkImportRejectsUnsafeShapes(t *testing.T) {
	cases := []string{
		"marz://import?url=https%3A%2F%2Fprovider.example%2Fsub",
		"luminet://other?url=https%3A%2F%2Fprovider.example%2Fsub",
		"luminet://import/path?url=https%3A%2F%2Fprovider.example%2Fsub",
		"luminet://import?url=http%3A%2F%2Fprovider.example%2Fsub",
		"luminet://import?url=https%3A%2F%2Fuser%3Apass%40provider.example%2Fsub",
		"luminet://import?url=https%3A%2F%2Fprovider.example%2Fsub&extra=1",
		"luminet://import?url=https%3A%2F%2Fprovider.example%2Fsub&url=https%3A%2F%2Fmirror.example%2Fsub",
		"luminet://import?url=https%3A%2F%2Fprovider.example%2Fsub#fragment",
	}
	for _, raw := range cases {
		if _, err := ParseDeepLinkImport(raw); err == nil {
			t.Fatalf("expected rejection for %q", raw)
		}
	}
}

func TestParseDeepLinkImportBoundsInputAndName(t *testing.T) {
	if _, err := ParseDeepLinkImport(strings.Repeat("x", maxDeepLinkLength+1)); err == nil {
		t.Fatal("oversized deep link accepted")
	}
	raw := "luminet://import?url=https%3A%2F%2Fprovider.example%2Fsub&name=" + strings.Repeat("a", maxDeepLinkNameLength+1)
	if _, err := ParseDeepLinkImport(raw); err == nil {
		t.Fatal("oversized profile name accepted")
	}
}
