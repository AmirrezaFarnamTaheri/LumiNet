package diagnostics

import "testing"

func TestAntiBotCloudflareChallenge(t *testing.T) {
	got := NewAntiBotDetector().InspectResponse(403, map[string][]string{"Server": {"cloudflare"}}, []byte("Just a moment... cf-mitigation"))
	if !got.IsBotBlocked || got.CDNProvider != "Cloudflare" {
		t.Fatalf("unexpected result: %#v", got)
	}
}
