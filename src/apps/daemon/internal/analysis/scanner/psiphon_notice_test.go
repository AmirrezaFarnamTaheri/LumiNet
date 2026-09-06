package scanner

import (
	"strings"
	"testing"
)

func TestParsePsiphonNoticeStreamDetectsProxyReadiness(t *testing.T) {
	state, err := ParsePsiphonNoticeStream("route-psiphon", strings.NewReader(
		`{"notice_type":"ListeningSocksProxyPort","ListeningSocksProxyPort":1080}`+"\n",
	))
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "success" || state.ReadinessState != "proxy_listening" || state.SOCKSPort != 1080 {
		t.Fatalf("unexpected psiphon readiness: %#v", state)
	}
}
