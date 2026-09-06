package sub

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/integrations/captchaclient"
	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

func TestFetchRejectsLoopbackBeforeCaptchaBypass(t *testing.T) {
	var requestCount int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<div class="cf-turnstile" data-sitekey="0x4AAAAAAAMockKey"></div>`)
	}))
	defer target.Close()

	solverServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"status": 1, "request": "mock-token"})
	}))
	defer solverServer.Close()

	solver := captchaclient.NewCaptchaSolver("test-key", solverServer.URL)
	solver.PollingInterval = time.Millisecond
	solver.Timeout = 10 * time.Millisecond

	_, err := Fetch(WithCaptchaSolver(context.Background(), solver), target.URL)
	if err == nil {
		t.Fatal("expected loopback subscription URL to be rejected")
	}
	if got := atomic.LoadInt32(&requestCount); got != 0 {
		t.Fatalf("loopback target was contacted %d times before egress validation", got)
	}
}

func TestParseContentSingBoxDetour(t *testing.T) {
	content := `{"outbounds":[{"type":"wireguard","tag":"Warp-IR","server":"162.159.195.93","server_port":2506,"local_address":"172.16.0.2/32","private_key":"CBVIIWvXdLr4PbSrnm11J300IiPudRD4R62/IxV1g=","peer_public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","reserved":"AAAA","mtu":1280},{"type":"wireguard","tag":"Warp-Main","server":"162.159.195.93","server_port":2506,"local_address":"172.16.0.2/32","private_key":"CCC/TQTc82ub9i8f37Rpix2v425Sv/mxTzvE/iKRMkw=","peer_public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","reserved":"AAAA","mtu":1280,"detour":"Warp-IR"}]}`
	configs, err := ParseContent(content)
	if err != nil {
		t.Fatalf("ParseContent failed: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("expected 2 configurations, got %d", len(configs))
	}
	var main, irName string
	for _, cfg := range configs {
		if cfg.Name == "Warp-Main" {
			main = cfg.DialerProxy
			if cfg.Detour != nil {
				irName = cfg.Detour.Name
			}
		}
	}
	if main != "Warp-IR" || !strings.EqualFold(irName, "Warp-IR") {
		t.Fatalf("detour not linked: dialer=%q detour=%q", main, irName)
	}
}

func TestParseContentSingBoxPreservesTransportTLSMultiplexAndAnyTLS(t *testing.T) {
	content := `{"outbounds":[
		{"type":"vmess","tag":"front","server":"203.0.113.10","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111","security":"auto","detour":"any","tls":{"enabled":true,"server_name":"edge.example","alpn":["h2","http/1.1"],"reality":{"enabled":true,"public_key":"pub","short_id":"01"}},"transport":{"type":"ws","path":"/ws","headers":{"Host":"cdn.example"}},"multiplex":{"enabled":true,"max_connections":4}},
		{"type":"anytls","tag":"any","server":"198.51.100.8","server_port":443,"password":"secret","idle_session_check_interval":"15s","idle_session_timeout":"45s","min_idle_session":7,"tls":{"enabled":true,"server_name":"any.example"}}
	]}`
	configs, err := ParseContent(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 2 {
		t.Fatalf("configs=%d", len(configs))
	}
	front, any := configs[0], configs[1]
	if front.Transport != "ws" || front.Path != "/ws" || front.Host != "cdn.example" || front.Security != "reality" || front.PublicKey != "pub" || front.ShortID != "01" || !front.SmuxEnabled || front.SmuxConcurrency != 4 {
		t.Fatalf("front fields lost: %+v", front)
	}
	if front.Detour != any || front.DialerProxy != "any" {
		t.Fatalf("detour not preserved: front=%+v any=%+v", front, any)
	}
	if any.Protocol != proxyconfig.ProtocolAnyTLS || any.AnyTLSIdleSessionCheckInterval != "15s" || any.AnyTLSIdleSessionTimeout != "45s" || any.MinIdleSessions != 7 || any.SNI != "any.example" {
		t.Fatalf("anytls fields lost: %+v", any)
	}
}
