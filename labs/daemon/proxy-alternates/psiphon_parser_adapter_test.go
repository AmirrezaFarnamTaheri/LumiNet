package proxy

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/scanner"
)

func TestPsiphonParserCompatibilityAdapterUsesCanonicalReadiness(t *testing.T) {
	parser := NewPsiphonNoticeParser("route-psiphon")
	state := parser.ParseLine(`{"listeningSocksProxyPort":1080,"conduitMode":"fronting"}`)
	if state.Status != "success" || state.SOCKSPort != 1080 || state.ConduitMode != "fronting" {
		t.Fatalf("unexpected parsed state: %#v", state)
	}

	var canonical scanner.ProviderRouteReadiness = state
	if canonical.RouteID != "route-psiphon" {
		t.Fatalf("canonical route ID = %q, want route-psiphon", canonical.RouteID)
	}

	streamState, err := ParsePsiphonNoticeStream("route-stream", strings.NewReader("listeningHttpProxyPort=8080\n"))
	if err != nil {
		t.Fatalf("ParsePsiphonNoticeStream() error = %v", err)
	}
	if streamState.Status != "success" || streamState.HTTPProxyPort != 8080 {
		t.Fatalf("unexpected stream state: %#v", streamState)
	}
}

func TestWindscribeProbeCompatibilityAdapterUsesCanonicalProbe(t *testing.T) {
	endpoint := "http://\r\ninvalid"
	compatibility := ProbeLocalHTTPProxy(context.Background(), endpoint, time.Second)
	canonical := scanner.ProbeLocalHTTPProxy(context.Background(), endpoint, time.Second)
	if !reflect.DeepEqual(compatibility, canonical) {
		t.Fatalf("probe adapter diverged: compatibility=%#v canonical=%#v", compatibility, canonical)
	}
}
