package warp

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type registrationRoundTripper func(*http.Request) (*http.Response, error)

func (fn registrationRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func TestRegisterWarpAccountWithClientUsesContextAndRejectsHTTPFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: registrationRoundTripper(func(request *http.Request) (*http.Response, error) {
		t.Fatal("transport must not be called after context cancellation")
		return nil, nil
	})}
	_, err := RegisterWarpAccountWithClient(ctx, client)
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("cancelled registration error = %v", err)
	}

	client = &http.Client{Transport: registrationRoundTripper(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(bytes.NewBufferString("unavailable"))}, nil
	})}
	_, err = RegisterWarpAccountWithClient(context.Background(), client)
	if err == nil || !strings.Contains(err.Error(), "HTTP status 503") {
		t.Fatalf("HTTP failure error = %v", err)
	}
}

func TestPingEndpointRejectsMalformedAndUnresponsiveEndpoints(t *testing.T) {
	if _, err := PingEndpoint("not-an-endpoint", time.Second); err == nil {
		t.Fatal("malformed endpoint must fail before probing")
	}

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	if _, err := PingEndpoint(listener.LocalAddr().String(), 25*time.Millisecond); err == nil {
		t.Fatal("an unresponsive UDP listener must not be reported as a WARP endpoint")
	}
}

func TestWARPExportsNormalizeReservedAndIPv6Endpoint(t *testing.T) {
	key := &WARPKey{
		PrivateKey: "private",
		Address:    "172.16.0.2/32",
		Reserved:   []int{7},
		Endpoint:   "[2606:4700:d0::1]:2408",
	}

	if got := GenerateV2RayWireGuardURL(key, "IPv6 WARP"); !strings.Contains(got, "reserved=7,0,0") {
		t.Fatalf("V2Ray URL did not normalize reserved bytes: %s", got)
	}

	singBox := GenerateSingBoxWireGuardConfig(key, "IPv6 WARP")
	if singBox["server"] != "2606:4700:d0::1" || singBox["server_port"] != 2408 {
		t.Fatalf("sing-box endpoint = %#v, want IPv6 host and port", singBox)
	}

	hiddify := GenerateHiddifyConfig(key, "IPv6 WARP")
	outbounds := hiddify["outbounds"].([]map[string]interface{})
	if outbounds[0]["server"] != "2606:4700:d0::1" || outbounds[0]["server_port"] != 2408 {
		t.Fatalf("Hiddify endpoint = %#v, want IPv6 host and port", outbounds[0])
	}
}

func TestEndpointHostPortFallsBackForInvalidInput(t *testing.T) {
	host, port := endpointHostPort("not-an-address")
	if host != "not-an-address" || port != 2408 {
		t.Fatalf("endpoint fallback = %q:%d, want original host and default port", host, port)
	}
}

func TestGenerateWireGuardKeyPair(t *testing.T) {
	pub, priv, err := GenerateWireGuardKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if pub == "" || priv == "" || pub == priv {
		t.Fatalf("invalid key pair: public=%q private=%q", pub, priv)
	}
}
