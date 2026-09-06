package sub

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

func TestValidateRoundTripIgnoresNamesButDetectsSemanticAndGraphLoss(t *testing.T) {
	target := &proxyconfig.ProxyConfig{Name: "hop", Protocol: proxyconfig.ProtocolSOCKS5, Address: "127.0.0.1", Port: 1080}
	source := []*proxyconfig.ProxyConfig{
		target,
		{Name: "exit", Protocol: proxyconfig.ProtocolVLESS, Address: "example.com", Port: 443, UUID: "11111111-1111-1111-1111-111111111111", Detour: target, DialerProxy: "hop"},
	}
	parser := func(string) ([]*proxyconfig.ProxyConfig, error) {
		hop := &proxyconfig.ProxyConfig{Name: "renamed-hop", Protocol: proxyconfig.ProtocolSOCKS5, Address: "127.0.0.1", Port: 1080}
		return []*proxyconfig.ProxyConfig{
			hop,
			{Name: "renamed-exit", Protocol: proxyconfig.ProtocolVLESS, Address: "example.com", Port: 443, UUID: "11111111-1111-1111-1111-111111111111", Detour: hop, DialerProxy: "renamed-hop"},
		}, nil
	}
	got := ValidateRoundTrip(source, "ignored", parser)
	if !got.Compatible || got.ExactNodes != 2 {
		t.Fatalf("compatible round trip rejected: %+v", got)
	}

	bad := ValidateRoundTrip(source, "ignored", func(string) ([]*proxyconfig.ProxyConfig, error) {
		return []*proxyconfig.ProxyConfig{
			{Name: "hop", Protocol: proxyconfig.ProtocolSOCKS5, Address: "127.0.0.1", Port: 1080},
			{Name: "exit", Protocol: proxyconfig.ProtocolVLESS, Address: "example.com", Port: 8443, UUID: "11111111-1111-1111-1111-111111111111"},
		}, nil
	})
	if bad.Compatible || bad.ChangedNodes == 0 {
		t.Fatalf("semantic loss not detected: %+v", bad)
	}
}

func TestValidateRoundTripReportsParserAndCardinalityFailure(t *testing.T) {
	source := []*proxyconfig.ProxyConfig{{Protocol: proxyconfig.ProtocolHTTP, Address: "example.com", Port: 8080}}
	failed := ValidateRoundTrip(source, "x", func(string) ([]*proxyconfig.ProxyConfig, error) { return nil, errors.New("bad output") })
	if failed.Compatible || failed.ParserError == "" || failed.MissingNodes != 1 {
		t.Fatalf("parser failure: %+v", failed)
	}
	extra := ValidateRoundTrip(source, "x", func(string) ([]*proxyconfig.ProxyConfig, error) { return append(source, source[0]), nil })
	if extra.Compatible || extra.ExtraNodes != 1 {
		t.Fatalf("extra nodes: %+v", extra)
	}
}

func TestGeneratedURIAndBase64RoundTripCanonicalParsedNodes(t *testing.T) {
	first, err := proxyconfig.ParseProxyURI("vless://11111111-1111-1111-1111-111111111111@example.com:443?host=www.example.com&path=%2Fws&security=tls&sni=www.example.com&type=ws#vless")
	if err != nil {
		t.Fatal(err)
	}
	second, err := proxyconfig.ParseProxyURI("anytls://secret@any.example.com:443?idle_session_check_interval=30s&idle_session_timeout=60s&min_idle_session=2&sni=any.example.com#any")
	if err != nil {
		t.Fatal(err)
	}
	configs := []*proxyconfig.ProxyConfig{first, second}
	for _, tc := range []struct {
		name   string
		target ConversionTarget
		parser ContentParser
	}{
		{name: "uri", target: ConversionURIList, parser: proxyconfig.ParseProxyList},
		{name: "base64", target: ConversionBase64, parser: func(content string) ([]*proxyconfig.ProxyConfig, error) {
			raw, err := base64.StdEncoding.DecodeString(content)
			if err != nil {
				return nil, err
			}
			return proxyconfig.ParseProxyList(string(raw))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ConvertConfigs(configs, tc.target, true)
			if err != nil {
				t.Fatal(err)
			}
			report := ValidateRoundTrip(configs, out.Content, tc.parser)
			if !report.Compatible {
				t.Fatalf("generated %s drift: %+v", tc.target, report)
			}
		})
	}
}

func TestGeneratedLumiNetBundleRoundTrip(t *testing.T) {
	hop := &proxyconfig.ProxyConfig{Name: "hop", Protocol: proxyconfig.ProtocolSOCKS5, Address: "127.0.0.1", Port: 1080}
	source := []*proxyconfig.ProxyConfig{
		hop,
		{Name: "exit", Protocol: proxyconfig.ProtocolVLESS, Address: "example.com", Port: 443, UUID: "11111111-1111-1111-1111-111111111111", Detour: hop, DialerProxy: "hop"},
	}
	out, err := ConvertConfigs(source, ConversionLumiNetJSON, true)
	if err != nil {
		t.Fatal(err)
	}
	report := ValidateRoundTrip(source, out.Content, func(content string) ([]*proxyconfig.ProxyConfig, error) {
		return parseLumiNetBundle([]byte(content))
	})
	if !report.Compatible {
		t.Fatalf("canonical bundle drift: %+v", report)
	}
}
