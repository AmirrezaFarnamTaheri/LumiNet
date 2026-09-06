package proxyconfig

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestThirdWaveVLESSRoundTripPreservesModernXrayTLSAndFinalMask(t *testing.T) {
	raw := `vless://u@example.com:443?type=splithttp&security=reality&sni=edge.example&fp=chrome&cs=TLS_AES_128_GCM_SHA256&ech=ZWNo&vcn=edge.example&pcs=abc&pbk=pk&sid=01&spx=%2Fprobe&fm=%7B%22type%22%3A%22random%22%7D&mode=packet-up&extra=%7B%22x%22%3A1%7D#n`
	p, err := ParseProxyURI(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Transport != "xhttp" || p.FinalMask == "" || p.SpiderX != "/probe" || p.CipherSuites == "" || p.XHTTPMode != "packet-up" {
		t.Fatalf("lost fields: %+v", p)
	}
	round := p.ToURI()
	q, err := ParseProxyURI(round)
	if err != nil {
		t.Fatal(err)
	}
	if q.Transport != "xhttp" || q.FinalMask != p.FinalMask || q.XHTTPExtra != p.XHTTPExtra || q.SpiderX != p.SpiderX || q.PinnedPeerCertSHA256 != "abc" {
		t.Fatalf("round trip mismatch: %+v", q)
	}
}

func TestThirdWaveTrojanRoundTripPreservesModernTLSFields(t *testing.T) {
	p, err := ParseProxyURI(`trojan://pw@example.com:443?type=xhttp&sni=s.example&alpn=h2%2Chttp%2F1.1&fp=chrome&cs=A&vcn=s.example&pcs=abc&fm=%7B%22a%22%3A1%7D&mode=auto&extra=%7B%22b%22%3A2%7D`)
	if err != nil {
		t.Fatal(err)
	}
	q, err := ParseProxyURI(p.ToURI())
	if err != nil {
		t.Fatal(err)
	}
	if q.XHTTPMode != "auto" || q.CipherSuites != "A" || q.PinnedPeerCertSHA256 != "abc" || len(q.ALPN) != 2 {
		t.Fatalf("mismatch: %+v", q)
	}
}

func TestThirdWaveVMessPreservesModernFields(t *testing.T) {
	m := map[string]any{"v": "2", "ps": "x", "add": "example.com", "port": "443", "id": "u", "aid": "0", "net": "splithttp", "tls": "tls", "sni": "s.example", "alpn": "h2", "fp": "chrome", "cs": "A", "vcn": "s.example", "pcs": "abc", "fm": "{\"a\":1}", "mode": "stream-up", "extra": "{\"b\":2}"}
	b, _ := json.Marshal(m)
	raw := "vmess://" + base64.StdEncoding.EncodeToString(b)
	p, err := ParseProxyURI(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Transport != "xhttp" || p.XHTTPMode != "stream-up" || p.PinnedPeerCertSHA256 != "abc" {
		t.Fatalf("lost fields: %+v", p)
	}
}

func TestThirdWaveFinalMaskValidationIsBoundedAndObjectOnly(t *testing.T) {
	if _, err := DecodeFinalMask(`{"a":1}`); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFinalMask(`[1]`); err == nil {
		t.Fatal("array accepted")
	}
	if _, err := DecodeFinalMask(strings.Repeat("x", MaxFinalMaskBytes+1)); err == nil {
		t.Fatal("oversized accepted")
	}
}

func TestThirdWaveXHTTPShareRoundTripPreservesModeAndExtra(t *testing.T) {
	p := &ProxyConfig{Protocol: ProtocolVLESS, UUID: "u", Address: "x", Port: 443, TLS: true, Transport: "splithttp", Host: "h", Path: "/p", XHTTPMode: "stream-one", XHTTPExtra: `{"scMaxEachPostBytes":1024}`}
	q, err := ParseProxyURI(p.ToURI())
	if err != nil {
		t.Fatal(err)
	}
	if q.Transport != "xhttp" || q.XHTTPMode != "stream-one" || q.XHTTPExtra != p.XHTTPExtra {
		t.Fatalf("mismatch: %+v", q)
	}
}

func TestThirdWaveBuildXrayXHTTPSettings(t *testing.T) {
	p := &ProxyConfig{Transport: "xhttp", Host: "h", Path: "/p", XHTTPMode: "packet-up", XHTTPExtra: `{"x":1}`}
	m, err := BuildXrayXHTTPSettings(p)
	if err != nil {
		t.Fatal(err)
	}
	if m["mode"] != "packet-up" || m["path"] != "/p" {
		t.Fatalf("bad settings: %#v", m)
	}
	p.XHTTPMode = "nope"
	if _, err := BuildXrayXHTTPSettings(p); err == nil {
		t.Fatal("bad mode accepted")
	}
}

func TestThirdWaveBuildXrayTLSSettingsFailsClosed(t *testing.T) {
	p := &ProxyConfig{TLS: true, Address: "example.com", SkipCertVerify: true}
	if _, err := BuildXrayTLSSettings(p); err == nil {
		t.Fatal("legacy insecure TLS accepted without pin")
	}
	p.PinnedPeerCertSHA256 = "abc"
	m, err := BuildXrayTLSSettings(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["allowInsecure"]; ok {
		t.Fatal("removed allowInsecure emitted")
	}
	if m["pinnedPeerCertSha256"] != "abc" {
		t.Fatalf("missing pin: %#v", m)
	}
}

func TestThirdWaveRealitySpiderXRoundTrip(t *testing.T) {
	p, err := ParseProxyURI(`vless://u@x:443?security=reality&pbk=p&sid=s&spx=%2Ffoo`)
	if err != nil {
		t.Fatal(err)
	}
	if p.SpiderX != "/foo" {
		t.Fatalf("got %q", p.SpiderX)
	}
	q, err := ParseProxyURI(p.ToURI())
	if err != nil {
		t.Fatal(err)
	}
	if q.SpiderX != "/foo" {
		t.Fatal("spiderX lost")
	}
}

func TestThirdWaveWireGuardPSKRoundTrip(t *testing.T) {
	p, err := ParseProxyURI(`wireguard://priv@x:51820?publickey=pub&presharedkey=psk`)
	if err != nil {
		t.Fatal(err)
	}
	if p.PreSharedKey != "psk" {
		t.Fatal("psk lost")
	}
	q, err := ParseProxyURI(p.ToURI())
	if err != nil {
		t.Fatal(err)
	}
	if q.PreSharedKey != "psk" {
		t.Fatal("psk not serialized")
	}
}

func TestThirdWavePurguardIsWireGuardAliasAndPreservesPSK(t *testing.T) {
	p, err := ParseProxyURI(`purguard://priv@x:51820?publickey=pub&psk=secret`)
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != ProtocolWireGuard || p.PreSharedKey != "secret" {
		t.Fatalf("bad purguard: %+v", p)
	}
}

func TestThirdWaveHysteria2RoundTripPreservesObservedCorpusFields(t *testing.T) {
	p, err := ParseProxyURI(`hysteria2://pw@x:443?sni=s&alpn=h3&obfs-password=ob&mport=2000-3000%2C443&pinSHA256=abc&up=10&down=20&fm=%7B%22a%22%3A1%7D`)
	if err != nil {
		t.Fatal(err)
	}
	if p.Hysteria2PortHopping == "" || p.PinnedPeerCertSHA256 != "abc" || p.Obfuscation != "ob" {
		t.Fatalf("lost: %+v", p)
	}
	q, err := ParseProxyURI(p.ToURI())
	if err != nil {
		t.Fatal(err)
	}
	if q.Hysteria2PortHopping != p.Hysteria2PortHopping || q.PinnedPeerCertSHA256 != "abc" {
		t.Fatalf("round lost: %+v", q)
	}
}

func TestThirdWaveHysteria2PortHoppingValidation(t *testing.T) {
	v, err := ParseHysteria2PortHopping("2000-3000,443")
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 2 || v[0] != "2000:3000" {
		t.Fatalf("bad: %#v", v)
	}
	if _, err := ParseHysteria2PortHopping("0"); err == nil {
		t.Fatal("invalid accepted")
	}
}

func TestThirdWaveSingBoxCompatibilityRejectsXrayOnlyFields(t *testing.T) {
	for _, p := range []*ProxyConfig{{Transport: "xhttp"}, {FinalMask: `{"a":1}`}, {CipherSuites: "A"}, {SpiderX: "/x"}} {
		if err := ValidateSingBoxCompatibility(p); err == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
}

func TestPostRefactor228ShadowsocksCoreCompatibilityPreservesOrRejectsExtensions(t *testing.T) {
	supported := &ProxyConfig{Protocol: ProtocolShadowsocks, Plugin: "v2ray-plugin", PluginOpts: "mode=websocket"}
	if err := ValidateSingBoxCompatibility(supported); err != nil {
		t.Fatalf("supported sing-box plugin rejected: %v", err)
	}
	for _, bad := range []*ProxyConfig{
		{Protocol: ProtocolShadowsocks, Plugin: "external-arbitrary-plugin"},
		{Protocol: ProtocolShadowsocks, PluginOpts: "mode=websocket"},
		{Protocol: ProtocolShadowsocks, Prefix: "0011"},
	} {
		if err := ValidateSingBoxCompatibility(bad); err == nil {
			t.Fatalf("sing-box silently accepted unsupported extension: %+v", bad)
		}
	}
	for _, bad := range []*ProxyConfig{
		{Protocol: ProtocolShadowsocks, Plugin: "v2ray-plugin"},
		{Protocol: ProtocolShadowsocks, PluginOpts: "mode=websocket"},
		{Protocol: ProtocolShadowsocks, Prefix: "0011"},
	} {
		if err := ValidateXrayCompatibility(bad); err == nil {
			t.Fatalf("Xray silently accepted unsupported extension: %+v", bad)
		}
	}
}

func TestPostRefactor228ExternalCoreCompatibilityReportsRuntimeTruth(t *testing.T) {
	for _, protocol := range []ProxyProtocol{ProtocolShadowsocksR, ProtocolKCP, ProtocolNipo, ProtocolSingBox} {
		compat := EvaluateExternalCoreCompatibility(&ProxyConfig{Protocol: protocol})
		if compat.Activatable || len(compat.Cores) != 0 || compat.Reason == "" {
			t.Fatalf("unsupported protocol %q reported activatable: %+v", protocol, compat)
		}
	}

	both := EvaluateExternalCoreCompatibility(&ProxyConfig{Protocol: ProtocolVLESS, Address: "example.com", Port: 443})
	if !both.Activatable || len(both.Cores) != 2 || both.Cores[0] != "sing-box" || both.Cores[1] != "xray" {
		t.Fatalf("VLESS core compatibility mismatch: %+v", both)
	}

	singOnly := EvaluateExternalCoreCompatibility(&ProxyConfig{Protocol: ProtocolShadowsocks, Plugin: "v2ray-plugin"})
	if !singOnly.Activatable || len(singOnly.Cores) != 1 || singOnly.Cores[0] != "sing-box" {
		t.Fatalf("plugin Shadowsocks should be sing-box-only: %+v", singOnly)
	}
}
