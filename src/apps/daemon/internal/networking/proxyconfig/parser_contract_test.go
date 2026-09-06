package proxyconfig

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestPostRefactor225WarpRequiresExplicitKeyMaterial(t *testing.T) {
	for _, uri := range []string{
		`warp://example.com:2408#missing-both`,
		`warp://private@example.com:2408#missing-peer`,
	} {
		if _, err := ParseProxyURI(uri); err == nil {
			t.Fatalf("ParseProxyURI(%q) succeeded without explicit WireGuard key material", uri)
		}
	}

	cfg, err := ParseProxyURI(`warp://private@example.com:2408?publickey=peer#explicit`)
	if err != nil {
		t.Fatalf("explicit WARP key material rejected: %v", err)
	}
	if cfg.PrivateKey != "private" || cfg.PublicKey != "peer" {
		t.Fatalf("unexpected explicit key material: private=%q public=%q", cfg.PrivateKey, cfg.PublicKey)
	}
}

func TestParseProxyURIContract(t *testing.T) {
	valid := []struct {
		uri  string
		want ProxyProtocol
	}{
		{"vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@example.com:443?type=tcp&security=tls#VlessTest", ProtocolVLESS},
		{"trojan://trojanpass@example.com:443?sni=example.com#TrojanTest", ProtocolTrojan},
		{"ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@example.com:8388#SSTest", ProtocolShadowsocks},
		{"ss://YWVzLTEyOC1nY206cGFzc3dvcmRAZXhhbXBsZS5jb206ODM4OA==#SSTestLegacy", ProtocolShadowsocks},
		{"hysteria2://hy2pass@example.com:443?up=10&down=50#Hy2Test", ProtocolHysteria2},
		{"tuic://9de78a2e-4b7b-4171-ba47-19ad0d7f9503:tuicpass@example.com:443#TuicTest", ProtocolTUIC},
		{"naive://username:password@example.com:443#NaiveTest", ProtocolNaive},
		{"wireguard://privatekey@example.com:51820?publickey=publickey#WgTest", ProtocolWireGuard},
		{"awg://privatekey@example.com:51820?publickey=publickey&jc=4&jmin=20&jmax=50&s1=10&s2=20&s3=30&s4=40&h1=1234&h2=5678&h3=9012&h4=3456#AwgTest", ProtocolAmneziaWG},
		{"http://user:pass@example.com:8080#HTTPTest", ProtocolHTTP},
		{"socks5://user:pass@example.com:1080#SOCKS5Test", ProtocolSOCKS5},
		{"kcp://kcppassword@example.com:29900?crypt=aes-128&nodelay=1&interval=20&resend=2&nc=1&sndwnd=128&rcvwnd=128&mtu=1350#KCPTest", ProtocolKCP},
	}
	for _, tc := range valid {
		cfg, err := ParseProxyURI(tc.uri)
		if err != nil {
			t.Fatalf("ParseProxyURI(%q): %v", tc.uri, err)
		}
		if cfg.Protocol != tc.want {
			t.Fatalf("ParseProxyURI(%q) protocol=%q want=%q", tc.uri, cfg.Protocol, tc.want)
		}
	}

	invalid := []string{
		"",
		"ftp://example.com:21",
		"vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@:443",
		"vless://@example.com:443",
		"trojan://trojanpass@:443",
		"trojan://@example.com:443",
		"ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@:8388",
		"ss://YWVzLTEyOC1nY206@example.com:8388",
		"hysteria2://hy2pass@:443",
		"hysteria2://@example.com:443",
		"tuic://9de78a2e-4b7b-4171-ba47-19ad0d7f9503:tuicpass@:443",
		"tuic://@example.com:443",
	}
	for _, uri := range invalid {
		if _, err := ParseProxyURI(uri); err == nil {
			t.Fatalf("ParseProxyURI(%q) expected error", uri)
		}
	}
}

func TestDirectProtocolCompatibility(t *testing.T) {
	tuic := "tuic://9de78a2e-4b7b-4171-ba47-19ad0d7f9503:tuicpass@example.com:443#TuicTest"
	cfg, err := ParseTUICDirect(tuic)
	if err != nil || cfg.Protocol != ProtocolTUIC {
		t.Fatalf("ParseTUICDirect() cfg=%v err=%v", cfg, err)
	}

	nipoJSON := `{"name":"Nipo Format Reg Node","config":{"serverIp":"127.0.0.11","serverPort":"8080","token":"reg-token","protocol":"http","fakeUrls":"google.com","tlsEnable":false}}`
	nipo := "nipovpn://" + base64.StdEncoding.EncodeToString([]byte(nipoJSON))
	cfg, err = ParseNipoDirect(nipo)
	if err != nil || cfg.Protocol != ProtocolNipo {
		t.Fatalf("ParseNipoDirect() cfg=%v err=%v", cfg, err)
	}
}

func TestExtractRealityParamsExported(t *testing.T) {
	u, err := url.Parse("vless://id@example.com:443?security=reality&pbk=pub&sid=short")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]interface{}{}
	ExtractRealityParams(u, out)
	tlsConfig, ok := out["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing TLS Reality params: %#v", out)
	}
	reality, ok := tlsConfig["reality"].(map[string]interface{})
	if !ok || reality["public_key"] != "pub" || reality["short_id"] != "short" {
		t.Fatalf("unexpected Reality params: %#v", out)
	}
}

func TestParseProxyURIPreservesObservedInsecureTLSAliases(t *testing.T) {
	tests := []string{
		"vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@example.com:443?security=tls&allowInsecure=true",
		"trojan://secret@example.com:443?insecure=1",
		"hysteria2://secret@example.com:443?allow_insecure=yes",
		"anytls://secret@example.com:443?insecure=true",
		"juicity://id:secret@example.com:443?allowInsecure=1",
		"tuic://9de78a2e-4b7b-4171-ba47-19ad0d7f9503:secret@example.com:443?insecure=true",
	}
	for _, raw := range tests {
		cfg, err := ParseProxyURI(raw)
		if err != nil {
			t.Fatalf("ParseProxyURI(%q): %v", raw, err)
		}
		if !cfg.SkipCertVerify {
			t.Fatalf("ParseProxyURI(%q) lost insecure TLS intent", raw)
		}
	}
}

func TestParseVMessPreservesSkipCertVerify(t *testing.T) {
	payload := `{"v":"2","ps":"vmess-insecure","add":"example.com","port":"443","id":"9de78a2e-4b7b-4171-ba47-19ad0d7f9503","aid":"0","net":"ws","tls":"tls","skip-cert-verify":true}`
	raw := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))
	cfg, err := ParseProxyURI(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SkipCertVerify {
		t.Fatal("VMess skip-cert-verify was not preserved")
	}
}

func TestParseProxyURIHTMLAmpersandNormalization(t *testing.T) {
	raw := "vless://9de78a2e-4b7b-4171-ba47-19ad0d7f9503@example.com:443?type=ws&amp;security=tls&amp;sni=cdn.example.com"
	cfg, err := ParseProxyURI(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Transport != "ws" || !cfg.TLS || cfg.SNI != "cdn.example.com" {
		t.Fatalf("HTML-escaped query lost semantics: transport=%q tls=%v sni=%q", cfg.Transport, cfg.TLS, cfg.SNI)
	}
}

func TestParseShadowsocksObservedSIP002Forms(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		method   string
		password string
		address  string
		port     int
	}{
		{
			name:     "plaintext ss2022 userinfo keeps colon-delimited key material",
			uri:      "ss://2022-blake3-aes-256-gcm:pRCipSixOSlsNAigMmwfYttz5VmVznoCYX4Pw1G4LxM=:ovtz25KfnF29DC8nL8tMIpBaQuGoUupwCRQIZUHECks=@195.201.32.108:8083#node",
			method:   "2022-blake3-aes-256-gcm",
			password: "pRCipSixOSlsNAigMmwfYttz5VmVznoCYX4Pw1G4LxM=:ovtz25KfnF29DC8nL8tMIpBaQuGoUupwCRQIZUHECks=",
			address:  "195.201.32.108",
			port:     8083,
		},
		{
			name:     "legacy base64 uses final at-sign as endpoint separator",
			uri:      "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpASEFDS01PRF9BUEtAMTguMTE4LjkuMTU2OjM4Mzg0",
			method:   "chacha20-ietf-poly1305",
			password: "@HACKMOD_APK",
			address:  "18.118.9.156",
			port:     38384,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseProxyURI(tt.uri)
			if err != nil {
				t.Fatalf("ParseProxyURI() error = %v", err)
			}
			if cfg.Protocol != ProtocolShadowsocks || cfg.Method != tt.method || cfg.Password != tt.password || cfg.Address != tt.address || cfg.Port != tt.port {
				t.Fatalf("parsed config = %#v", cfg)
			}
		})
	}
}

func TestParseVMessAcceptsBooleanTLS(t *testing.T) {
	payload := `{"v":2,"ps":"bool-tls","add":"example.com","port":443,"id":"d13fc2f5-3e05-4795-8d4c-111111111111","aid":0,"net":"ws","tls":true,"sni":"example.com"}`
	uri := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("ParseProxyURI() error = %v", err)
	}
	if !cfg.TLS || cfg.SNI != "example.com" {
		t.Fatalf("parsed config = %#v", cfg)
	}
}

func TestParseShadowsocksRejectsMisSchemedVMessJSON(t *testing.T) {
	payload := `{"add":"51.254.21.193","aid":"0","host":"@ProxyVPN11","id":"9bcecb26-920a-4e68-b296-88526310bff6","net":"ws","path":"/","port":"20086","ps":"mis-schemed","tls":"","v":"2"}`
	uri := "ss://" + base64.StdEncoding.EncodeToString([]byte(payload))
	if cfg, err := ParseProxyURI(uri); err == nil {
		t.Fatalf("mis-schemed VMess JSON must not be accepted as Shadowsocks: %#v", cfg)
	}
}

func TestParseShadowsocksRejectsMisSchemedVLESS(t *testing.T) {
	uri := "ss://660df26a-bccb-4536-a950-1712e533f5ed@example.com:443?security=reality&encryption=none&pbk=publickey&type=tcp&flow=xtls-rprx-vision"
	if cfg, err := ParseProxyURI(uri); err == nil {
		t.Fatalf("mis-schemed VLESS/Reality config must not be accepted as Shadowsocks: %#v", cfg)
	}
}

func TestAnyTLSIdleSessionFieldsRoundTrip(t *testing.T) {
	cfg, err := ParseProxyURI("anytls://secret@example.com:443?idle_session_check_interval=15s&idle_session_timeout=45s&min_idle_session=7&sni=edge.example#any")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AnyTLSIdleSessionCheckInterval != "15s" || cfg.AnyTLSIdleSessionTimeout != "45s" || cfg.MinIdleSessions != 7 {
		t.Fatalf("idle fields not parsed: %+v", cfg)
	}
	roundTrip, err := ParseProxyURI(cfg.ToURI())
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip.AnyTLSIdleSessionCheckInterval != "15s" || roundTrip.AnyTLSIdleSessionTimeout != "45s" || roundTrip.MinIdleSessions != 7 {
		t.Fatalf("idle fields lost on round trip: %+v uri=%s", roundTrip, cfg.ToURI())
	}
}

func TestVLESSToURIPreservesExplicitSecurityMode(t *testing.T) {
	cases := []struct {
		security string
		tls      bool
	}{
		{security: "tls", tls: false},
		{security: "reality", tls: true},
	}
	for _, tc := range cases {
		cfg := &ProxyConfig{Protocol: ProtocolVLESS, UUID: "11111111-1111-1111-1111-111111111111", Address: "example.com", Port: 443, Security: tc.security, TLS: tc.tls}
		parsed, err := ParseProxyURI(cfg.ToURI())
		if err != nil {
			t.Fatalf("parse %s: %v", tc.security, err)
		}
		if parsed.Security != tc.security || !parsed.TLS {
			t.Fatalf("security %s round-trip = security %q tls=%v", tc.security, parsed.Security, parsed.TLS)
		}
	}
}

func TestPostRefactor225TUICRejectsUnknownCongestionAndUDPRelayModes(t *testing.T) {
	base := ProxyConfig{Protocol: ProtocolTUIC, Address: "example.test", Port: 443, UUID: "11111111-1111-1111-1111-111111111111", Password: "fixture-secret"}
	for _, tc := range []struct {
		name   string
		mutate func(*ProxyConfig)
	}{
		{name: "unknown congestion", mutate: func(p *ProxyConfig) { p.CongestionControl = "reno-ish" }},
		{name: "unknown udp relay", mutate: func(p *ProxyConfig) { p.UDPRelayMode = "auto" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("Validate() accepted unsupported TUIC mode: %+v", cfg)
			}
		})
	}

	for _, congestion := range []string{"cubic", "new_reno", "newreno", "bbr"} {
		for _, udp := range []string{"native", "quic"} {
			cfg := base
			cfg.CongestionControl = congestion
			cfg.UDPRelayMode = udp
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() rejected supported TUIC modes congestion=%q udp=%q: %v", congestion, udp, err)
			}
		}
	}
}

func TestShadowsocks2022KeyAdmission(t *testing.T) {
	key16 := base64.StdEncoding.EncodeToString(make([]byte, 16))
	key32 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	cases := []struct {
		name     string
		method   string
		password string
		wantErr  bool
	}{
		{name: "aes128-single", method: "2022-blake3-aes-128-gcm", password: key16},
		{name: "aes128-identity-chain", method: "2022-blake3-aes-128-gcm", password: key16 + ":" + key16},
		{name: "aes256-single", method: "2022-blake3-aes-256-gcm", password: key32},
		{name: "chacha-single", method: "2022-blake3-chacha20-poly1305", password: key32},
		{name: "wrong-length", method: "2022-blake3-aes-128-gcm", password: key32, wantErr: true},
		{name: "malformed-base64", method: "2022-blake3-aes-256-gcm", password: "***", wantErr: true},
		{name: "empty-identity-component", method: "2022-blake3-aes-128-gcm", password: key16 + ":", wantErr: true},
		{name: "unknown-2022-method", method: "2022-blake3-future", password: key32, wantErr: true},
		{name: "legacy-method-unchanged", method: "aes-256-gcm", password: "ordinary password"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &ProxyConfig{Protocol: ProtocolShadowsocks, Address: "example.com", Port: 8388, Method: tc.method, Password: tc.password}
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected validation error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestParseShadowsocks2022PreservesMultiComponentKeys(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 16))
	password := key + ":" + key
	uri := "ss://2022-blake3-aes-128-gcm:" + password + "@example.com:8388#ss2022"
	cfg, err := ParseProxyURI(uri)
	if err != nil {
		t.Fatalf("ParseProxyURI rejected valid SS2022 URI: %v", err)
	}
	if cfg.Password != password {
		t.Fatalf("identity/user key chain changed: got %q want %q", cfg.Password, password)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid SS2022 key chain rejected: %v", err)
	}
}
