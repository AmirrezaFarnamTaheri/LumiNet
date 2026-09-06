package proxyconfig

import (
	"testing"
)

func TestOvpnConfigTranspiler(t *testing.T) {
	transpiler := NewOvpnConfigTranspiler()

	raw := `
# Client config
client
dev tun
proto udp
remote vpn.example.com 1194
cipher AES-256-GCM
auth SHA512
route 10.8.0.0 255.255.255.0
<ca>
-----BEGIN CERTIFICATE-----
MIIB...CA...
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIB...CERT...
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIB...KEY...
-----END PRIVATE KEY-----
</key>
`

	profile, err := transpiler.Transpile(raw)
	if err != nil {
		t.Fatalf("failed to transpile config: %v", err)
	}

	if profile.RemoteHost != "vpn.example.com" || profile.RemotePort != 1194 {
		t.Fatalf("remote host/port mismatch: %s:%d", profile.RemoteHost, profile.RemotePort)
	}
	if profile.Proto != "udp" || profile.DevType != "tun" {
		t.Fatalf("proto/dev mismatch")
	}
	if profile.Cipher != "AES-256-GCM" || profile.AuthDigest != "SHA512" {
		t.Fatalf("cipher/auth mismatch")
	}
	if len(profile.Routes) != 1 || profile.Routes[0] != "10.8.0.0 255.255.255.0" {
		t.Fatalf("routes mismatch: %v", profile.Routes)
	}
	if profile.CACert == "" || profile.ClientCert == "" || profile.ClientKey == "" {
		t.Fatalf("embedded certificates missing")
	}
}
