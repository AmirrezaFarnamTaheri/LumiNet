package proxy

import (
	"net/url"
	"testing"
)

func TestCloudflareWorkerURLsRetainProtocolSpecificFields(t *testing.T) {
	vless := GenerateVlessWorkerURL(CFWorkerVlessConfig{
		UserUUID: "user", Hostname: "edge.example", ProxyIP: "198.51.100.10", Port: 443, Path: "/ws", Flow: "xtls-rprx", Encryption: "none",
	}, " VLESS edge ")
	trojan := GenerateTrojanWorkerURL(CFWorkerTrojanConfig{
		Password: "secret", Hostname: "edge.example", Port: 443,
	}, "Trojan edge")

	for _, testCase := range []struct {
		name string
		raw  string
		want map[string]string
	}{
		{"vless", vless, map[string]string{"encryption": "none", "flow": "xtls-rprx", "path": "/ws"}},
		{"trojan", trojan, map[string]string{"path": "/", "security": "tls"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			parsed, err := url.Parse(testCase.raw)
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range testCase.want {
				if got := parsed.Query().Get(key); got != value {
					t.Fatalf("%s = %q, want %q in %q", key, got, value, testCase.raw)
				}
			}
		})
	}
}
