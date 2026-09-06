package sub

import (
	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
	"testing"
)

func TestFilterSafeProxyConfig(t *testing.T) {
	cases := []struct {
		addr string
		safe bool
	}{{"127.0.0.1", false}, {"192.168.1.1", false}, {"10.0.0.5", false}, {"localhost", false}, {"test.local", false}, {"example.com", true}, {"8.8.8.8", true}}
	for _, tc := range cases {
		if got := FilterSafeProxyConfig(&proxyconfig.ProxyConfig{Address: tc.addr}); got != tc.safe {
			t.Fatalf("%s safe=%v want %v", tc.addr, got, tc.safe)
		}
	}
}
