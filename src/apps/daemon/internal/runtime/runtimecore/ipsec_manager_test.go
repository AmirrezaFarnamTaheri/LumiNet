package runtimecore

import (
	"net"
	"strings"
	"testing"
)

func TestIpsecProfileConfiguration(t *testing.T) {
	ip := net.ParseIP("203.0.113.10")
	profile, err := NewIpsecProfile(ip, "client@luminet.internal", "gw@luminet.internal")
	if err != nil {
		t.Fatalf("NewIpsecProfile failed: %v", err)
	}

	conf := profile.GenerateSwanctlConf()
	if !strings.Contains(conf, "203.0.113.10") {
		t.Errorf("conf missing remote IP: %s", conf)
	}
	if !strings.Contains(conf, "client@luminet.internal") {
		t.Errorf("conf missing client ID: %s", conf)
	}

	daemon := NewNatTKeepaliveDaemon(1)
	if daemon.interval.Seconds() != 1 {
		t.Errorf("expected interval 1, got %v", daemon.interval)
	}
}
