package warp

import (
	"strings"
	"testing"
)

func TestWarpAccountProfileAndConf(t *testing.T) {
	client := NewWarpAccountClient("")
	prof, err := client.GenerateMockProfile("free")
	if err != nil {
		t.Fatalf("GenerateMockProfile failed: %v", err)
	}

	conf, err := client.SynthesizeWireguardConf(prof, "", "")
	if err != nil {
		t.Fatalf("SynthesizeWireguardConf failed: %v", err)
	}

	if !strings.Contains(conf, "172.16.0.2/32") {
		t.Errorf("conf missing allocated IPv4: %s", conf)
	}
	if !strings.Contains(conf, "engage.cloudflareclient.com:2408") {
		t.Errorf("conf missing default endpoint: %s", conf)
	}
}
