package runtimecore

import (
	"slices"
	"testing"
)

func TestNormalizeIKEv2RequestAndArgs(t *testing.T) {
	req, err := normalizeRequest(Request{Engine: EngineIKEv2, Server: "vpn.example.com", Identity: "client@example.com", RemoteIdentity: "vpn.example.com", Certificate: "/tmp/client.crt", PrivateKey: "/tmp/client.key", RemoteTS: "0.0.0.0/0", IKEProposals: []string{"aes256-sha256-modp2048"}, ESPProposals: []string{"aes256-sha256"}})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	got := newIKEv2Engine(req).commandArgs()
	wantParts := []string{"--host", "vpn.example.com", "--identity", "client@example.com", "--profile", "ikev2-pub", "--remote-identity", "vpn.example.com", "--remote-ts", "0.0.0.0/0", "--ike-proposal", "aes256-sha256-modp2048", "--esp-proposal", "aes256-sha256"}
	for i := 0; i+1 < len(wantParts); i += 2 {
		found := false
		for j := 0; j+1 < len(got); j++ {
			if got[j] == wantParts[i] && got[j+1] == wantParts[i+1] {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing pair %q %q in %#v", wantParts[i], wantParts[i+1], got)
		}
	}
	if !slices.Contains(got, "--cert") || !slices.Contains(got, "--priv") {
		t.Fatalf("credential flags missing: %#v", got)
	}
}

func TestNormalizeIKEv2RequestRejectsInteractiveProfileShape(t *testing.T) {
	_, err := normalizeRequest(Request{Engine: EngineIKEv2, Server: "vpn.example.com", Identity: "user", Certificate: "", PrivateKey: ""})
	if err == nil {
		t.Fatal("expected missing certificate/private key to fail")
	}
}

func TestNormalizeIKEv2RequestRejectsUnsafeAndUnboundedProposals(t *testing.T) {
	base := Request{Engine: EngineIKEv2, Server: "vpn.example.com", Identity: "client@example.com", Certificate: "/tmp/client.crt", PrivateKey: "/tmp/client.key"}
	bad := base
	bad.IKEProposals = []string{"aes256\nsha256"}
	if _, err := normalizeRequest(bad); err == nil {
		t.Fatal("expected newline-bearing proposal to fail")
	}
	tooMany := base
	tooMany.ESPProposals = make([]string, 9)
	for i := range tooMany.ESPProposals {
		tooMany.ESPProposals[i] = "aes256-sha256"
	}
	if _, err := normalizeRequest(tooMany); err == nil {
		t.Fatal("expected proposal count bound to fail")
	}
}
