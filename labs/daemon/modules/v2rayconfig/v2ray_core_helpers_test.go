package v2rayconfig

import (
	"strings"
	"testing"
)

func TestParseAddress(t *testing.T) {
	// IPv4
	addrV4, err := ParseAddress("127.0.0.1")
	if err != nil || addrV4.Family() != AddressFamilyIPv4 || addrV4.String() != "127.0.0.1" {
		t.Errorf("IPv4 ParseAddress failed: %v", err)
	}

	// IPv6
	addrV6, err := ParseAddress("::1")
	if err != nil || addrV6.Family() != AddressFamilyIPv6 || addrV6.String() != "::1" {
		t.Errorf("IPv6 ParseAddress failed: %v", err)
	}

	// Domain
	addrDomain, err := ParseAddress("google.com")
	if err != nil || addrDomain.Family() != AddressFamilyDomain || addrDomain.Domain() != "google.com" {
		t.Errorf("Domain ParseAddress failed: %v", err)
	}

	// Empty
	_, err = ParseAddress("")
	if err == nil {
		t.Error("Expected error on empty address, got nil")
	}
}

func TestTLSConfigMock_BuildTLSClientConfig(t *testing.T) {
	cfg := &TLSConfigMock{
		AllowInsecure:           true,
		ServerName:              "domain.com",
		ALPN:                    []string{"h2", "http/1.1"},
		EnableSessionResumption: true,
		PinnedPeerCertificateChainSha256: []string{"hash1"},
	}
	res := cfg.BuildTLSClientConfig()
	if !strings.Contains(res, "domain.com") || !strings.Contains(res, "Insecure=true") || !strings.Contains(res, "PinnedSha256=hash1") {
		t.Errorf("BuildTLSClientConfig failed: %s", res)
	}
}

func TestBlackholeResponseMock_BuildBlackholeConfig(t *testing.T) {
	b := &BlackholeResponseMock{Type: "http"}
	res, err := b.BuildBlackholeConfig()
	if err != nil || !strings.Contains(res, "HTTP") {
		t.Errorf("BuildBlackholeConfig failed: res=%q, err=%v", res, err)
	}

	b.Type = "none"
	res, err = b.BuildBlackholeConfig()
	if err != nil || !strings.Contains(res, "None") {
		t.Errorf("BuildBlackholeConfig failed: res=%q, err=%v", res, err)
	}

	b.Type = "invalid"
	_, err = b.BuildBlackholeConfig()
	if err == nil {
		t.Error("Expected error for invalid Blackhole config type, got nil")
	}
}
