// Package v2rayconfig provides V2Ray/Xray configuration building with anti-censorship features.
// Ported from: v2ray-core-main, v2ray-go-main, v2ray-core-master
// Target path: server/internal/v2rayconfig/v2ray_core_helpers.go

package v2rayconfig

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// IP and family address parsing parameters.
const (
	IPv4len = 4
	IPv6len = 16
)

type AddressFamily int

const (
	AddressFamilyIPv4 AddressFamily = iota
	AddressFamilyIPv6
	AddressFamilyDomain
)

// Address interface exposed in v2ray-go-main.
type Address interface {
	IP() net.IP
	Domain() string
	Family() AddressFamily
	String() string
}

type ParsedAddress struct {
	ip     net.IP
	domain string
	family AddressFamily
}

func (p *ParsedAddress) IP() net.IP           { return p.ip }
func (p *ParsedAddress) Domain() string       { return p.domain }
func (p *ParsedAddress) Family() AddressFamily { return p.family }
func (p *ParsedAddress) String() string {
	if p.family == AddressFamilyDomain {
		return p.domain
	}
	return p.ip.String()
}

// ParseAddress parses host strings to Address interface properties.
func ParseAddress(addrStr string) (Address, error) {
	ip := net.ParseIP(addrStr)
	if ip != nil {
		if ip.To4() != nil {
			return &ParsedAddress{ip: ip, family: AddressFamilyIPv4}, nil
		}
		return &ParsedAddress{ip: ip, family: AddressFamilyIPv6}, nil
	}
	if addrStr == "" {
		return nil, errors.New("empty address string")
	}
	return &ParsedAddress{domain: addrStr, family: AddressFamilyDomain}, nil
}

// TLSConfigMock represents V2Ray TLS configuration.
type TLSConfigMock struct {
	CertFile                         string   `json:"certFile"`
	KeyFile                          string   `json:"keyFile"`
	AllowInsecure                    bool     `json:"allowInsecure"`
	ServerName                       string   `json:"serverName"`
	ALPN                             []string `json:"alpn"`
	EnableSessionResumption          bool     `json:"enableSessionResumption"`
	DisableSystemRoot                bool     `json:"disableSystemRoot"`
	PinnedPeerCertificateChainSha256 []string `json:"pinnedPeerCertificateChainSha256"`
}

// BuildTLSClientConfig builds simulated TLS properties.
func (t *TLSConfigMock) BuildTLSClientConfig() string {
	var pins string
	if len(t.PinnedPeerCertificateChainSha256) > 0 {
		pins = fmt.Sprintf(", PinnedSha256=%s", strings.Join(t.PinnedPeerCertificateChainSha256, ";"))
	}
	return fmt.Sprintf("TLSConfig: SNI=%s, Insecure=%t, ALPN=%s, SessionResumption=%t%s",
		t.ServerName, t.AllowInsecure, strings.Join(t.ALPN, ","), t.EnableSessionResumption, pins)
}

// BlackholeResponseMock represents blackhole Spoof responses.
type BlackholeResponseMock struct {
	Type string `json:"type"` // "none" or "http"
}

// BuildBlackholeConfig parses response configs.
func (b *BlackholeResponseMock) BuildBlackholeConfig() (string, error) {
	if b.Type == "" || b.Type == "none" {
		return "Blackhole: None Response Settings Built", nil
	}
	if b.Type == "http" {
		return "Blackhole: HTTP Response Settings Built", nil
	}
	return "", fmt.Errorf("failed to parse Blackhole response config type: %s", b.Type)
}
