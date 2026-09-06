// Package security handles intrusion detection and firewall hooks.
package security

import (
	"fmt"
	"net"
	"strings"
)

// ThreatLevel is a risk score for an IP.
type ThreatLevel int

const (
	ThreatNone     ThreatLevel = 0
	ThreatLow      ThreatLevel = 1
	ThreatMedium   ThreatLevel = 2
	ThreatHigh     ThreatLevel = 3
	ThreatCritical ThreatLevel = 4
)

// IPAnalyser classifies IPs by PTR heuristics and private-range checks.
type IPAnalyser struct {
	privateNets    []*net.IPNet
	ThreatKeywords []string
}

func NewIPAnalyser() *IPAnalyser {
	privates := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	var nets []*net.IPNet
	for _, c := range privates {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return &IPAnalyser{
		privateNets:    nets,
		ThreatKeywords: []string{"tor-exit", "vpn", "proxy", "relay", "scan", "bot"},
	}
}

// Analyse returns the threat level and reasons for an IP.
func (a *IPAnalyser) Analyse(ipStr string) (ThreatLevel, string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ThreatNone, "", fmt.Errorf("IPAnalyser.Analyse: invalid IP %q", ipStr)
	}
	if ip.IsLoopback() {
		return ThreatNone, "loopback", nil
	}
	for _, n := range a.privateNets {
		if n.Contains(ip) {
			return ThreatNone, "private", nil
		}
	}
	ptrs, _ := net.LookupAddr(ipStr)
	ptr := strings.ToLower(strings.Join(ptrs, " "))
	level := ThreatNone
	var reasons []string
	for _, kw := range a.ThreatKeywords {
		if strings.Contains(ptr, kw) {
			level++
			reasons = append(reasons, kw)
		}
	}
	if level > ThreatCritical {
		level = ThreatCritical
	}
	return level, strings.Join(reasons, ","), nil
}

// IsPrivate reports whether ip falls in a private or loopback range.
func (a *IPAnalyser) IsPrivate(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.IsLoopback() {
		return true
	}
	for _, n := range a.privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}