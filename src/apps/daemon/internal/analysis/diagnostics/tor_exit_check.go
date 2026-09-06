package diagnostics

import (
	"context"
	"fmt"
	"net"
	"strings"
)

const torDNSELSuffix = "dnsel.torproject.org"

type torHostResolver interface {
	LookupHost(context.Context, string) ([]string, error)
}

// TorExitStatus is deliberately tri-state: resolver failure is not evidence
// that an address is not a Tor exit.
type TorExitStatus string

const (
	TorExitYes     TorExitStatus = "exit"
	TorExitNo      TorExitStatus = "not_exit"
	TorExitUnknown TorExitStatus = "unknown"
)

type TorExitResult struct {
	IP     string        `json:"ip"`
	Query  string        `json:"query"`
	Status TorExitStatus `json:"status"`
	Answer []string      `json:"answer,omitempty"`
	Reason string        `json:"reason,omitempty"`
}

// TorDNSELQueryName returns the Tor DNSEL query name for an IPv4 address.
func TorDNSELQueryName(rawIP string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(rawIP))
	if ip == nil || ip.To4() == nil {
		return "", fmt.Errorf("Tor DNSEL requires an IPv4 address")
	}
	v4 := ip.To4()
	return fmt.Sprintf("%d.%d.%d.%d.%s", v4[3], v4[2], v4[1], v4[0], torDNSELSuffix), nil
}

// CheckTorExit queries Tor DNSEL using an injected resolver. NXDOMAIN means
// non-exit; 127.0.0.2 means exit; transport/timeouts remain unknown so a DNS
// outage cannot be misrepresented as negative evidence.
func CheckTorExit(ctx context.Context, rawIP string, resolver torHostResolver) (TorExitResult, error) {
	query, err := TorDNSELQueryName(rawIP)
	if err != nil {
		return TorExitResult{}, err
	}
	result := TorExitResult{IP: net.ParseIP(strings.TrimSpace(rawIP)).To4().String(), Query: query, Status: TorExitUnknown}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	answers, err := resolver.LookupHost(ctx, query)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			result.Status = TorExitNo
			result.Reason = "dnsel_nxdomain"
			return result, nil
		}
		result.Reason = "dnsel_unavailable"
		return result, nil
	}
	result.Answer = append([]string(nil), answers...)
	for _, answer := range answers {
		if ip := net.ParseIP(strings.TrimSpace(answer)); ip != nil && ip.Equal(net.IPv4(127, 0, 0, 2)) {
			result.Status = TorExitYes
			result.Reason = "dnsel_127_0_0_2"
			return result, nil
		}
	}
	// Unexpected positive DNS data is not authoritative non-exit evidence.
	result.Reason = "dnsel_unexpected_answer"
	return result, nil
}
