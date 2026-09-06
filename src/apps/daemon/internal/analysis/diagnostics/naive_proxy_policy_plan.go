package diagnostics

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	naiveFirstPaddedFrames = 8
	naiveFrameHeaderBytes  = 3
	naiveMaxPaddingBytes   = 255
	naiveMaxPayloadBytes   = 65535
	maxNaiveProxyHops      = 8
	maxNaiveListeners      = 16
)

type NaiveListenPolicy struct {
	Scheme string `json:"scheme"`
	Port   int    `json:"port"`
}

type NaiveProxyHopPolicy struct {
	Scheme  string `json:"scheme"`
	HasAuth bool   `json:"has_auth,omitempty"`
}

type NaiveProxyPolicyRequest struct {
	Platform          string                `json:"platform"`
	Listeners         []NaiveListenPolicy   `json:"listeners"`
	ProxyChain        []NaiveProxyHopPolicy `json:"proxy_chain,omitempty"`
	Padding           string                `json:"padding,omitempty"`
	FastOpenRequested bool                  `json:"fast_open_requested,omitempty"`
	ResolverCIDR      string                `json:"resolver_cidr,omitempty"`
	ExtraHeaderCount  int                   `json:"extra_header_count,omitempty"`
}

type NaiveProxyPolicyPlan struct {
	Platform                    string                `json:"platform"`
	Listeners                   []NaiveListenPolicy   `json:"listeners"`
	ProxyChain                  []NaiveProxyHopPolicy `json:"proxy_chain"`
	Padding                     string                `json:"padding"`
	PaddingNegotiatedByHeader   bool                  `json:"padding_negotiated_by_header"`
	FirstPaddedFrames           int                   `json:"first_padded_frames"`
	FrameHeaderBytes            int                   `json:"frame_header_bytes"`
	MaxPaddingBytes             int                   `json:"max_padding_bytes"`
	MaxPayloadBytes             int                   `json:"max_payload_bytes"`
	FirstConnectFastOpenAllowed bool                  `json:"first_connect_fast_open_allowed"`
	NaivePaddingEligible        bool                  `json:"naive_padding_eligible"`
	PerformsNetworkIO           bool                  `json:"performs_network_io"`
	StartsProxy                 bool                  `json:"starts_proxy"`
	WritesResolverRules         bool                  `json:"writes_resolver_rules"`
	Warnings                    []string              `json:"warnings"`
	Invariants                  []string              `json:"invariants"`
}

func BuildNaiveProxyPolicyPlan(req NaiveProxyPolicyRequest) (NaiveProxyPolicyPlan, error) {
	platform := strings.ToLower(strings.TrimSpace(req.Platform))
	switch platform {
	case "linux", "windows", "macos", "android":
	default:
		return NaiveProxyPolicyPlan{}, fmt.Errorf("platform must be linux, windows, macos, or android")
	}
	if len(req.Listeners) == 0 || len(req.Listeners) > maxNaiveListeners {
		return NaiveProxyPolicyPlan{}, fmt.Errorf("listener count must be 1..%d", maxNaiveListeners)
	}
	listeners := make([]NaiveListenPolicy, 0, len(req.Listeners))
	for i, raw := range req.Listeners {
		scheme := strings.ToLower(strings.TrimSpace(raw.Scheme))
		switch scheme {
		case "socks", "http":
		case "redir":
			if platform != "linux" {
				return NaiveProxyPolicyPlan{}, fmt.Errorf("redir listener is supported only on linux")
			}
		default:
			return NaiveProxyPolicyPlan{}, fmt.Errorf("listener %d scheme must be socks, http, or redir", i)
		}
		if raw.Port < 1 || raw.Port > 65535 {
			return NaiveProxyPolicyPlan{}, fmt.Errorf("listener %d port must be 1..65535", i)
		}
		listeners = append(listeners, NaiveListenPolicy{Scheme: scheme, Port: raw.Port})
	}
	if len(req.ProxyChain) > maxNaiveProxyHops {
		return NaiveProxyPolicyPlan{}, fmt.Errorf("proxy chain exceeds %d hops", maxNaiveProxyHops)
	}
	chain := make([]NaiveProxyHopPolicy, 0, len(req.ProxyChain))
	hasSOCKS := false
	seenTCPBeforeQUIC := false
	for i, raw := range req.ProxyChain {
		scheme := strings.ToLower(strings.TrimSpace(raw.Scheme))
		switch scheme {
		case "http", "https":
			seenTCPBeforeQUIC = true
		case "socks":
			hasSOCKS = true
			seenTCPBeforeQUIC = true
			if raw.HasAuth {
				return NaiveProxyPolicyPlan{}, fmt.Errorf("SOCKS proxy authentication is not admitted by the NaiveProxy chain contract")
			}
		case "quic":
			if seenTCPBeforeQUIC {
				return NaiveProxyPolicyPlan{}, fmt.Errorf("QUIC proxy cannot follow a TCP-based proxy")
			}
		default:
			return NaiveProxyPolicyPlan{}, fmt.Errorf("proxy hop %d scheme must be http, https, socks, or quic", i)
		}
		chain = append(chain, NaiveProxyHopPolicy{Scheme: scheme, HasAuth: raw.HasAuth})
	}
	if len(chain) > 1 && hasSOCKS {
		return NaiveProxyPolicyPlan{}, fmt.Errorf("multi-proxy chains containing SOCKS are not admitted")
	}
	padding := strings.ToLower(strings.TrimSpace(req.Padding))
	if padding == "" {
		padding = "variant1"
	}
	if padding != "none" && padding != "variant1" {
		return NaiveProxyPolicyPlan{}, fmt.Errorf("padding must be none or variant1")
	}
	if req.ExtraHeaderCount < 0 || req.ExtraHeaderCount > 32 {
		return NaiveProxyPolicyPlan{}, fmt.Errorf("extra_header_count must be 0..32")
	}
	if cidr := strings.TrimSpace(req.ResolverCIDR); cidr != "" {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return NaiveProxyPolicyPlan{}, fmt.Errorf("resolver_cidr: %w", err)
		}
		if prefix.Addr().Is6() {
			return NaiveProxyPolicyPlan{}, fmt.Errorf("IPv6 resolver range is not admitted by the NaiveProxy resolver contract")
		}
	}
	paddingEligible := false
	if len(chain) > 0 {
		last := chain[len(chain)-1].Scheme
		paddingEligible = last == "http" || last == "https" || last == "quic"
	}
	plan := NaiveProxyPolicyPlan{
		Platform: platform, Listeners: listeners, ProxyChain: chain, Padding: padding,
		PaddingNegotiatedByHeader: padding == "variant1", FirstPaddedFrames: naiveFirstPaddedFrames,
		FrameHeaderBytes: naiveFrameHeaderBytes, MaxPaddingBytes: naiveMaxPaddingBytes,
		MaxPayloadBytes: naiveMaxPayloadBytes, FirstConnectFastOpenAllowed: padding != "variant1",
		NaivePaddingEligible: paddingEligible, PerformsNetworkIO: false, StartsProxy: false, WritesResolverRules: false,
		Invariants: []string{
			"variant1 framing is limited to the first eight reads and writes after stream establishment",
			"each padded frame has a two-byte payload length, one-byte padding length, at most 255 padding bytes, and at most 65535 payload bytes",
			"padding is opt-in and considered negotiated only through peer padding capability evidence",
			"the first CONNECT cannot use payload Fast Open while padding capability is still unknown",
			"SOCKS hops do not gain authentication, chaining, or Naive padding semantics they cannot represent",
			"QUIC hops never silently follow TCP-based hops",
			"the planner never creates listeners, modifies iptables, writes resolver rules, logs TLS keys, or starts a proxy runtime",
		},
	}
	if padding == "variant1" && !paddingEligible {
		plan.Warnings = append(plan.Warnings, "variant1 padding was requested but the final proxy hop is not padding-capable")
	}
	if req.FastOpenRequested && padding == "variant1" {
		plan.Warnings = append(plan.Warnings, "Fast Open is suppressed on the first CONNECT until peer padding capability is known")
	}
	return plan, nil
}
