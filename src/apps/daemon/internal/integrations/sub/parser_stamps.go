// SPDX-License-Identifier: MIT
//
// dnscrypt stamp-list subscription parsing (R2 roadmap wiring). Operator
// feeds sometimes ship raw dnscrypt DNS stamps (one per line, from
// dnscrypt-proxy public-resolvers lists). This parser turns such a feed
// into normalised resolver entries so stamp-based feeds flow through the
// same subscription pipeline as share-link feeds. Wraps
// networking/dns.ParseServerStampList.

package sub

import (
	"fmt"

	dnsnet "github.com/maybeknott/luminet/internal/networking/dns"
)

// StampResolver is the normalised form of one parsed DNS stamp.
type StampResolver struct {
	// Proto is one of "dnscrypt", "doh", "dot", "odoh-target", "dnscrypt-relay".
	Proto string `json:"proto"`
	// Addr is the provider address (host:port for plain/dnscrypt, URL for DoH/DoT).
	Addr string `json:"addr"`
	// ProviderName is the provider certificate name (dnscrypt) or hostname.
	ProviderName string `json:"provider_name,omitempty"`
	// Path is the DoH/DoT URL path, when present.
	Path string `json:"path,omitempty"`
	// PubKeyHex is the server public key, hex encoded.
	PubKeyHex string `json:"pub_key_hex,omitempty"`
	// Hashes are the hashed certificate hashes, hex encoded.
	Hashes []string `json:"hashes,omitempty"`
	// Props are the informal property flags (DNSSEC, NoLog, NoFilter).
	Props dnsnet.ServerInformalProperties `json:"props,omitempty"`
}

// StampParseIssue reports one unparseable feed line (skipped, not fatal).
type StampParseIssue struct {
	Line int    `json:"line"`
	Err  string `json:"err"`
}

// StampParseResult is the outcome of parsing a whole stamp feed.
type StampParseResult struct {
	Resolvers []StampResolver   `json:"resolvers"`
	Issues    []StampParseIssue `json:"issues,omitempty"`
}

// ParseStampFeed decodes a multi-line dnscrypt stamp list. Blank lines,
// comment lines (#, //) and non-stamp lines are silently skipped by the
// underlying batch parser (mixed-feed semantics); genuinely malformed
// sdns:// entries are reported as issues with 1-based line numbers. Never fails: partial parse is always returned.
func ParseStampFeed(content string) StampParseResult {
	stamps, errs := dnsnet.ParseServerStampList(content)
	out := StampParseResult{Resolvers: make([]StampResolver, 0, len(stamps))}
	for _, e := range errs {
		out.Issues = append(out.Issues, StampParseIssue{Line: e.Line, Err: e.Err.Error()})
	}
	for _, s := range stamps {
		r := StampResolver{
			Proto:        s.Proto.String(),
			Addr:         s.ServerAddrStr,
			ProviderName: s.ProviderName,
			Path:         s.Path,
			PubKeyHex:    fmt.Sprintf("%x", s.ServerPk),
			Hashes:       make([]string, 0, len(s.Hashes)),
			Props:        s.Props,
		}
		for _, h := range s.Hashes {
			r.Hashes = append(r.Hashes, fmt.Sprintf("%x", h))
		}
		out.Resolvers = append(out.Resolvers, r)
	}
	return out
}
