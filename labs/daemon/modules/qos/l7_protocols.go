// Package qos manages packet classification and traffic shaping.
// Ported from: l7-protocols-master (README, protocols/)
// Target path: server/internal/qos/l7_protocols.go

package qos

import (
	"regexp"
	"strings"
)

// L7ProtocolDef represents a Layer-7 protocol pattern definition.
type L7ProtocolDef struct {
	Name        string
	Category    string
	Pattern     string
	Description string
	Regexp      *regexp.Regexp
}

// Getters & Setters for L7ProtocolDef
func (d *L7ProtocolDef) GetName() string { return d.Name }
func (d *L7ProtocolDef) SetName(v string) { d.Name = v }

// DefaultL7Protocols returns predefined Layer-7 protocol definitions.
func DefaultL7Protocols() []L7ProtocolDef {
	defs := []L7ProtocolDef{
		{
			Name:        "http",
			Category:    "web",
			Pattern:     `^(get|post|head|put|delete|options|trace|connect) .* http/1\.[01]`,
			Description: "Hypertext Transfer Protocol HTTP/1.x",
		},
		{
			Name:        "ssh",
			Category:    "remote",
			Pattern:     `^ssh-[12]\.[0-9]`,
			Description: "Secure Shell Protocol",
		},
		{
			Name:        "dns",
			Category:    "networking",
			Pattern:     `^[\x00-\xff][\x00-\xff][\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00]`,
			Description: "Domain Name System standard query",
		},
		{
			Name:        "tls",
			Category:    "secure",
			Pattern:     `^\x16\x03[\x00-\x03]`,
			Description: "Transport Layer Security handshake record",
		},
		{
			Name:        "bittorrent",
			Category:    "p2p",
			Pattern:     `^\x13bittorrent protocol`,
			Description: "BitTorrent Peer Protocol handshake",
		},
		{
			Name:        "socks",
			Category:    "proxy",
			Pattern:     `^[\x04\x05][\x01-\x03][\x00-\xff]`,
			Description: "SOCKS Proxy Handshake",
		},
		{
			Name:        "ftp",
			Category:    "file",
			Pattern:     `^220[\x20-\x7e]+(ftp|file transfer)`,
			Description: "File Transfer Protocol Greeting",
		},
		{
			Name:        "smtp",
			Category:    "email",
			Pattern:     `^220[\x20-\x7e]+(smtp|mail|esmtp)`,
			Description: "Simple Mail Transfer Protocol Greeting",
		},
		{
			Name:        "imap",
			Category:    "email",
			Pattern:     `^\* OK [\x20-\x7e]*imap`,
			Description: "Internet Message Access Protocol Greeting",
		},
		{
			Name:        "rdp",
			Category:    "remote",
			Pattern:     `^\x03\x00\x00[\x09-\xff]\x0e\xe0\x00\x00\x00\x00\x00`,
			Description: "Remote Desktop Protocol Connection Request",
		},
		{
			Name:        "smb",
			Category:    "file",
			Pattern:     `^\xffsmb`,
			Description: "Server Message Block",
		},
		{
			Name:        "telnet",
			Category:    "remote",
			Pattern:     `^\xff[\xfb-\xfe][\x00-\xff]`,
			Description: "Telnet Negotiation Sequence",
		},
	}

	for i := range defs {
		if re, err := regexp.Compile("(?i)" + defs[i].Pattern); err == nil {
			defs[i].Regexp = re
		}
	}
	return defs
}

// MatchL7Protocol checks payload bytes against known protocol signatures.
func MatchL7Protocol(payload []byte, defs []L7ProtocolDef) string {
	if len(payload) == 0 {
		return "unknown"
	}
	// Convert slice safely to string for regex checks
	s := string(payload)
	if len(s) > 128 {
		s = s[:128]
	}
	for _, def := range defs {
		if def.Regexp != nil && def.Regexp.MatchString(s) {
			return def.Name
		}
	}
	return "unknown"
}

// ClassifyTraffic performs inline categorization.
func ClassifyTraffic(payload []byte) (string, string) {
	defs := DefaultL7Protocols()
	name := MatchL7Protocol(payload, defs)
	if name == "unknown" {
		return "unknown", "unknown"
	}
	for _, def := range defs {
		if strings.EqualFold(def.Name, name) {
			return def.Name, def.Category
		}
	}
	return name, "unknown"
}
