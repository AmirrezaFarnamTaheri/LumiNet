package proxy

import (
	"bufio"
	"errors"
	"io"
	"net/netip"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// CIDR Prefix-List ACL
// Ported from v2rayA/Clash routing cores.
// High-performance IP routing decisions using netip.Prefix.
// ─────────────────────────────────────────────────────────────────────────────

// PrefixList represents an optimized list of IP prefixes for fast matching.
type PrefixList struct {
	prefixes []netip.Prefix
}

// NewPrefixList creates an empty prefix list.
func NewPrefixList() *PrefixList {
	return &PrefixList{
		prefixes: make([]netip.Prefix, 0),
	}
}

// Add parses a CIDR string and adds it to the list.
func (p *PrefixList) Add(cidr string) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return err
	}
	p.prefixes = append(p.prefixes, prefix)
	return nil
}

// Contains checks if the given IP string is covered by any prefix in the list.
func (p *PrefixList) Contains(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ContainsAddr checks if the given netip.Addr is covered by the list.
func (p *PrefixList) ContainsAddr(addr netip.Addr) bool {
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// LoadFromReader loads CIDR rules from an io.Reader (one per line).
// Ignores empty lines and comments (#).
func LoadFromReader(r io.Reader) (*PrefixList, error) {
	if r == nil {
		return nil, errors.New("nil reader")
	}
	pl := NewPrefixList()
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Split by space/comment just in case
		parts := strings.Fields(line)
		if len(parts) > 0 {
			_ = pl.Add(parts[0]) // Ignore parse errors for robust loading
		}
	}
	return pl, scanner.Err()
}
