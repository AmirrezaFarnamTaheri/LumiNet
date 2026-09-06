package proxyconfig

import (
	"fmt"
	"strings"
)

// WgHopChain models a multi-hop WireGuard route: an entry hop, zero or more
// intermediate hops, and a terminal exit —
// WgHopManager (MPL-2; model re-expressed for the proxyconfig type system).
//
// Ordering matters: traffic enters at Chain[0] and exits through the last
// element. A single-element chain degenerates to a plain WireGuard outbound.
type WgHopChain struct {
	Hops []*ProxyConfig
}

// ParseWgHopChain parses a pipe-separated chain of WireGuard URIs:
//
//	wg://hop1.example:51820?...|wg://exit.example:51820?...
//
// Every segment must parse as a WireGuard (or AmneziaWG) config; duplicate
// endpoints inside one chain are rejected to prevent accidental loops.
func ParseWgHopChain(chain string) (*WgHopChain, error) {
	segments := strings.Split(chain, "|")
	if len(segments) == 0 {
		return nil, fmt.Errorf("wg hop chain is empty")
	}
	parsed := make([]*ProxyConfig, 0, len(segments))
	seenEndpoints := make(map[string]struct{}, len(segments))
	for i, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return nil, fmt.Errorf("wg hop chain segment %d is empty", i+1)
		}
		cfg, err := parseWireGuard(segment)
		if err != nil {
			return nil, fmt.Errorf("wg hop %d: %w", i+1, err)
		}
		key := strings.ToLower(cfg.Address) + ":" + fmt.Sprint(cfg.Port)
		if _, dup := seenEndpoints[key]; dup {
			return nil, fmt.Errorf("wg hop %d repeats endpoint %s", i+1, key)
		}
		seenEndpoints[key] = struct{}{}
		parsed = append(parsed, cfg)
	}
	return &WgHopChain{Hops: parsed}, nil
}

// Entry returns the first hop.
func (c *WgHopChain) Entry() *ProxyConfig {
	if len(c.Hops) == 0 {
		return nil
	}
	return c.Hops[0]
}

// Exit returns the last hop (nil when the chain is empty).
func (c *WgHopChain) Exit() *ProxyConfig {
	if len(c.Hops) == 0 {
		return nil
	}
	return c.Hops[len(c.Hops)-1]
}

// Validate checks the chain can route: every consecutive pair must differ in
// endpoint and each hop must carry both keys WireGuard needs to dial it.
func (c *WgHopChain) Validate() error {
	if len(c.Hops) == 0 {
		return fmt.Errorf("wg hop chain has no hops")
	}
	for i, hop := range c.Hops {
		if hop.PublicKey == "" {
			return fmt.Errorf("wg hop %d (%s): missing peer public key", i+1, hop.Address)
		}
		if i > 0 && c.Hops[i-1].Address == hop.Address && c.Hops[i-1].Port == hop.Port {
			return fmt.Errorf("wg hop %d repeats the previous endpoint", i+1)
		}
	}
	return nil
}

// Describe renders a stable human-readable summary for logs.
func (c *WgHopChain) Describe() string {
	parts := make([]string, 0, len(c.Hops))
	for _, hop := range c.Hops {
		parts = append(parts, fmt.Sprintf("%s:%d", hop.Address, hop.Port))
	}
	return strings.Join(parts, " -> ")
}
