package routing

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
)

type GeoCidrEntry struct {
	NetAddr     uint32
	Mask        uint32
	CountryCode string
}

type EnhancedGeoIpLookup struct {
	mu      sync.RWMutex
	entries []GeoCidrEntry
}

func NewEnhancedGeoIpLookup() *EnhancedGeoIpLookup {
	return &EnhancedGeoIpLookup{
		entries: make([]GeoCidrEntry, 0),
	}
}

func (g *EnhancedGeoIpLookup) AddCidr(octets [4]byte, maskBits uint8, countryCode string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	ipU32 := binary.BigEndian.Uint32(octets[:])
	var mask uint32
	if maskBits == 0 {
		mask = 0
	} else {
		mask = ^uint32(0) << (32 - maskBits)
	}

	g.entries = append(g.entries, GeoCidrEntry{
		NetAddr:     ipU32 & mask,
		Mask:        mask,
		CountryCode: strings.ToUpper(strings.TrimSpace(countryCode)),
	})
}

func (g *EnhancedGeoIpLookup) Lookup(octets [4]byte) (string, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	ipU32 := binary.BigEndian.Uint32(octets[:])
	var bestMatch string
	var bestMask uint32
	found := false

	for _, entry := range g.entries {
		if (ipU32 & entry.Mask) == entry.NetAddr {
			if !found || entry.Mask > bestMask {
				bestMatch = entry.CountryCode
				bestMask = entry.Mask
				found = true
			}
		}
	}

	return bestMatch, found
}

func (g *EnhancedGeoIpLookup) LookupIP(ip net.IP) (string, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return "", false
	}
	var octets [4]byte
	copy(octets[:], ip4)
	return g.Lookup(octets)
}

func IsPrivateIPv4(octets [4]byte) bool {
	switch octets[0] {
	case 10, 127:
		return true
	case 172:
		return octets[1] >= 16 && octets[1] <= 31
	case 192:
		return octets[1] == 168
	default:
		return false
	}
}
