// Package sub manages subscription parsing and fetching.
package sub

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

// GeoIPDatabase handles IP range mapping from sing-geoip and MaxMind-compatible binary formats.
type GeoIPDatabase struct {
	// entries maps country codes to CIDR ranges
	entries map[string][]string
}

// GeoIPEntry represents a single GeoIP record.
type GeoIPEntry struct {
	CountryCode string
	CIDRs       []string
}

func NewGeoIPDatabase() *GeoIPDatabase {
	return &GeoIPDatabase{
		entries: make(map[string][]string),
	}
}

// Parse reads sing-geoip format binary database from r, populating CIDR lookup tables.
// The format is a sequence of length-prefixed protobuf-like records:
//
//	[2-byte ISO country code][4-byte CIDR count][CIDRs as 5-byte records: [1-byte prefix][4-byte IP]]
func (g *GeoIPDatabase) Parse(r io.Reader) error {
	g.entries = make(map[string][]string)
	br := bufio.NewReader(r)

	for {
		// Read 2-byte country code
		code := make([]byte, 2)
		if _, err := io.ReadFull(br, code); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("GeoIPDatabase.Parse: read country code: %w", err)
		}
		cc := strings.ToUpper(string(code))

		// Read 4-byte CIDR count
		var count uint32
		if err := binary.Read(br, binary.BigEndian, &count); err != nil {
			return fmt.Errorf("GeoIPDatabase.Parse: read count for %s: %w", cc, err)
		}

		cidrs := make([]string, 0, count)
		for i := uint32(0); i < count; i++ {
			// 1-byte prefix length + 4-byte IPv4
			prefix := make([]byte, 1)
			if _, err := io.ReadFull(br, prefix); err != nil {
				return fmt.Errorf("GeoIPDatabase.Parse: read prefix: %w", err)
			}
			ipBytes := make([]byte, 4)
			if _, err := io.ReadFull(br, ipBytes); err != nil {
				return fmt.Errorf("GeoIPDatabase.Parse: read ip: %w", err)
			}
			ip := net.IP(ipBytes)
			cidrs = append(cidrs, fmt.Sprintf("%s/%d", ip.String(), prefix[0]))
		}
		g.entries[cc] = cidrs
	}
	return nil
}

// LookupCountry returns all CIDR ranges for the given ISO 3166-1 alpha-2 country code.
func (g *GeoIPDatabase) LookupCountry(code string) ([]string, bool) {
	cidrs, ok := g.entries[strings.ToUpper(code)]
	return cidrs, ok
}

// AllCountries returns all country codes present in the database.
func (g *GeoIPDatabase) AllCountries() []string {
	codes := make([]string, 0, len(g.entries))
	for k := range g.entries {
		codes = append(codes, k)
	}
	return codes
}

// Contains reports whether the given IP address falls within any CIDR for the given country code.
func (g *GeoIPDatabase) Contains(code, ipStr string) (bool, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, fmt.Errorf("GeoIPDatabase.Contains: invalid IP %q", ipStr)
	}
	cidrs, ok := g.entries[strings.ToUpper(code)]
	if !ok {
		return false, nil
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}
