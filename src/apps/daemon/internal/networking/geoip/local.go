package geoip

import (
	"net"
	"strings"
)

// IsLocalOrLanIP returns true if the given IP address is in a local or private LAN subnet.
// Includes loopback, RFC 1918, RFC 3927 (link-local), RFC 6598 (CGNAT), and IPv6 local/multicast ranges.
func IsLocalOrLanIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// 1. Loopback checking
	if ip.IsLoopback() {
		return true
	}

	// 2. Multicast checking
	if ip.IsMulticast() {
		return true
	}

	// 3. IPv4 specific checks
	if ip4 := ip.To4(); ip4 != nil {
		// RFC 1918 private subnets:
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// RFC 3927 Link-Local: 169.254.0.0/16
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		// RFC 6598 CGNAT: 100.64.0.0/10
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		return false
	}

	// 4. IPv6 specific checks
	// Link-Local: fe80::/10
	if strings.HasPrefix(strings.ToLower(ip.String()), "fe80:") {
		return true
	}
	// Unique Local (ULA): fc00::/7
	if len(ip) == 16 {
		firstByte := ip[0]
		if (firstByte & 0xfe) == 0xfc {
			return true
		}
	}
	// Site-Local: fec0::/10
	if strings.HasPrefix(strings.ToLower(ip.String()), "fec0:") {
		return true
	}

	return false
}
