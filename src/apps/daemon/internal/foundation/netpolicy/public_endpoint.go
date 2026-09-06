package netpolicy

import "net/netip"

// IsPublicAddress reports whether address is safe to use as an untrusted
// remote-network probe/fetch destination. Global-unicast alone is not enough:
// documentation, benchmarking, CGNAT, protocol-transition, and other special
// ranges must also be denied so remote data cannot steer LumiNet toward local
// or non-routable targets.
func IsPublicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// IsDocumentationAddress identifies address ranges reserved for examples and
// documentation. Fronted Tor transports often carry such placeholders and
// must be probed through their declared broker/front endpoint instead.
func IsDocumentationAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() {
		return false
	}
	for _, prefix := range documentationPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

var documentationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}
