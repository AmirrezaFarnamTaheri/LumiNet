package scanner

import (
	"fmt"
	"net"
)

// CIDRExpansionResult holds the expanded IP addresses from a CIDR block.
type CIDRExpansionResult struct {
	CIDR   string
	IPs    []string
	Count  int
}

// CIDRExpander expands CIDR blocks to their constituent IP address list.
type CIDRExpander struct{}

// NewCIDRExpander returns a new CIDRExpander.
func NewCIDRExpander() *CIDRExpander {
	return &CIDRExpander{}
}

// ExpandCIDR enumerates all host addresses within the given CIDR range.
// For /24 and smaller blocks, it returns every IP. For larger blocks (> 65536 IPs),
// it returns an error to prevent memory exhaustion.
func (e *CIDRExpander) ExpandCIDR(cidr string) (*CIDRExpansionResult, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("CIDRExpander: invalid CIDR %q: %w", cidr, err)
	}

	ones, bits := network.Mask.Size()
	hostBits := bits - ones
	// Cap expansion at 2^16 = 65536 hosts
	if hostBits > 16 {
		return nil, fmt.Errorf("CIDRExpander: block too large (%d host bits)", hostBits)
	}

	count := 1 << hostBits
	ips := make([]string, 0, count)

	current := cloneIP(ip.Mask(network.Mask))
	for i := 0; i < count; i++ {
		ips = append(ips, current.String())
		incrementIP(current)
	}

	return &CIDRExpansionResult{CIDR: cidr, IPs: ips, Count: count}, nil
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// DivideCIDRIntoSubnets divides a larger CIDR range into smaller CIDR blocks of the specified size.
// Returns a list of CIDR strings.
func (e *CIDRExpander) DivideCIDRIntoSubnets(cidr string, subnetBits int) ([]string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("CIDRExpander: invalid CIDR %q: %w", cidr, err)
	}

	ones, bits := network.Mask.Size()
	if subnetBits < ones || subnetBits > bits {
		// If requesting a larger subnet size than base network or out of range, return the base CIDR.
		return []string{network.String()}, nil
	}

	// Calculate number of subnets
	diff := subnetBits - ones
	if diff > 24 {
		return nil, fmt.Errorf("CIDRExpander: subnet division results in too many subnets (%d subnets)", 1<<diff)
	}

	numSubnets := 1 << diff
	subnets := make([]string, 0, numSubnets)
	baseIP := network.IP.Mask(network.Mask)

	// Subnet step size in decimal bytes
	step := 1 << (bits - subnetBits)

	// Work with 4 bytes for IPv4, 16 bytes for IPv6
	for i := 0; i < numSubnets; i++ {
		current := cloneIP(baseIP)
		// Add offset to base IP
		offset := int64(i) * int64(step)
		addOffsetToIP(current, offset)
		subnets = append(subnets, fmt.Sprintf("%s/%d", current.String(), subnetBits))
	}

	return subnets, nil
}

func addOffsetToIP(ip net.IP, offset int64) {
	// Add offset from right to left
	for i := len(ip) - 1; i >= 0 && offset > 0; i-- {
		val := int64(ip[i]) + offset
		ip[i] = byte(val & 0xff)
		offset = val >> 8
	}
}
