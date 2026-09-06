package scanner

import (
	"fmt"
	"net"
)

// divideCIDRSubnets splits parentCIDR into subnets at subnetBits. It is scanner
// implementation, not a reusable cross-module interface.
func divideCIDRSubnets(parentCIDR string, subnetBits int) ([]string, error) {
	_, network, err := net.ParseCIDR(parentCIDR)
	if err != nil {
		return nil, fmt.Errorf("divide CIDR %q: %w", parentCIDR, err)
	}
	ones, bits := network.Mask.Size()
	if subnetBits < ones || subnetBits > bits {
		return nil, fmt.Errorf("subnet bits %d out of range [%d, %d]", subnetBits, ones, bits)
	}
	diff := subnetBits - ones
	if diff > 24 {
		return nil, fmt.Errorf("would produce %d subnets (limit 16M)", 1<<diff)
	}
	numSubnets := 1 << diff
	step := int64(1) << (bits - subnetBits)
	base := append(net.IP(nil), network.IP.Mask(network.Mask)...)
	subnets := make([]string, 0, numSubnets)
	for i := 0; i < numSubnets; i++ {
		current := append(net.IP(nil), base...)
		addCIDROffset(current, int64(i)*step)
		subnets = append(subnets, fmt.Sprintf("%s/%d", current.String(), subnetBits))
	}
	return subnets, nil
}

func addCIDROffset(ip net.IP, offset int64) {
	for i := len(ip) - 1; i >= 0 && offset > 0; i-- {
		value := int64(ip[i]) + offset
		ip[i] = byte(value & 0xff)
		offset = value >> 8
	}
}
