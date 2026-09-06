package proxy

import (
	"fmt"
	"math/big"
	"net"
)

// Subnet returns a subnet IPNet from a base IPNet, adding newBits to prefix length and selecting subnet index num.
func Subnet(base *net.IPNet, newBits int, num int) (*net.IPNet, error) {
	return SubnetBig(base, newBits, big.NewInt(int64(num)))
}

// SubnetBig is Subnet but using a big.Int index.
func SubnetBig(base *net.IPNet, newBits int, num *big.Int) (*net.IPNet, error) {
	ip := base.IP.To4()
	bits := 32
	if ip == nil {
		ip = base.IP.To16()
		bits = 128
	}
	if ip == nil {
		return nil, fmt.Errorf("invalid IP in base network")
	}

	ones, totalBits := base.Mask.Size()
	newOnes := ones + newBits
	if newOnes > totalBits {
		return nil, fmt.Errorf("new prefix length %d exceeds total bits %d", newOnes, totalBits)
	}

	// Calculate maximum number of subnets
	maxNum := big.NewInt(1)
	maxNum.Lsh(maxNum, uint(newBits))
	if num.Cmp(big.NewInt(0)) < 0 || num.Cmp(maxNum) >= 0 {
		return nil, fmt.Errorf("subnet index %s out of range [0, %s)", num.String(), maxNum.String())
	}

	ipInt, _ := ipToInt(ip)
	// Shift index into position
	offset := big.NewInt(1)
	offset.Lsh(num, uint(bits-newOnes))
	ipInt.Add(ipInt, offset)

	newIP := intToIP(ipInt, bits)
	newMask := net.CIDRMask(newOnes, totalBits)

	return &net.IPNet{
		IP:   newIP.Mask(newMask),
		Mask: newMask,
	}, nil
}

// Host returns the IP of the host at index num in base network.
func Host(base *net.IPNet, num int) (net.IP, error) {
	return HostBig(base, big.NewInt(int64(num)))
}

// HostBig is Host but using big.Int index.
func HostBig(base *net.IPNet, num *big.Int) (net.IP, error) {
	ip := base.IP.To4()
	bits := 32
	if ip == nil {
		ip = base.IP.To16()
		bits = 128
	}
	if ip == nil {
		return nil, fmt.Errorf("invalid IP in base network")
	}

	ones, _ := base.Mask.Size()
	maxNum := big.NewInt(1)
	maxNum.Lsh(maxNum, uint(bits-ones))
	if num.Cmp(big.NewInt(0)) < 0 || num.Cmp(maxNum) >= 0 {
		return nil, fmt.Errorf("host index %s out of range [0, %s)", num.String(), maxNum.String())
	}

	ipInt, _ := ipToInt(ip)
	ipInt.Add(ipInt, num)

	return intToIP(ipInt, bits), nil
}

// AddressRange returns the first and last IP of the CIDR network block.
func AddressRange(network *net.IPNet) (net.IP, net.IP) {
	first := network.IP
	last := make(net.IP, len(first))
	for i := range first {
		last[i] = first[i] | ^network.Mask[i]
	}
	return first, last
}

// AddressCount returns the number of addresses in the network block.
func AddressCount(network *net.IPNet) uint64 {
	ones, bits := network.Mask.Size()
	return 1 << uint(bits-ones)
}

// VerifyNoOverlap asserts that none of the subnets overlap with the given CIDR block.
func VerifyNoOverlap(subnets []*net.IPNet, CIDRBlock *net.IPNet) error {
	for _, sub := range subnets {
		if sub.Contains(CIDRBlock.IP) || CIDRBlock.Contains(sub.IP) {
			return fmt.Errorf("networks %s and %s overlap", sub.String(), CIDRBlock.String())
		}
	}
	return nil
}

// PreviousSubnet returns the previous subnet block of the same prefix length, if it exists.
func PreviousSubnet(network *net.IPNet, prefixLen int) (*net.IPNet, bool) {
	ip := network.IP.To4()
	bits := 32
	if ip == nil {
		ip = network.IP.To16()
		bits = 128
	}
	if ip == nil {
		return nil, false
	}

	ipInt, _ := ipToInt(ip)
	offset := big.NewInt(1)
	offset.Lsh(offset, uint(bits-prefixLen))

	// check underflow
	if ipInt.Cmp(offset) < 0 {
		return nil, false
	}

	ipInt.Sub(ipInt, offset)
	prevIP := intToIP(ipInt, bits)
	mask := net.CIDRMask(prefixLen, bits)
	return &net.IPNet{
		IP:   prevIP.Mask(mask),
		Mask: mask,
	}, true
}

// NextSubnet returns the next subnet block of the same prefix length, if it exists.
func NextSubnet(network *net.IPNet, prefixLen int) (*net.IPNet, bool) {
	ip := network.IP.To4()
	bits := 32
	if ip == nil {
		ip = network.IP.To16()
		bits = 128
	}
	if ip == nil {
		return nil, false
	}

	ipInt, _ := ipToInt(ip)
	offset := big.NewInt(1)
	offset.Lsh(offset, uint(bits-prefixLen))

	ipInt.Add(ipInt, offset)

	// check overflow
	limit := big.NewInt(1)
	limit.Lsh(limit, uint(bits))
	if ipInt.Cmp(limit) >= 0 {
		return nil, false
	}

	nextIP := intToIP(ipInt, bits)
	mask := net.CIDRMask(prefixLen, bits)
	return &net.IPNet{
		IP:   nextIP.Mask(mask),
		Mask: mask,
	}, true
}

// Inc increments an IP address.
func Inc(IP net.IP) net.IP {
	ip := make(net.IP, len(IP))
	copy(ip, IP)
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
	return ip
}

// Dec decrements an IP address.
func Dec(IP net.IP) net.IP {
	ip := make(net.IP, len(IP))
	copy(ip, IP)
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]--
		if ip[i] < 255 {
			break
		}
	}
	return ip
}

func ipToInt(ip net.IP) (*big.Int, int) {
	val := &big.Int{}
	val.SetBytes(ip)
	return val, len(ip) * 8
}

func intToIP(ipInt *big.Int, bits int) net.IP {
	ipBytes := ipInt.Bytes()
	ret := make(net.IP, bits/8)
	// pad on the left
	copy(ret[len(ret)-len(ipBytes):], ipBytes)
	return ret
}

func insertNumIntoIP(ip net.IP, bigNum *big.Int, prefixLen int) net.IP {
	ipInt, bits := ipToInt(ip)

	// Create a mask to clear the host bits
	mask := big.NewInt(1)
	mask.Lsh(mask, uint(bits-prefixLen))
	mask.Sub(mask, big.NewInt(1))
	mask.Not(mask)

	ipInt.And(ipInt, mask)
	ipInt.Or(ipInt, bigNum)
	return intToIP(ipInt, bits)
}

// checkIPv4 is helper to convert 16-byte representation to 4-byte IPv4 if applicable
func checkIPv4(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
