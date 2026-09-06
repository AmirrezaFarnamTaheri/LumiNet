package mobile

type BypassSubnet struct {
	Address string
	Prefix  int
}

// GetBypassSubnets returns subnets that must NOT route into the VPN interface.
func GetBypassSubnets() []BypassSubnet {
	return []BypassSubnet{
		{"10.0.0.0", 8},          // RFC 1918 Private LAN
		{"172.16.0.0", 12},       // RFC 1918 Private LAN
		{"192.168.0.0", 16},      // RFC 1918 Private LAN
		{"127.0.0.0", 8},         // Loopback
		{"169.254.0.0", 16},      // Link-Local (auto-IP)
		{"224.0.0.0", 4},         // Multicast
		{"255.255.255.255", 32},  // Broadcast
		{"100.64.0.0", 10},       // CGNAT (Carrier-grade NAT)
		{"198.18.0.0", 15},       // Benchmarking / Inter-network communications
	}
}

// GetIPv6BypassSubnets returns IPv6 multicast and link-local ranges that bypass proxying.
func GetIPv6BypassSubnets() []BypassSubnet {
	return []BypassSubnet{
		{"fe80::", 10},   // Link-local unicast
		{"ff02::1", 128}, // Link-local multicast node-local (all nodes)
		{"ff02::2", 128}, // Link-local multicast node-local (all routers)
	}
}

// NonTorList contains the subnet list matching InviZible routing exclusions.
func NonTorList() []BypassSubnet {
	subnets := GetBypassSubnets()
	subnets = append(subnets, GetIPv6BypassSubnets()...)
	return subnets
}
