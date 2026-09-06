package transport

import (
	"sync"
)

type CensorshipRegion int

const (
	RegionGlobal CensorshipRegion = iota
	RegionChina
	RegionIran
	RegionRussia
)

type RegionalEvasionProfile struct {
	Region                   CensorshipRegion
	DnsFragmentationEnabled  bool
	DnsFragmentSize          int
	TcpMssClamp              uint16
	TlsPaddingMin            int
	TlsPaddingMax            int
	ParallelDnsQueries       bool
	PreferredDnsServers      []string
}

type CensorshipProfileSynthesizer struct {
	profiles map[CensorshipRegion]*RegionalEvasionProfile
	mu       sync.RWMutex
}

func NewCensorshipProfileSynthesizer() *CensorshipProfileSynthesizer {
	s := &CensorshipProfileSynthesizer{
		profiles: make(map[CensorshipRegion]*RegionalEvasionProfile),
	}

	s.profiles[RegionChina] = &RegionalEvasionProfile{
		Region:                  RegionChina,
		DnsFragmentationEnabled: true,
		DnsFragmentSize:         40,
		TcpMssClamp:             1200,
		TlsPaddingMin:           100,
		TlsPaddingMax:           500,
		ParallelDnsQueries:      true,
		PreferredDnsServers:     []string{"https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"},
	}

	s.profiles[RegionIran] = &RegionalEvasionProfile{
		Region:                  RegionIran,
		DnsFragmentationEnabled: true,
		DnsFragmentSize:         32,
		TcpMssClamp:             1100,
		TlsPaddingMin:           256,
		TlsPaddingMax:           1024,
		ParallelDnsQueries:      true,
		PreferredDnsServers:     []string{"https://sky.rethinkdns.com/dns-query", "https://dns.quad9.net/dns-query"},
	}

	s.profiles[RegionRussia] = &RegionalEvasionProfile{
		Region:                  RegionRussia,
		DnsFragmentationEnabled: false,
		DnsFragmentSize:         0,
		TcpMssClamp:             1300,
		TlsPaddingMin:           64,
		TlsPaddingMax:           256,
		ParallelDnsQueries:      true,
		PreferredDnsServers:     []string{"https://1.1.1.1/dns-query"},
	}

	s.profiles[RegionGlobal] = &RegionalEvasionProfile{
		Region:                  RegionGlobal,
		DnsFragmentationEnabled: false,
		DnsFragmentSize:         0,
		TcpMssClamp:             1460,
		TlsPaddingMin:           0,
		TlsPaddingMax:           0,
		ParallelDnsQueries:      false,
		PreferredDnsServers:     []string{"https://1.1.1.1/dns-query"},
	}

	return s
}

func (s *CensorshipProfileSynthesizer) GetProfile(region CensorshipRegion) *RegionalEvasionProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.profiles[region]; ok {
		return p
	}
	return s.profiles[RegionGlobal]
}
