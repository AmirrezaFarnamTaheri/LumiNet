package proxy

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
)

type WgPeerRecord struct {
	PublicKey   string `json:"public_key"`
	PresharedKey string `json:"preshared_key,omitempty"`
	AllocatedV4 net.IP `json:"allocated_v4"`
	AllocatedV6 net.IP `json:"allocated_v6"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
}

type WireguardIpam struct {
	mu           sync.Mutex
	v4Network    *net.IPNet
	v6Network    *net.IPNet
	allocatedV4  map[string]bool
	allocatedV6  map[string]bool
	peers        map[string]*WgPeerRecord
	nextHostIdV4 uint32
	nextHostIdV6 uint64
}

func NewWireguardIpam(v4Cidr, v6Cidr string) (*WireguardIpam, error) {
	_, net4, err := net.ParseCIDR(v4Cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid v4 cidr: %w", err)
	}
	_, net6, err := net.ParseCIDR(v6Cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid v6 cidr: %w", err)
	}

	return &WireguardIpam{
		v4Network:    net4,
		v6Network:    net6,
		allocatedV4:  make(map[string]bool),
		allocatedV6:  make(map[string]bool),
		peers:        make(map[string]*WgPeerRecord),
		nextHostIdV4: 2, // 1 is gateway
		nextHostIdV6: 2,
	}, nil
}

func (ipam *WireguardIpam) AllocatePeer(pubKey, name string) (*WgPeerRecord, error) {
	ipam.mu.Lock()
	defer ipam.mu.Unlock()

	if _, exists := ipam.peers[pubKey]; exists {
		return nil, errors.New("peer with public key already exists")
	}

	v4Base := ipam.v4Network.IP.To4()
	if v4Base == nil {
		return nil, errors.New("invalid v4 network")
	}
	v4 := make(net.IP, 4)
	copy(v4, v4Base)
	v4[3] = byte(ipam.nextHostIdV4)
	ipam.nextHostIdV4++

	v6Base := ipam.v6Network.IP.To16()
	if v6Base == nil {
		return nil, errors.New("invalid v6 network")
	}
	v6 := make(net.IP, 16)
	copy(v6, v6Base)
	v6[15] = byte(ipam.nextHostIdV6)
	ipam.nextHostIdV6++

	psk := make([]byte, 32)
	_, _ = rand.Read(psk)

	rec := &WgPeerRecord{
		PublicKey:    pubKey,
		PresharedKey: base64.StdEncoding.EncodeToString(psk),
		AllocatedV4:  v4,
		AllocatedV6:  v6,
		Name:         name,
		Enabled:      true,
	}

	ipam.peers[pubKey] = rec
	ipam.allocatedV4[v4.String()] = true
	ipam.allocatedV6[v6.String()] = true

	return rec, nil
}

func (ipam *WireguardIpam) FormatClientConf(rec *WgPeerRecord, clientPrivKey, srvEndpoint, srvPubKey, dns string) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32, %s/128
DNS = %s

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, clientPrivKey, rec.AllocatedV4.String(), rec.AllocatedV6.String(), dns, srvPubKey, rec.PresharedKey, srvEndpoint)
}
