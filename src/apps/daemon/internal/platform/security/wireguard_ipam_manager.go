package security

import (
	"errors"
	"fmt"
	"strings"
)

type WireguardPeer struct {
	PublicKey  string   `json:"public_key"`
	AssignedIP string   `json:"assigned_ip"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint"`
	Enabled    bool     `json:"enabled"`
}

type WireguardIpamManager struct {
	subnetPrefix string
	nextSuffix   uint8
	serverIP     string
	listenPort   uint16
	peers        map[string]*WireguardPeer
	ipToKey      map[string]string
}

func NewWireguardIpamManager(subnetPrefix string, listenPort uint16) (*WireguardIpamManager, error) {
	parts := strings.Split(subnetPrefix, ".")
	if len(parts) != 3 {
		return nil, errors.New("subnet prefix must have 3 octets, e.g. 10.14.0")
	}

	return &WireguardIpamManager{
		subnetPrefix: subnetPrefix,
		nextSuffix:   2,
		serverIP:     fmt.Sprintf("%s.1", subnetPrefix),
		listenPort:   listenPort,
		peers:        make(map[string]*WireguardPeer),
		ipToKey:      make(map[string]string),
	}, nil
}

func (w *WireguardIpamManager) AllocatePeer(publicKey string) (*WireguardPeer, error) {
	if peer, ok := w.peers[publicKey]; ok {
		return peer, nil
	}

	if w.nextSuffix >= 254 {
		return nil, errors.New("subnet exhausted")
	}

	assignedIP := fmt.Sprintf("%s.%d", w.subnetPrefix, w.nextSuffix)
	w.nextSuffix++

	peer := &WireguardPeer{
		PublicKey:  publicKey,
		AssignedIP: assignedIP,
		AllowedIPs: []string{fmt.Sprintf("%s/32", assignedIP)},
		Enabled:    true,
	}

	w.peers[publicKey] = peer
	w.ipToKey[assignedIP] = publicKey
	return peer, nil
}

func (w *WireguardIpamManager) ReleasePeer(publicKey string) error {
	peer, ok := w.peers[publicKey]
	if !ok {
		return errors.New("peer not found")
	}

	delete(w.ipToKey, peer.AssignedIP)
	delete(w.peers, publicKey)
	return nil
}

func (w *WireguardIpamManager) GenerateServerConfig(serverPrivateKey string) string {
	var lines []string
	lines = append(lines, "[Interface]")
	lines = append(lines, fmt.Sprintf("Address = %s/24", w.serverIP))
	lines = append(lines, fmt.Sprintf("ListenPort = %d", w.listenPort))
	lines = append(lines, fmt.Sprintf("PrivateKey = %s", serverPrivateKey))
	lines = append(lines, "")

	for _, peer := range w.peers {
		if peer.Enabled {
			lines = append(lines, "[Peer]")
			lines = append(lines, fmt.Sprintf("PublicKey = %s", peer.PublicKey))
			lines = append(lines, fmt.Sprintf("AllowedIPs = %s", strings.Join(peer.AllowedIPs, ", ")))
			if peer.Endpoint != "" {
				lines = append(lines, fmt.Sprintf("Endpoint = %s", peer.Endpoint))
			}
			lines = append(lines, "")
		}
	}

	return strings.Join(lines, "\n")
}

func (w *WireguardIpamManager) GenerateClientConfig(peerPublicKey, peerPrivateKey, serverPublicKey, serverEndpoint string) (string, error) {
	peer, ok := w.peers[peerPublicKey]
	if !ok {
		return "", errors.New("peer not registered")
	}

	var lines []string
	lines = append(lines, "[Interface]")
	lines = append(lines, fmt.Sprintf("Address = %s/32", peer.AssignedIP))
	lines = append(lines, fmt.Sprintf("PrivateKey = %s", peerPrivateKey))
	lines = append(lines, "DNS = 1.1.1.1")
	lines = append(lines, "")

	lines = append(lines, "[Peer]")
	lines = append(lines, fmt.Sprintf("PublicKey = %s", serverPublicKey))
	lines = append(lines, fmt.Sprintf("Endpoint = %s", serverEndpoint))
	lines = append(lines, "AllowedIPs = 0.0.0.0/0, ::/0")
	lines = append(lines, "PersistentKeepalive = 25")

	return strings.Join(lines, "\n"), nil
}
