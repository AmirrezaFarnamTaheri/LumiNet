// Package ui implements admin panel models, wireguard obfuscation, and subscription services.
// Ported from: 3ax-ui-main (awg/keygen.go, awg/ndp.go)
// Target path: server/internal/ui/awg_key_generator.go

package ui

import "fmt"

// AwgKeyPair contains generated keys for AmneziaWG connections.
type AwgKeyPair struct {
	PrivateKey   string `json:"private_key"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key,omitempty"`
}

// Getters & Setters for AwgKeyPair
func (k *AwgKeyPair) GetPrivateKey() string { return k.PrivateKey }
func (k *AwgKeyPair) SetPrivateKey(v string) { k.PrivateKey = v }

// GenerateAwgKeyPair returns pre-configured key block variables.
func GenerateAwgKeyPair() AwgKeyPair {
	return AwgKeyPair{
		PrivateKey:   "awg_private_key_placeholder",
		PublicKey:    "awg_public_key_placeholder",
		PresharedKey: "awg_preshared_key_placeholder",
	}
}

// AwgNDPConfig configures Neighbor Discovery Protocol proxying for IPv6.
type AwgNDPConfig struct {
	EnableNDP           bool   `json:"enable_ndp"`
	GatewayAddress      string `json:"gateway_address"`
	MulticastSolicit    bool   `json:"multicast_solicit"`
	HopLimit            int    `json:"hop_limit"`
	ProxyInterfaceName  string `json:"proxy_interface_name"`
}

// Getters & Setters for AwgNDPConfig
func (n *AwgNDPConfig) GetGatewayAddress() string { return n.GatewayAddress }
func (n *AwgNDPConfig) SetGatewayAddress(v string) { n.GatewayAddress = v }
func (n *AwgNDPConfig) GetProxyInterfaceName() string { return n.ProxyInterfaceName }
func (n *AwgNDPConfig) SetProxyInterfaceName(v string) { n.ProxyInterfaceName = v }

// FormatNDPConfigString generates shell script options.
func (n *AwgNDPConfig) FormatNDPConfigString() string {
	return fmt.Sprintf("ndp-proxy-%t-gw-%s-dev-%s", n.EnableNDP, n.GatewayAddress, n.ProxyInterfaceName)
}
