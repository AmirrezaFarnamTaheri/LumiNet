package warp

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"time"
)

type WarpAccountProfile struct {
	AccountID   string    `json:"account_id"`
	AccessToken string    `json:"access_token"`
	PrivateKey  string    `json:"private_key"`
	PublicKey   string    `json:"public_key"`
	AllocatedV4 net.IP    `json:"allocated_v4"`
	AllocatedV6 net.IP    `json:"allocated_v6"`
	AccountType string    `json:"account_type"`
	Created     time.Time `json:"created"`
}

type WarpAccountClient struct {
	endpoint string
}

func NewWarpAccountClient(apiEndpoint string) *WarpAccountClient {
	if apiEndpoint == "" {
		apiEndpoint = "https://api.cloudflareclient.com/v0a1922"
	}
	return &WarpAccountClient{
		endpoint: apiEndpoint,
	}
}

func (c *WarpAccountClient) GenerateMockProfile(accountType string) (*WarpAccountProfile, error) {
	priv := make([]byte, 32)
	pub := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return nil, err
	}
	if _, err := rand.Read(pub); err != nil {
		return nil, err
	}

	return &WarpAccountProfile{
		AccountID:   fmt.Sprintf("mock-warp-%d", time.Now().UnixNano()),
		AccessToken: "mock-warp-token",
		PrivateKey:  base64.StdEncoding.EncodeToString(priv),
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		AllocatedV4: net.ParseIP("172.16.0.2"),
		AllocatedV6: net.ParseIP("2606:4700:110:8735:6a4a:2a41:b6b7:b3d3"),
		AccountType: accountType,
		Created:     time.Now(),
	}, nil
}

func (c *WarpAccountClient) SynthesizeWireguardConf(profile *WarpAccountProfile, endpoint string, peerPubKey string) (string, error) {
	if profile == nil {
		return "", errors.New("nil warp account profile")
	}
	if endpoint == "" {
		endpoint = "engage.cloudflareclient.com:2408"
	}
	if peerPubKey == "" {
		peerPubKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
	}

	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32, %s/128
DNS = 1.1.1.1, 2606:4700:4700::1111

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, profile.PrivateKey, profile.AllocatedV4.String(), profile.AllocatedV6.String(), peerPubKey, endpoint), nil
}
