package transport

import (
	"fmt"
	"net/http"
	"net/url"
)

// RelayTunnelClientConfig specifies remote HTTP relay credentials and endpoints.
type RelayTunnelClientConfig struct {
	RelayEndpoint string `json:"relay_endpoint"`
	AuthToken     string `json:"auth_token"`
	TargetHost    string `json:"target_host"`
	TargetPort    int    `json:"target_port"`
}

// RelayTunnelClient handles the setup and tunneling through an HTTP relay.
type RelayTunnelClient struct {
	cfg RelayTunnelClientConfig
}

// NewRelayTunnelClient creates an HTTP relay tunnel client instance.
func NewRelayTunnelClient(cfg RelayTunnelClientConfig) (*RelayTunnelClient, error) {
	if cfg.RelayEndpoint == "" {
		return nil, fmt.Errorf("relay endpoint cannot be empty")
	}
	if cfg.TargetHost == "" || cfg.TargetPort <= 0 {
		return nil, fmt.Errorf("invalid target destination host/port")
	}
	return &RelayTunnelClient{cfg: cfg}, nil
}

// BuildConnectRequest constructs an HTTP CONNECT request headers.
func (c *RelayTunnelClient) BuildConnectRequest() (*http.Request, error) {
	target := fmt.Sprintf("%s:%d", c.cfg.TargetHost, c.cfg.TargetPort)
	u, err := url.Parse(c.cfg.RelayEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid relay url: %w", err)
	}

	req, err := http.NewRequest(http.MethodConnect, u.String(), nil)
	if err != nil {
		return nil, err
	}

	req.Host = target
	req.Header.Set("Proxy-Connection", "Keep-Alive")
	if c.cfg.AuthToken != "" {
		req.Header.Set("Proxy-Authorization", fmt.Sprintf("Bearer %s", c.cfg.AuthToken))
	}

	return req, nil
}
