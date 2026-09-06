// Package proxy implements multi-protocol proxy servers and clients.
// Ported from: l7mp-master (listener.js, cluster.js, l7mp.js)
// Target path: server/internal/proxy/l7mp_listener.go

package proxy

import "fmt"

// L7MPCluster models load-balanced destinations.
// Maps to cluster.js.
type L7MPCluster struct {
	Name        string   `json:"name"`
	LoadBalance string   `json:"load_balance"` // round-robin, least-conn
	Endpoints   []string `json:"endpoints"`
	IntervalMs  int      `json:"interval_ms"`
}

// Getters & Setters for L7MPCluster
func (c *L7MPCluster) GetName() string  { return c.Name }
func (c *L7MPCluster) SetName(v string) { c.Name = v }

// L7MPListener models inbound proxy ports.
// Maps to listener.js.
type L7MPListener struct {
	Name          string `json:"name"`
	Port          int    `json:"port"`
	Protocol      string `json:"protocol"` // tcp, udp, ws
	TargetCluster string `json:"target_cluster"`
}

// Getters & Setters for L7MPListener
func (l *L7MPListener) GetName() string  { return l.Name }
func (l *L7MPListener) SetName(v string) { l.Name = v }

// L7MPConfig aggregates the active proxy topology config.
type L7MPConfig struct {
	Listeners []L7MPListener `json:"listeners"`
	Clusters  []L7MPCluster  `json:"clusters"`
}

// DefaultL7MPConfig returns a simple base topology.
func DefaultL7MPConfig() L7MPConfig {
	return L7MPConfig{
		Listeners: []L7MPListener{
			{Name: "http-in", Port: 8080, Protocol: "tcp", TargetCluster: "local-http"},
		},
		Clusters: []L7MPCluster{
			{Name: "local-http", LoadBalance: "round-robin", Endpoints: []string{"127.0.0.1:80"}, IntervalMs: 1000},
		},
	}
}

// AddListener to config.
func (c *L7MPConfig) AddListener(l L7MPListener) error {
	for _, existing := range c.Listeners {
		if existing.Port == l.Port {
			return fmt.Errorf("port %d already in use by listener %s", l.Port, existing.Name)
		}
	}
	c.Listeners = append(c.Listeners, l)
	return nil
}
