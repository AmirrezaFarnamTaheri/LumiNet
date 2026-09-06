// Package xray provides data types for Xray proxy traffic statistics.
// Ported from 3ax-ui-main/xray/traffic.go (verbatim) and
// 3ax-ui-main/xray/client_traffic.go.
package xray

// Traffic represents network traffic statistics for an Xray inbound or outbound tag.
// Ported verbatim from 3ax-ui/xray/traffic.go.
type Traffic struct {
	IsInbound  bool
	IsOutbound bool
	Tag        string
	Up         int64
	Down       int64
}

// ClientTraffic represents per-user (email-keyed) traffic statistics.
// Ported from 3ax-ui/xray/client_traffic.go.
type ClientTraffic struct {
	// Email is the unique client identifier used by Xray for traffic accounting.
	Email string `json:"email" form:"email"`
	// Up is the total bytes uploaded by this client.
	Up int64 `json:"up"`
	// Down is the total bytes downloaded by this client.
	Down int64 `json:"down"`
	// Total is the configured traffic limit (0 = unlimited).
	Total int64 `json:"total"`
	// ExpiryTime is a Unix millisecond timestamp after which the client is expired (0 = never).
	ExpiryTime int64 `json:"expiryTime"`
	// Enable reports whether this client is active.
	Enable bool `json:"enable"`
	// Reset is the periodic traffic-reset interval identifier.
	Reset int `json:"reset"`
}
