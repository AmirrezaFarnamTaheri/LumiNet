// Package netutil includes byte-rate policy definitions.
// (formerly package traffic)
package netutil

import "fmt"

const DefaultUnlimitedRateBytesPerSecond int64 = 100 * 1024 * 1024

// RatePolicy configures a byte-rate limiter independently of packet or envelope shaping.
type RatePolicy struct {
	BytesPerSecond int64
	BurstBytes     int64
}

// Normalize validates a bounded rate policy and supplies a burst when omitted.
func (p RatePolicy) Normalize() (RatePolicy, error) {
	if p.BytesPerSecond <= 0 {
		return RatePolicy{}, fmt.Errorf("traffic rate must be positive")
	}
	if p.BurstBytes <= 0 {
		p.BurstBytes = p.BytesPerSecond
	}
	return p, nil
}

// DefaultUnlimitedPolicy returns the historical high-throughput default used by qos.
func DefaultUnlimitedPolicy() RatePolicy {
	return RatePolicy{BytesPerSecond: DefaultUnlimitedRateBytesPerSecond}
}
