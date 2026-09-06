package proxy

import (
	"context"
	"fmt"
	"net"
	"time"
)

// KCPConn wraps a UDP socket simulating KCP framing.
type KCPConn struct {
	net.Conn
	fecEnabled bool
}

type KCPDialer struct {
	Timeout   time.Duration
	FecData   int
	FecParity int
}

func NewKCPDialer(timeout time.Duration) *KCPDialer {
	return &KCPDialer{
		Timeout:   timeout,
		FecData:   10,
		FecParity: 3,
	}
}

func (d *KCPDialer) DialKCP(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: d.Timeout}
	conn, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to dial UDP for KCP: %w", err)
	}
	return &KCPConn{Conn: conn, fecEnabled: true}, nil
}
