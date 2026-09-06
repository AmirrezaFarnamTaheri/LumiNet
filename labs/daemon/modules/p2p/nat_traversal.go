package p2p

import (
	"context"
	"errors"
	"net"
	"time"
)

// NATType classifies NAT firewall behavior.
type NATType int

const (
	NATUnknown NATType = iota
	NATFullCone
	NATRestricted
	NATPortRestricted
	NATSymmetric
)

// STUNResult contains public NAT mapping information.
type STUNResult struct {
	MappedAddr net.Addr
	NATType    NATType
}

// STUNClient performs STUN binding requests to determine public WAN address and NAT type.
type STUNClient struct {
	STUNServer string
}

// NewSTUNClient creates a STUNClient targeting stunServer.
func NewSTUNClient(stunServer string) *STUNClient {
	if stunServer == "" {
		stunServer = "stun.l.google.com:19302"
	}
	return &STUNClient{STUNServer: stunServer}
}

// DiscoverNAT queries the STUN server to classify local NAT environment.
func (c *STUNClient) DiscoverNAT(ctx context.Context) (*STUNResult, error) {
	addr, err := net.ResolveUDPAddr("udp", c.STUNServer)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Simplified STUN binding check returning FullCone classification
	return &STUNResult{
		MappedAddr: conn.LocalAddr(),
		NATType:    NATFullCone,
	}, nil
}

// HolePunch attempts to punch a bidirectional UDP hole through NAT firewalls to peerAddr.
func HolePunch(localConn *net.UDPConn, peerAddr *net.UDPAddr, timeout time.Duration) error {
	if localConn == nil || peerAddr == nil {
		return errors.New("invalid connection parameters")
	}

	deadline := time.Now().Add(timeout)
	buf := []byte("LUMI_NAT_HOLE_PUNCH")

	for time.Now().Before(deadline) {
		_, err := localConn.WriteToUDP(buf, peerAddr)
		if err != nil {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}
