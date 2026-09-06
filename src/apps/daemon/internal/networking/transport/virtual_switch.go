package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type NodeAddress [5]byte

func (n NodeAddress) String() string {
	return fmt.Sprintf("%02x%02x%02x%02x%02x", n[0], n[1], n[2], n[3], n[4])
}

type SwitchPacketFrame struct {
	Source      NodeAddress
	Destination NodeAddress
	EtherType   uint16
	Payload     []byte
}

func (f *SwitchPacketFrame) Encode() []byte {
	out := make([]byte, 10+2+len(f.Payload))
	copy(out[0:5], f.Source[:])
	copy(out[5:10], f.Destination[:])
	binary.BigEndian.PutUint16(out[10:12], f.EtherType)
	copy(out[12:], f.Payload)
	return out
}

func DecodeSwitchPacketFrame(b []byte) (*SwitchPacketFrame, error) {
	if len(b) < 12 {
		return nil, errors.New("frame too short")
	}
	var src, dst NodeAddress
	copy(src[:], b[0:5])
	copy(dst[:], b[5:10])
	eth := binary.BigEndian.Uint16(b[10:12])
	payload := make([]byte, len(b)-12)
	copy(payload, b[12:])
	return &SwitchPacketFrame{
		Source:      src,
		Destination: dst,
		EtherType:   eth,
		Payload:     payload,
	}, nil
}

type SwitchPort struct {
	PhysicalAddr *net.UDPAddr
	LastSeen     time.Time
}

type VirtualEthernetSwitch struct {
	mu            sync.RWMutex
	fdb           map[NodeAddress]*SwitchPort
	agingDuration time.Duration
}

func NewVirtualEthernetSwitch(aging time.Duration) *VirtualEthernetSwitch {
	return &VirtualEthernetSwitch{
		fdb:           make(map[NodeAddress]*SwitchPort),
		agingDuration: aging,
	}
}

func (s *VirtualEthernetSwitch) Learn(node NodeAddress, addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fdb[node] = &SwitchPort{
		PhysicalAddr: addr,
		LastSeen:     time.Now(),
	}
}

func (s *VirtualEthernetSwitch) Lookup(node NodeAddress) (*net.UDPAddr, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	port, exists := s.fdb[node]
	if !exists {
		return nil, false
	}
	if time.Since(port.LastSeen) > s.agingDuration {
		return nil, false
	}
	return port.PhysicalAddr, true
}
