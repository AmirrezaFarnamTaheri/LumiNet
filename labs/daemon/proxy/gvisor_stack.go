package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// UserspaceStack manages user-mode IP packet handling.
type UserspaceStack struct {
	MTU      uint32
	LocalIP  string
	Attached bool
}

func NewUserspaceStack(localIP string, mtu uint32) *UserspaceStack {
	return &UserspaceStack{
		MTU:      mtu,
		LocalIP:  localIP,
		Attached: true,
	}
}

// DeliverIPPacket parses the IP packet and handles protocols.
func (s *UserspaceStack) DeliverIPPacket(packet []byte) error {
	if len(packet) == 0 {
		return fmt.Errorf("empty packet payload")
	}
	if len(packet) < 20 {
		return errors.New("packet too short for IP header")
	}

	version := packet[0] >> 4
	if version != 4 {
		return fmt.Errorf("only IPv4 supported in mock userspace stack, got version %d", version)
	}

	headerLen := int(packet[0]&0x0f) * 4
	if len(packet) < headerLen {
		return errors.New("packet length shorter than header length")
	}

	protocol := packet[9]
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	switch protocol {
	case 1: // ICMP
		if headerLen+8 <= len(packet) {
			icmpType := packet[headerLen]
			if icmpType == 8 { // Echo request
				// Log mock ping receipt
				fmt.Printf("Mock userspace stack: received ICMP ping request from %s to %s\n", srcIP, dstIP)
			}
		}
	case 6: // TCP
		if headerLen+20 <= len(packet) {
			srcPort := binary.BigEndian.Uint16(packet[headerLen : headerLen+2])
			dstPort := binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4])
			fmt.Printf("Mock userspace stack: received TCP flow %s:%d -> %s:%d\n", srcIP, srcPort, dstIP, dstPort)
		}
	case 17: // UDP
		if headerLen+8 <= len(packet) {
			srcPort := binary.BigEndian.Uint16(packet[headerLen : headerLen+2])
			dstPort := binary.BigEndian.Uint16(packet[headerLen+2 : headerLen+4])
			fmt.Printf("Mock userspace stack: received UDP flow %s:%d -> %s:%d\n", srcIP, srcPort, dstIP, dstPort)
		}
	}

	return nil
}
