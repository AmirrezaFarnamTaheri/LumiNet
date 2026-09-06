package security

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

var (
	ErrDnsPacketTooShort = errors.New("dns packet too short")
	ErrMalformedOptRR    = errors.New("malformed opt record")
)

// EdnsScrubber scrubs EDNS Client Subnet (ECS) options from DNS packets
type EdnsScrubber struct {
	MaskIPv4Bits    int
	MaskIPv6Bits    int
	StripCompletely bool
}

func NewEdnsScrubber(maskIPv4, maskIPv6 int, stripCompletely bool) *EdnsScrubber {
	return &EdnsScrubber{
		MaskIPv4Bits:    maskIPv4,
		MaskIPv6Bits:    maskIPv6,
		StripCompletely: stripCompletely,
	}
}

// MaskIPv4 masks trailing host bits for an IPv4 address string
func (s *EdnsScrubber) MaskIPv4(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr)).To4()
	if ip == nil {
		return ipStr
	}
	mask := net.CIDRMask(s.MaskIPv4Bits, 32)
	masked := ip.Mask(mask)
	return masked.String()
}

// ScrubPacket strips option code 8 (ECS) from DNS OPT pseudo-RRs
func (s *EdnsScrubber) ScrubPacket(packet []byte) ([]byte, error) {
	if len(packet) < 12 {
		return nil, ErrDnsPacketTooShort
	}

	arcount := binary.BigEndian.Uint16(packet[10:12])
	if arcount == 0 {
		return packet, nil
	}

	qdcount := binary.BigEndian.Uint16(packet[4:6])
	ancount := binary.BigEndian.Uint16(packet[6:8])
	nscount := binary.BigEndian.Uint16(packet[8:10])

	offset := 12
	// Skip QD
	for i := 0; i < int(qdcount); i++ {
		next, err := skipDnsName(packet, offset)
		if err != nil {
			return nil, err
		}
		offset = next + 4
		if offset > len(packet) {
			return nil, ErrDnsPacketTooShort
		}
	}

	// Skip AN + NS
	for i := 0; i < int(ancount+nscount); i++ {
		next, err := skipDnsRR(packet, offset)
		if err != nil {
			return nil, err
		}
		offset = next
	}

	// Process Additional
	var newAdditional []byte
	var newArcount uint16

	for i := 0; i < int(arcount); i++ {
		if offset >= len(packet) {
			break
		}
		rrStart := offset
		nameEnd, err := skipDnsName(packet, offset)
		if err != nil || nameEnd+10 > len(packet) {
			return nil, ErrMalformedOptRR
		}

		rtype := binary.BigEndian.Uint16(packet[nameEnd : nameEnd+2])
		rdlen := int(binary.BigEndian.Uint16(packet[nameEnd+8 : nameEnd+10]))
		rdataStart := nameEnd + 10
		rdataEnd := rdataStart + rdlen

		if rdataEnd > len(packet) {
			return nil, ErrMalformedOptRR
		}

		if rtype == 41 { // OPT RR
			if !s.StripCompletely {
				var cleanedRdata []byte
				roff := rdataStart
				for roff+4 <= rdataEnd {
					optCode := binary.BigEndian.Uint16(packet[roff : roff+2])
					optLen := int(binary.BigEndian.Uint16(packet[roff+2 : roff+4]))
					optDataEnd := roff + 4 + optLen
					if optDataEnd > rdataEnd {
						break
					}
					if optCode != 8 { // Not ECS
						cleanedRdata = append(cleanedRdata, packet[roff:optDataEnd]...)
					}
					roff = optDataEnd
				}

				newAdditional = append(newAdditional, packet[rrStart:rdataStart-2]...)
				lenBuf := make([]byte, 2)
				binary.BigEndian.PutUint16(lenBuf, uint16(len(cleanedRdata)))
				newAdditional = append(newAdditional, lenBuf...)
				newAdditional = append(newAdditional, cleanedRdata...)
				newArcount++
			}
		} else {
			newAdditional = append(newAdditional, packet[rrStart:rdataEnd]...)
			newArcount++
		}
		offset = rdataEnd
	}

	reconstructed := make([]byte, 12)
	copy(reconstructed, packet[:12])
	binary.BigEndian.PutUint16(reconstructed[10:12], newArcount)

	initialOffset, err := findAdditionalOffset(packet, int(qdcount), int(ancount), int(nscount))
	if err != nil {
		return nil, err
	}

	reconstructed = append(reconstructed, packet[12:initialOffset]...)
	reconstructed = append(reconstructed, newAdditional...)
	return reconstructed, nil
}

func findAdditionalOffset(packet []byte, qd, an, ns int) (int, error) {
	offset := 12
	for i := 0; i < qd; i++ {
		next, err := skipDnsName(packet, offset)
		if err != nil {
			return 0, err
		}
		offset = next + 4
	}
	for i := 0; i < an+ns; i++ {
		next, err := skipDnsRR(packet, offset)
		if err != nil {
			return 0, err
		}
		offset = next
	}
	return offset, nil
}

func skipDnsName(packet []byte, offset int) (int, error) {
	for offset < len(packet) {
		l := int(packet[offset])
		if l == 0 {
			return offset + 1, nil
		}
		if (l & 0xC0) == 0xC0 {
			return offset + 2, nil
		}
		offset += l + 1
	}
	return 0, ErrDnsPacketTooShort
}

func skipDnsRR(packet []byte, offset int) (int, error) {
	nameEnd, err := skipDnsName(packet, offset)
	if err != nil || nameEnd+10 > len(packet) {
		return 0, ErrDnsPacketTooShort
	}
	rdlen := int(binary.BigEndian.Uint16(packet[nameEnd+8 : nameEnd+10]))
	end := nameEnd + 10 + rdlen
	if end > len(packet) {
		return 0, ErrDnsPacketTooShort
	}
	return end, nil
}
