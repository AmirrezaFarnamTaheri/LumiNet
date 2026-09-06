package proxy

import (
	"encoding/binary"
)

// CalculateChecksum computes the standard internet checksum (RFC 1071) of the data.
func CalculateChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)

	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	if length%2 != 0 {
		sum += uint32(data[length-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(^sum)
}

// CalculateTCPChecksum computes the TCP checksum including the pseudo-header for IPv4/IPv6.
func CalculateTCPChecksum(tcpSegment []byte, srcIP, dstIP []byte) uint16 {
	var pseudoHeader []byte
	if len(srcIP) == 4 { // IPv4
		pseudoHeader = make([]byte, 12)
		copy(pseudoHeader[0:4], srcIP)
		copy(pseudoHeader[4:8], dstIP)
		pseudoHeader[9] = 6 // TCP protocol
		binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpSegment)))
	} else if len(srcIP) == 16 { // IPv6
		pseudoHeader = make([]byte, 40)
		copy(pseudoHeader[0:16], srcIP)
		copy(pseudoHeader[16:32], dstIP)
		binary.BigEndian.PutUint32(pseudoHeader[32:36], uint32(len(tcpSegment)))
		pseudoHeader[39] = 6
	} else {
		return 0
	}

	combined := append(pseudoHeader, tcpSegment...)
	return CalculateChecksum(combined)
}
