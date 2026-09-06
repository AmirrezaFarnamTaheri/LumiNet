package scanner

// scanner_dns_service.go — lightweight userspace DNS hijacking/proxy service.
// Ported from MaybeEdgeScanner DnsVpnService.java.
// Orchestrates direct TUN packet capture, filtering UDP port 53 DNS queries,
// forwarding outside the TUN interface, and composing response UDP packets with IP checksums.

import (
	"context"
	"io"
	"net"
	"time"
)

// DnsVpnConfig defines properties for the userspace DNS hijack adapter.
type DnsVpnConfig struct {
	TUNAddress string // e.g. "10.111.222.1"
	Dns1       string // primary upstream resolver IP (e.g. "1.1.1.1")
	Dns2       string // secondary upstream resolver IP
}

// StartUserspaceDnsVpn runs the packet reader loop on a virtual TUN interface,
// intercepting and resolving DNS requests.
func StartUserspaceDnsVpn(ctx context.Context, tun io.ReadWriteCloser, config DnsVpnConfig) error {
	upstreams := []string{config.Dns1}
	if config.Dns2 != "" {
		upstreams = append(upstreams, config.Dns2)
	}

	buf := make([]byte, 32767)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := tun.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			continue
		}
		if n < 20 {
			continue
		}

		// IPv4 checks
		ipVersion := (buf[0] >> 4) & 0x0F
		if ipVersion != 4 {
			continue
		}
		ipHeaderLen := int(buf[0]&0x0F) * 4
		if ipHeaderLen < 20 || n < ipHeaderLen+8 {
			continue
		}
		protocol := buf[9]
		if protocol != 17 { // UDP
			continue
		}

		// Port checks
		dstPort := (int(buf[ipHeaderLen+2]) << 8) | int(buf[ipHeaderLen+3])
		if dstPort != 53 { // DNS query
			continue
		}

		srcPort := (int(buf[ipHeaderLen]) << 8) | int(buf[ipHeaderLen+1])
		payloadOffset := ipHeaderLen + 8
		payloadLen := n - payloadOffset
		if payloadLen <= 0 {
			continue
		}

		// Extract DNS query payload and source IP
		dnsQuery := make([]byte, payloadLen)
		copy(dnsQuery, buf[payloadOffset:n])
		srcIP := make([]byte, 4)
		copy(srcIP, buf[12:16])

		// Dispatch DNS forward in background coroutine
		go func(srcIP []byte, srcPort int, query []byte) {
			response := forwardDNSQuery(query, upstreams)
			if len(response) == 0 {
				return
			}

			// Parse upstream source IP to send back
			upstreamIP := net.ParseIP(config.Dns1).To4()
			if upstreamIP == nil {
				upstreamIP = net.IPv4(10, 111, 222, 1).To4()
			}

			respPacket := BuildUdpPacket(upstreamIP, srcIP, 53, srcPort, response)
			_, _ = tun.Write(respPacket)
		}(srcIP, srcPort, dnsQuery)
	}
}

func forwardDNSQuery(query []byte, upstreams []string) []byte {
	for _, upstream := range upstreams {
		addr := net.JoinHostPort(upstream, "53")
		conn, err := net.Dial("udp", addr)
		if err != nil {
			continue
		}
		_, err = conn.Write(query)
		if err != nil {
			conn.Close()
			continue
		}
		respBuf := make([]byte, 4096)
		// 3-second read timeout
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := conn.Read(respBuf)
		conn.Close()
		if err == nil && n > 0 {
			return respBuf[:n]
		}
	}
	return nil
}

// BuildUdpPacket constructs a raw IPv4 UDP packet.
// Source: DnsVpnService.java buildUdpPacket()
func BuildUdpPacket(srcIP, dstIP net.IP, srcPort, dstPort int, payload []byte) []byte {
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	buf := make([]byte, totalLen)

	buf[0] = 0x45 // Version 4, Header Length 20 bytes
	buf[1] = 0
	buf[2] = byte((totalLen >> 8) & 0xFF)
	buf[3] = byte(totalLen & 0xFF)
	buf[4] = 0
	buf[5] = 0
	buf[6] = 0x40 // Flags: Don't Fragment
	buf[7] = 0
	buf[8] = 64 // TTL
	buf[9] = 17 // UDP protocol
	buf[10] = 0 // Checksum placeholder
	buf[11] = 0
	copy(buf[12:16], srcIP.To4())
	copy(buf[16:20], dstIP.To4())

	// IP checksum calculation
	csum := CalculateRFC1071Checksum(buf[0:20])
	buf[10] = byte((csum >> 8) & 0xFF)
	buf[11] = byte(csum & 0xFF)

	// UDP Header
	udpOffset := 20
	buf[udpOffset] = byte((srcPort >> 8) & 0xFF)
	buf[udpOffset+1] = byte(srcPort & 0xFF)
	buf[udpOffset+2] = byte((dstPort >> 8) & 0xFF)
	buf[udpOffset+3] = byte(dstPort & 0xFF)
	buf[udpOffset+4] = byte((udpLen >> 8) & 0xFF)
	buf[udpOffset+5] = byte(udpLen & 0xFF)
	buf[udpOffset+6] = 0 // UDP checksum is optional in IPv4 (can be 0)
	buf[udpOffset+7] = 0
	copy(buf[28:], payload)

	return buf
}

// CalculateRFC1071Checksum computes the 16-bit one's complement Internet checksum.
// Source: DnsVpnService.java calculateChecksum()
func CalculateRFC1071Checksum(data []byte) uint16 {
	var sum uint32
	n := len(data)
	for i := 0; i < n-1; i += 2 {
		sum += (uint32(data[i]) << 8) | uint32(data[i+1])
	}
	if n%2 != 0 {
		sum += uint32(data[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum & 0xFFFF)
}
