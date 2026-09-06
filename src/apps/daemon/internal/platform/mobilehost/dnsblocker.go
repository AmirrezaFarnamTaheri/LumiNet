// Package mobilehost hosts the Android TUN boundary.
//
// dnsblocker.go absorbs the FPTN DomainBlocker semantics (GPL-3 upstream,
// behaviour re-expressed): intercept outbound UDP/53 packets inside the TUN,
// match the queried name (and parent domains) against a blocklist, and answer
// in-band so the stub resolver never falls back to hard-to-block transports.
//
// Null-route answers point A queries at 127.0.0.1 and AAAA at ::1: the app
// sees a "successful" resolution, its TCP connect to loopback fails instantly,
// and crucially it does NOT retry over DoH — which NXDOMAIN alone can trigger.
package mobilehost

import (
	"encoding/binary"
	"strings"
)

const (
	dnsPort      = 53
	protoUDP     = 17
	minIPv4Header = 20
	ipv6Header    = 40
	udpHeaderLen  = 8
	dnsHeaderLen  = 12

	qtypeA    = 0x0001
	qtypeAAAA = 0x001C
)

// DNSBlocker holds the compiled blocklist.
type DNSBlocker struct {
	blocked map[string]struct{}
}

// NewDNSBlocker compiles a blocklist: entries are lowercased; subdomains of an
// entry match too (parent-domain walk).
func NewDNSBlocker(domains []string) *DNSBlocker {
	blocker := &DNSBlocker{blocked: make(map[string]struct{}, len(domains))}
	for _, domain := range domains {
		d := strings.ToLower(strings.TrimSpace(domain))
		d = strings.TrimPrefix(d, "domain:")
		if strings.Contains(d, ".") {
			blocker.blocked[strings.Trim(d, ".")] = struct{}{}
		}
	}
	return blocker
}

// Len reports the compiled blocklist size.
func (b *DNSBlocker) Len() int { return len(b.blocked) }

// ProcessPacket inspects one IP packet. It returns a synthesized reply when the
// packet is an outgoing DNS query for a blocked name, otherwise nil.
func (b *DNSBlocker) ProcessPacket(packet []byte) []byte {
	if b == nil || len(b.blocked) == 0 || len(packet) < minIPv4Header {
		return nil
	}
	version := int(packet[0] >> 4)
	var ipHeaderLen int
	switch version {
	case 4:
		if packet[9] != protoUDP {
			return nil
		}
		ipHeaderLen = int(packet[0]&0x0F) * 4
	case 6:
		if len(packet) < ipv6Header || packet[6] != protoUDP {
			return nil
		}
		ipHeaderLen = ipv6Header
	default:
		return nil
	}
	if ipHeaderLen < minIPv4Header && version == 4 {
		return nil
	}
	udpOff := ipHeaderLen
	if len(packet) < udpOff+udpHeaderLen+dnsHeaderLen {
		return nil
	}
	dstPort := binary.BigEndian.Uint16(packet[udpOff+2:])
	if dstPort != dnsPort {
		return nil // only intercept outgoing queries
	}
	dnsOff := udpOff + udpHeaderLen
	flags := packet[dnsOff+2]
	if flags&0x80 != 0 {
		return nil // QR=1: response, not query
	}
	name, questionEnd, ok := parseDNSQuestion(packet, dnsOff)
	if !ok || !b.matches(name) {
		return nil
	}
	return buildNullRouteReply(packet, version, ipHeaderLen, udpOff, dnsOff, questionEnd)
}

// matches walks parent domains: "sub.ads.example.com" matches "ads.example.com".
func (b *DNSBlocker) matches(domain string) bool {
	for {
		if _, hit := b.blocked[domain]; hit {
			return true
		}
		dot := strings.IndexByte(domain, '.')
		if dot < 0 || dot == len(domain)-1 {
			return false
		}
		domain = domain[dot+1:]
	}
}

// parseDNSQuestion returns the lower-cased QNAME and the offset just past
// QTYPE+QCLASS, honouring RFC 1035 compression pointers.
func parseDNSQuestion(packet []byte, dnsOff int) (string, int, bool) {
	if len(packet) < dnsOff+dnsHeaderLen {
		return "", 0, false
	}
	qdcount := binary.BigEndian.Uint16(packet[dnsOff+4:])
	if qdcount == 0 {
		return "", 0, false
	}
	var sb strings.Builder
	ptr := dnsOff + dnsHeaderLen
	jumped := false
	nextAfterName := ptr
	for hops := 0; hops < 128 && ptr < len(packet); hops++ {
		length := int(packet[ptr])
		if length == 0 {
			if !jumped {
				nextAfterName = ptr + 1
			}
			break
		}
		if length&0xC0 == 0xC0 {
			if ptr+2 > len(packet) {
				break
			}
			if !jumped {
				nextAfterName = ptr + 2
			}
			jumped = true
			ptr = dnsOff + (int(length&0x3F)<<8 | int(packet[ptr+1]))
			continue
		}
		ptr++
		if ptr+length > len(packet) {
			break
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		for j := 0; j < length; j++ {
			sb.WriteByte(packet[ptr+j])
		}
		ptr += length
	}
	name := strings.ToLower(sb.String())
	if name == "" {
		return "", 0, false
	}
	return name, nextAfterName + 4, true
}

// buildNullRouteReply swaps the UDP payload for a response answering the
// question with loopback (or NXDOMAIN for non-address types), fixes up DNS
// counts/flags, swaps ports, and recomputes checksums.
func buildNullRouteReply(packet []byte, version, ipHeaderLen, udpOff, dnsOff, questionEnd int) []byte {
	// questionEnd sits just past QTYPE+QCLASS; both must be present.
	if questionEnd > len(packet) {
		return buildNXDOMAINReply(packet, version, udpOff, dnsOff)
	}
	qtype := binary.BigEndian.Uint16(packet[questionEnd-4:])
	var rdata []byte
	answerType := qtype
	switch qtype {
	case qtypeAAAA:
		rdata = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1} // ::1
	case qtypeA:
		rdata = []byte{127, 0, 0, 1}
	default:
		return buildNXDOMAINReply(packet, version, udpOff, dnsOff)
	}

	// Answer RR: NAME = compression pointer to QNAME (0xC00C), TYPE, CLASS IN,
	// short TTL, RDLENGTH, RDATA.
	rr := make([]byte, 2, 2+8+len(rdata))
	rr[0] = 0xC0
	rr[1] = byte(dnsHeaderLen)
	rr = append(rr, byte(answerType>>8), byte(answerType), 0, 0, 0, 10)
	rr = append(rr, byte(len(rdata)>>8), byte(len(rdata)))
	rr = append(rr, rdata...)

	question := packet[dnsOff:questionEnd]

	reply := make([]byte, 0, udpOff+udpHeaderLen+len(question)+len(rr))
	reply = append(reply, packet[:udpOff]...)       // IP header
	reply = append(reply, packet[udpOff:dnsOff]...) // UDP header
	reply = append(reply, question...)              // echoed question
	reply = append(reply, rr...)                    // answer RR

	finalizeUDPReply(reply, version, udpOff, dnsOff, 1)
	return reply
}


func buildNXDOMAINReply(packet []byte, version, udpOff, dnsOff int) []byte {
	// Echo the full question section; RCODE=3 (NXDOMAIN), ANCOUNT=0.
	question := packet[dnsOff:]

	reply := make([]byte, 0, udpOff+udpHeaderLen+len(question))
	reply = append(reply, packet[udpOff:dnsOff]...) // UDP header
	reply = append(reply, question...)              // echoed question

	binary.BigEndian.PutUint16(reply[udpOff+4:], uint16(len(question)))
	flags := binary.BigEndian.Uint16(reply[dnsOff+2:]) | 0x8000 | 0x0003 // QR=1 | RCODE=NXDOMAIN
	binary.BigEndian.PutUint16(reply[dnsOff+2:], flags)
	return finalizeUDPReply(reply, version, udpOff, dnsOff, 0)
}

// finalizeUDPReply mirrors source/dest ports, zeroes and recomputes UDP and
// IPv4 header checksums, and patches the IPv4 total-length field.
func finalizeUDPReply(reply []byte, version, udpOff, dnsOff int, answers uint16) []byte {
	udpLen := uint16(len(reply) - udpOff)
	// swap ports
	reply[udpOff], reply[udpOff+2] = reply[udpOff+2], reply[udpOff]
	reply[udpOff+1], reply[udpOff+3] = reply[udpOff+3], reply[udpOff+1]
	// DNS flags: QR=1
	reply[dnsOff+2] |= 0x80
	// ANCOUNT / ARCOUNT
	if dnsOff+12 <= len(reply) {
		binary.BigEndian.PutUint16(reply[dnsOff+6:], answers)
		binary.BigEndian.PutUint16(reply[dnsOff+10:], 0)
	}
	binary.BigEndian.PutUint16(reply[udpOff+4:], udpLen)
	reply[udpOff+6], reply[udpOff+7] = 0, 0

	if version == 4 {
		totalLen := uint16(len(reply))
		reply[2], reply[3] = byte(totalLen>>8), byte(totalLen)
		reply[10], reply[11] = 0, 0
		v4Header := int(reply[0]&0x0F) * 4
		sum := checksum(reply[:v4Header])
		reply[10], reply[11] = byte(sum>>8), byte(sum)
		sum = udpChecksum(reply, udpOff)
		reply[udpOff+6], reply[udpOff+7] = byte(sum>>8), byte(sum)
	}
	// IPv6: upper-layer checksum lives in the UDP pseudo-header field at
	// udpOff+6..7; recomputed against the IPv6 pseudo-header below.
	if version == 6 {
		reply[udpOff+6], reply[udpOff+7] = 0, 0
		sum := udpChecksumIPv6(reply, udpOff)
		reply[udpOff+6], reply[udpOff+7] = byte(sum>>8), byte(sum)
	}
	return reply
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

func udpChecksum(packet []byte, udpOff int) uint16 {
	var sum uint32
	// pseudo-header: src, dst, zero, proto, length
	for i := 12; i < 20; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	sum += uint32(packet[9]) + uint32(uint16(len(packet)-udpOff))
	udp := packet[udpOff:]
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(udp[i])<<8 | uint32(udp[i+1])
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

func udpChecksumIPv6(packet []byte, udpOff int) uint16 {
	var sum uint32
	for i := 8; i < 24; i += 2 { // src
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	for i := 24; i < 40; i += 2 { // dst
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	udpLen := uint16(len(packet) - udpOff)
	sum += uint32(packet[6]) + uint32(udpLen)
	udp := packet[udpOff:]
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(udp[i])<<8 | uint32(udp[i+1])
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}
