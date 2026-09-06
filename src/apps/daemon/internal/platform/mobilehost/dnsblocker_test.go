package mobilehost

import (
	"encoding/binary"
	"testing"
)

// buildDNSQuery crafts a minimal IPv4+UDP DNS query for name with qtype.
func buildDNSQuery(name string, qtype uint16) []byte {
	labels := splitName(name)
	qnameWire := 0
	for _, label := range labels {
		qnameWire += 1 + len(label)
	}
	qnameWire++ // root zero byte
	dnsLen := 12 + qnameWire + 4
	ipHdr := 20
	udpHdr := 8
	total := ipHdr + udpHdr + dnsLen

	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(total))
	pkt[8] = 64
	pkt[9] = protoUDP
	// src 10.0.0.2 dst 8.8.8.8
	copy(pkt[12:16], []byte{10, 0, 0, 2})
	copy(pkt[16:20], []byte{8, 8, 8, 8})
	udp := ipHdr
	binary.BigEndian.PutUint16(pkt[udp:], 5353)
	binary.BigEndian.PutUint16(pkt[udp+2:], dnsPort)
	binary.BigEndian.PutUint16(pkt[udp+4:], uint16(dnsLen))

	dns := ipHdr + udpHdr
	binary.BigEndian.PutUint16(pkt[dns:], 0x1234) // id
	binary.BigEndian.PutUint16(pkt[dns+4:], 1)    // QDCOUNT=1
	offset := dns + 12
	for _, label := range labels {
		pkt[offset] = byte(len(label))
		offset++
		copy(pkt[offset:], label)
		offset += len(label)
	}
	pkt[offset] = 0
	offset++
	binary.BigEndian.PutUint16(pkt[offset:], qtype)
	return pkt
}

func splitName(name string) []string {
	out := []string{}
	current := ""
	for _, c := range name {
		if c == '.' {
			out = append(out, current)
			current = ""
			continue
		}
		current += string(c)
	}
	if current != "" {
		out = append(out, current)
	}
	return out
}

func TestBlockerBlocksExactAndSubdomains(t *testing.T) {
	b := NewDNSBlocker([]string{"ads.example.com"})
	if b.Len() != 1 {
		t.Fatalf("len = %d", b.Len())
	}
	query := buildDNSQuery("ads.example.com", qtypeA)
	reply := b.ProcessPacket(query)
	if reply == nil {
		t.Fatal("exact blocked domain not intercepted")
	}
	sub := b.ProcessPacket(buildDNSQuery("track.ads.example.com", qtypeA))
	if sub == nil {
		t.Fatal("subdomain of blocked domain not intercepted")
	}
	clean := b.ProcessPacket(buildDNSQuery("example.com", qtypeA))
	if clean != nil {
		t.Fatal("parent of blocked entry must NOT match")
	}
}

func TestBlockerIgnoresResponsesAndNonDNS(t *testing.T) {
	b := NewDNSBlocker([]string{"ads.example.com"})
	query := buildDNSQuery("ads.example.com", qtypeA)
	// flip QR bit to make it a response
	dnsOff := 28
	query[dnsOff+2] |= 0x80
	if got := b.ProcessPacket(query); got != nil {
		t.Fatal("responses must pass through")
	}
	if got := b.ProcessPacket([]byte{0x45, 0, 0, 20}); len(got) != 0 && got != nil {
		t.Log("truncated packet handled")
	}
	tcp := buildDNSQuery("ads.example.com", qtypeA)
	tcp[9] = 6 // TCP protocol
	if got := b.ProcessPacket(tcp); got != nil {
		t.Fatal("non-UDP must pass through")
	}
}

func TestBlockerNullRouteAnswerIsLoopback(t *testing.T) {
	b := NewDNSBlocker([]string{"tracker.example.net"})
	aQuery := buildDNSQuery("tracker.example.net", qtypeA)
	reply := b.ProcessPacket(aQuery)
	if reply == nil {
		t.Fatal("no reply synthesized")
	}
	dnsOff := 20 + 8
	// ANCOUNT should be 1 and rdata should end in 127.0.0.1 near the tail.
	ancount := binary.BigEndian.Uint16(reply[dnsOff+6:])
	if ancount != 1 {
		t.Fatalf("ancount = %d", ancount)
	}
	if !containsLoopbackV4(reply) {
		t.Fatal("loopback rdata missing")
	}
}

func TestBlockerAAAAAnswersLoopbackV6(t *testing.T) {
	b := NewDNSBlocker([]string{"blocked.example"})
	aaaa := buildDNSQuery("blocked.example", qtypeAAAA)
	reply := b.ProcessPacket(aaaa)
	if reply == nil {
		t.Fatal("AAAA query not answered")
	}
	if !containsLoopbackV6(reply) {
		t.Fatal("AAAA rdata should be ::1")
	}
}

func containsLoopbackV4(pkt []byte) bool {
	for i := 0; i+4 <= len(pkt); i++ {
		if pkt[i] == 127 && pkt[i+1] == 0 && pkt[i+2] == 0 && pkt[i+3] == 1 {
			return true
		}
	}
	return false
}

func containsLoopbackV6(pkt []byte) bool {
	loopback := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	for i := 0; i+16 <= len(pkt); i++ {
		match := true
		for j := 0; j < 16; j++ {
			if pkt[i+j] != loopback[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
