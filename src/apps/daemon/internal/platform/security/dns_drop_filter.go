package security

import "encoding/binary"

type DnsDropFilter struct {
	DroppedCount int
	PassedCount  int
}

func NewDnsDropFilter() *DnsDropFilter {
	return &DnsDropFilter{}
}

func (f *DnsDropFilter) InspectPacket(ipID uint16, fragOff uint16, srcPort uint16, dnsPayload []byte) (bool, string) {
	if srcPort != 53 {
		f.PassedCount++
		return true, "pass"
	}
	if ipID == 0 {
		f.DroppedCount++
		return false, "dropped: ip_id == 0"
	}
	if fragOff == 0x0040 {
		f.DroppedCount++
		return false, "dropped: frag_off == 0x0040"
	}
	if len(dnsPayload) < 12 {
		f.PassedCount++
		return true, "pass"
	}

	answerRRs := binary.BigEndian.Uint16(dnsPayload[6:8])
	authRRs := binary.BigEndian.Uint16(dnsPayload[8:10])
	aaBit := (dnsPayload[2] & 0b00000100) != 0

	if answerRRs == 1 && authRRs == 0 && aaBit {
		f.DroppedCount++
		return false, "dropped: authoritative bit set on recursive response"
	}

	f.PassedCount++
	return true, "pass"
}
