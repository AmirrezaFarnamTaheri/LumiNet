package nat

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestIPv4Defragmenter(t *testing.T) {
	d := NewIPv4Defragmenter()

	src := netip.MustParseAddr("192.168.1.100")
	dst := netip.MustParseAddr("8.8.8.8")

	// Create original packet
	payload := []byte("HELLO THIS IS A VERY LONG MESSAGE THAT WILL BE FRAGMENTED FOR TESTING PURPOSES")
	fullPacket := make([]byte, 20+len(payload))

	ip := IPv4Packet(fullPacket)
	ip[0] = 0x45 // Version 4, IHL 5
	ip.SetTotalLength(uint16(len(fullPacket)))
	ip.SetIdentification(0x1234)
	ip.SetFlags(0)
	ip.SetFragmentOffset(0)
	ip.SetTimeToLive(64)
	ip.SetProtocol(ProtocolTCP)
	ip.SetSourceIP(src)
	ip.SetDestinationIP(dst)

	copy(fullPacket[20:], payload)
	ip.ResetChecksum()

	// Fragment 1: First 32 bytes of payload
	frag1Payload := payload[:32]
	frag1 := make([]byte, 20+len(frag1Payload))
	copy(frag1, fullPacket[:20])
	copy(frag1[20:], frag1Payload)
	ip1 := IPv4Packet(frag1)
	ip1.SetTotalLength(uint16(len(frag1)))
	ip1.SetFlags(FlagMoreFragment)
	ip1.SetFragmentOffset(0)
	ip1.ResetChecksum()

	// Fragment 2: Remaining payload
	frag2Payload := payload[32:]
	frag2 := make([]byte, 20+len(frag2Payload))
	copy(frag2, fullPacket[:20])
	copy(frag2[20:], frag2Payload)
	ip2 := IPv4Packet(frag2)
	ip2.SetTotalLength(uint16(len(frag2)))
	ip2.SetFlags(0) // Last fragment
	ip2.SetFragmentOffset(32)
	ip2.ResetChecksum()

	// Submit fragment 1
	res, err := d.DefragIPv4(frag1)
	if err != ErrIncompleteFragment {
		t.Errorf("expected ErrIncompleteFragment, got %v", err)
	}
	if res != nil {
		t.Error("expected nil result for incomplete fragment")
	}

	// Submit fragment 2
	res, err = d.DefragIPv4(frag2)
	if err != nil {
		t.Errorf("unexpected error on complete fragment: %v", err)
	}
	if res == nil {
		t.Fatal("expected reassembled packet, got nil")
	}

	// Verify reassembled packet
	resIP := IPv4Packet(res)
	if resIP.TotalLen() != uint16(len(fullPacket)) {
		t.Errorf("expected total len %d, got %d", len(fullPacket), resIP.TotalLen())
	}
	if resIP.Flags() != 0 {
		t.Errorf("expected flags 0, got %v", resIP.Flags())
	}
	if resIP.FragmentOffset() != 0 {
		t.Errorf("expected offset 0, got %v", resIP.FragmentOffset())
	}
	if !bytes.Equal(resIP.Payload(), payload) {
		t.Errorf("payload mismatch.\nExpected: %s\nGot: %s", payload, resIP.Payload())
	}
}

func makeIPv4Fragment(t *testing.T, id uint16, offset int, more bool, payload []byte) []byte {
	t.Helper()
	packet := make([]byte, IPv4HeaderSize+len(payload))
	ip := IPv4Packet(packet)
	ip[0] = 0x45
	ip.SetTotalLength(uint16(len(packet)))
	ip.SetIdentification(id)
	if more {
		ip.SetFlags(FlagMoreFragment)
	}
	ip.SetFragmentOffset(uint32(offset))
	ip.SetTimeToLive(64)
	ip.SetProtocol(ProtocolUDP)
	ip.SetSourceIP(netip.MustParseAddr("192.0.2.10"))
	ip.SetDestinationIP(netip.MustParseAddr("198.51.100.20"))
	copy(packet[IPv4HeaderSize:], payload)
	ip.ResetChecksum()
	return packet
}

func TestIPv4DefragmenterOutOfOrderUsesFirstFragmentHeader(t *testing.T) {
	d := NewIPv4Defragmenter()
	last := makeIPv4Fragment(t, 77, 8, false, []byte("ijkl"))
	first := makeIPv4Fragment(t, 77, 0, true, []byte("abcdefgh"))

	if got, err := d.DefragIPv4(last); err != ErrIncompleteFragment || got != nil {
		t.Fatalf("last-first result=%v err=%v", got, err)
	}
	got, err := d.DefragIPv4(first)
	if err != nil {
		t.Fatal(err)
	}
	if payload := IPv4Packet(got).Payload(); !bytes.Equal(payload, []byte("abcdefghijkl")) {
		t.Fatalf("payload=%q", payload)
	}
}

func TestIPv4DefragmenterAcceptsIdenticalDuplicateOverlap(t *testing.T) {
	d := NewIPv4Defragmenter()
	first := makeIPv4Fragment(t, 88, 0, true, []byte("abcdefgh"))
	duplicate := makeIPv4Fragment(t, 88, 0, true, []byte("abcdefgh"))
	last := makeIPv4Fragment(t, 88, 8, false, []byte("ijkl"))

	if _, err := d.DefragIPv4(first); err != ErrIncompleteFragment {
		t.Fatal(err)
	}
	if _, err := d.DefragIPv4(duplicate); err != ErrIncompleteFragment {
		t.Fatalf("duplicate identical fragment rejected: %v", err)
	}
	got, err := d.DefragIPv4(last)
	if err != nil {
		t.Fatal(err)
	}
	if payload := IPv4Packet(got).Payload(); !bytes.Equal(payload, []byte("abcdefghijkl")) {
		t.Fatalf("payload=%q", payload)
	}
}

func TestIPv4DefragmenterRejectsConflictingOverlapAndDropsFlow(t *testing.T) {
	d := NewIPv4Defragmenter()
	first := makeIPv4Fragment(t, 99, 0, true, []byte("abcdefgh"))
	conflict := makeIPv4Fragment(t, 99, 0, true, []byte("abcdWXYZ"))
	if _, err := d.DefragIPv4(first); err != ErrIncompleteFragment {
		t.Fatal(err)
	}
	if _, err := d.DefragIPv4(conflict); !errors.Is(err, ErrConflictingFragment) {
		t.Fatalf("conflicting overlap error=%v", err)
	}
	if len(d.flows) != 0 {
		t.Fatalf("conflicting flow retained: %d", len(d.flows))
	}
}

func TestIPv4DefragmenterRejectsInvalidNonFinalAlignment(t *testing.T) {
	d := NewIPv4Defragmenter()
	fragment := makeIPv4Fragment(t, 111, 0, true, []byte("seven!!")) // 7 bytes
	if _, err := d.DefragIPv4(fragment); !errors.Is(err, ErrInvalidFragment) {
		t.Fatalf("misaligned non-final fragment error=%v", err)
	}
}

func TestIPv4DefragmenterEvictsOldestAtFlowBound(t *testing.T) {
	d := NewIPv4Defragmenter()
	d.maxFlows = 2
	first := makeIPv4Fragment(t, 1, 0, true, []byte("abcdefgh"))
	second := makeIPv4Fragment(t, 2, 0, true, []byte("abcdefgh"))
	third := makeIPv4Fragment(t, 3, 0, true, []byte("abcdefgh"))
	if _, err := d.DefragIPv4(first); err != ErrIncompleteFragment {
		t.Fatal(err)
	}
	for _, flow := range d.flows {
		flow.updatedAt = flow.updatedAt.Add(-time.Hour)
	}
	if _, err := d.DefragIPv4(second); err != ErrIncompleteFragment {
		t.Fatal(err)
	}
	if _, err := d.DefragIPv4(third); err != ErrIncompleteFragment {
		t.Fatal(err)
	}
	if len(d.flows) != 2 {
		t.Fatalf("flow count=%d, want 2", len(d.flows))
	}
	for flow := range d.flows {
		if flow.ID == 1 {
			t.Fatal("oldest flow was not evicted")
		}
	}
}

func TestIPv4DefragmenterUsesDatagramPayloadLimitNotCurrentFragmentIHL(t *testing.T) {
	d := NewIPv4Defragmenter()
	// Non-zero fragments may carry a different set of copied IPv4 options. A
	// long current-fragment header must not shrink the datagram payload limit;
	// the offset-zero fragment's header is authoritative at final assembly.
	payload := []byte("abcdefgh")
	packet := make([]byte, 60+len(payload))
	ip := IPv4Packet(packet)
	ip[0] = 0x4f // Version 4, IHL 15 (60 bytes).
	ip.SetTotalLength(uint16(len(packet)))
	ip.SetIdentification(124)
	ip.SetFlags(FlagMoreFragment)
	ip.SetFragmentOffset(65472)
	ip.SetTimeToLive(64)
	ip.SetProtocol(ProtocolUDP)
	ip.SetSourceIP(netip.MustParseAddr("192.0.2.10"))
	ip.SetDestinationIP(netip.MustParseAddr("198.51.100.20"))
	copy(packet[60:], payload)
	ip.ResetChecksum()

	if got, err := d.DefragIPv4(packet); !errors.Is(err, ErrIncompleteFragment) || got != nil {
		t.Fatalf("high-offset long-IHL fragment result=%v err=%v", got, err)
	}
}

func TestIPv4PacketValidRejectsImpossibleLengths(t *testing.T) {
	packet := makeIPv4Fragment(t, 123, 0, false, []byte("payload"))
	ip := IPv4Packet(packet)
	if !ip.Valid() {
		t.Fatal("well-formed packet rejected")
	}

	badHeader := append([]byte(nil), packet...)
	IPv4Packet(badHeader)[0] = 0x44 // IHL 16 bytes
	if IPv4Packet(badHeader).Valid() {
		t.Fatal("short IHL accepted")
	}

	badTotal := append([]byte(nil), packet...)
	IPv4Packet(badTotal).SetTotalLength(10)
	if IPv4Packet(badTotal).Valid() {
		t.Fatal("total length smaller than header accepted")
	}

	truncatedTotal := append([]byte(nil), packet...)
	IPv4Packet(truncatedTotal).SetTotalLength(uint16(len(truncatedTotal) + 1))
	if IPv4Packet(truncatedTotal).Valid() {
		t.Fatal("declared total length beyond available bytes accepted")
	}

	truncatedHeader := append([]byte(nil), packet...)
	truncatedHeader[0] = 0x4f // IHL 60 while only the short packet is available.
	if IPv4Packet(truncatedHeader).Valid() {
		t.Fatal("declared header length beyond available bytes accepted")
	}
}
