package diagnostics

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestFlowHashSymmetry(t *testing.T) {
	ip1 := net.ParseIP("192.168.1.100")
	port1 := uint16(54321)
	ip2 := net.ParseIP("1.1.1.1")
	port2 := uint16(443)

	hForward := ComputeFlowHash(ip1, port1, ip2, port2)
	hReverse := ComputeFlowHash(ip2, port2, ip1, port1)

	if hForward != hReverse {
		t.Fatalf("flow hash not symmetrical: forward=%d, reverse=%d", hForward, hReverse)
	}

	// IPv6 symmetry test
	ip6A := net.ParseIP("2001:db8::1")
	ip6B := net.ParseIP("2606:4700::6810:1")
	h6Forward := ComputeFlowHash(ip6A, 8080, ip6B, 9090)
	h6Reverse := ComputeFlowHash(ip6B, 9090, ip6A, 8080)

	if h6Forward != h6Reverse {
		t.Fatalf("IPv6 flow hash not symmetrical: forward=%d, reverse=%d", h6Forward, h6Reverse)
	}
}

func TestFlowLatencyTrackerRTT(t *testing.T) {
	tracker := NewFlowLatencyTracker()

	clientIP := net.ParseIP("10.0.0.5")
	clientPort := uint16(33445)
	serverIP := net.ParseIP("10.0.0.1")
	serverPort := uint16(80)

	tSyn := uint64(1_000_000_000) // 1.000s
	tracker.OnSYN(clientIP, clientPort, serverIP, serverPort, tSyn)

	if tracker.PendingCount() != 1 {
		t.Fatalf("expected 1 pending handshake, got %d", tracker.PendingCount())
	}

	tSynAck := uint64(1_020_000_000) // 1.020s (+20ms)
	rtt, ok := tracker.OnSYNACK(serverIP, serverPort, clientIP, clientPort, tSynAck)
	if !ok {
		t.Fatalf("expected successful RTT calculation")
	}

	if rtt != 20*time.Millisecond {
		t.Fatalf("expected 20ms RTT, got %v", rtt)
	}

	if tracker.PendingCount() != 0 {
		t.Fatalf("expected 0 pending handshakes after ACK, got %d", tracker.PendingCount())
	}

	stats := tracker.GetStats()
	if stats.SampleCount != 1 {
		t.Fatalf("expected 1 sample, got %d", stats.SampleCount)
	}
	if stats.AverageRTT() != 20*time.Millisecond {
		t.Fatalf("expected average 20ms, got %v", stats.AverageRTT())
	}
	if stats.MinRTT != 20*time.Millisecond || stats.MaxRTT != 20*time.Millisecond {
		t.Fatalf("unexpected min/max RTT: %v / %v", stats.MinRTT, stats.MaxRTT)
	}
}

func TestUnmarshalTCPPacketAndProcess(t *testing.T) {
	tracker := NewFlowLatencyTracker()

	raw := make([]byte, 48)
	// IPv4-mapped 1.2.3.4
	raw[10] = 0xff
	raw[11] = 0xff
	raw[12] = 1
	raw[13] = 2
	raw[14] = 3
	raw[15] = 4

	// IPv4-mapped 5.6.7.8
	raw[26] = 0xff
	raw[27] = 0xff
	raw[28] = 5
	raw[29] = 6
	raw[30] = 7
	raw[31] = 8

	binary.BigEndian.PutUint16(raw[32:34], 12345) // srcPort
	binary.BigEndian.PutUint16(raw[34:36], 80)    // dstPort

	raw[36] = 1 // SYN
	raw[37] = 0 // ACK
	binary.LittleEndian.PutUint64(raw[40:48], 5_000_000_000)

	pktSYN, err := UnmarshalTCPPacket(raw)
	if err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}
	if !pktSYN.SYN || pktSYN.ACK {
		t.Fatalf("unexpected flags on SYN packet")
	}

	rtt, ok := tracker.ProcessPacket(pktSYN)
	if ok || rtt != 0 {
		t.Fatalf("SYN should not produce RTT")
	}
	if tracker.PendingCount() != 1 {
		t.Fatalf("expected 1 pending handshake, got %d", tracker.PendingCount())
	}

	// Reverse packet (SYN-ACK)
	rawAck := make([]byte, 48)
	copy(rawAck[0:16], raw[16:32])
	copy(rawAck[16:32], raw[0:16])
	copy(rawAck[32:34], raw[34:36])
	copy(rawAck[34:36], raw[32:34])
	rawAck[36] = 1 // SYN
	rawAck[37] = 1 // ACK
	binary.LittleEndian.PutUint64(rawAck[40:48], 5_045_000_000) // +45ms

	pktACK, err := UnmarshalTCPPacket(rawAck)
	if err != nil {
		t.Fatalf("unexpected unmarshal error on ACK: %v", err)
	}

	rtt, ok = tracker.ProcessPacket(pktACK)
	if !ok {
		t.Fatalf("expected successful RTT calculation on SYN-ACK")
	}
	if rtt != 45*time.Millisecond {
		t.Fatalf("expected 45ms RTT, got %v", rtt)
	}
}

func TestFlowLatencyPruneStale(t *testing.T) {
	tracker := NewFlowLatencyTracker()

	ipA := net.ParseIP("10.1.1.1")
	ipB := net.ParseIP("10.2.2.2")
	tracker.OnSYN(ipA, 1000, ipB, 2000, 100)

	pruned := tracker.PruneStale(1000, 500)
	if pruned != 1 {
		t.Fatalf("expected 1 pruned entry, got %d", pruned)
	}
	if tracker.PendingCount() != 0 {
		t.Fatalf("expected 0 pending entries, got %d", tracker.PendingCount())
	}
}
