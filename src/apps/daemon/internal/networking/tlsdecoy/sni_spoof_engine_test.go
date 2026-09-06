package tlsdecoy

import (
	"encoding/binary"
	"net"
	"testing"
)

func Test4TupleKey(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.10")
	dstIP := net.ParseIP("104.16.1.1")
	key := NewConn4TupleKey(srcIP, 54321, dstIP, 443)

	if key.SrcPort != 54321 || key.DstPort != 443 {
		t.Fatalf("unexpected ports: %d -> %d", key.SrcPort, key.DstPort)
	}

	rev := key.Reverse()
	if rev.SrcPort != 443 || rev.DstPort != 54321 {
		t.Fatalf("unexpected reverse ports: %d -> %d", rev.SrcPort, rev.DstPort)
	}
	if rev.SrcIP != key.DstIP || rev.DstIP != key.SrcIP {
		t.Fatalf("reverse IPs do not match")
	}
}

func TestBuildFakeClientHello(t *testing.T) {
	var random, sessionID, keyShare [32]byte
	for i := 0; i < 32; i++ {
		random[i] = byte(i)
		sessionID[i] = byte(i + 32)
		keyShare[i] = byte(i + 64)
	}

	fakeSNI := "speedtest.net"
	ch, err := BuildFakeClientHello(fakeSNI, random, sessionID, keyShare)
	if err != nil {
		t.Fatalf("BuildFakeClientHello failed: %v", err)
	}

	// Canonical length must strictly equal 517 bytes
	if len(ch) != 517 {
		t.Fatalf("expected 517 bytes, got %d", len(ch))
	}

	// Test with 6-char SNI "mci.ir"
	ch2, err := BuildFakeClientHello("mci.ir", random, sessionID, keyShare)
	if err != nil {
		t.Fatalf("BuildFakeClientHello failed with mci.ir: %v", err)
	}
	if len(ch2) != 517 {
		t.Fatalf("expected 517 bytes for mci.ir, got %d", len(ch2))
	}
}

func TestBuildFakePayloadPacket(t *testing.T) {
	// Synthesize 40-byte IPv4 + TCP packet
	raw := make([]byte, 40)
	raw[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(raw[2:4], 40)
	binary.BigEndian.PutUint16(raw[4:6], 0x1234) // ID
	raw[8] = 64                                 // TTL
	raw[9] = 6                                  // TCP
	copy(raw[12:16], net.ParseIP("192.168.1.1").To4())
	copy(raw[16:20], net.ParseIP("104.16.1.1").To4())
	computeIPv4Checksum(raw[:20])

	binary.BigEndian.PutUint16(raw[20:22], 54321) // SrcPort
	binary.BigEndian.PutUint16(raw[22:24], 443)   // DstPort
	binary.BigEndian.PutUint32(raw[24:28], 1000)  // Seq
	binary.BigEndian.PutUint32(raw[28:32], 2000)  // Ack
	raw[32] = 0x50                                // DataOffset: 5 (20B)
	raw[33] = tcpFlagACK
	computeTCPChecksum(raw, 20)

	fakePayload := []byte("DECOY_PAYLOAD_TEST")
	fakeSeq := uint32(99000)
	fakePkt, err := BuildFakePayloadPacket(raw, fakePayload, fakeSeq)
	if err != nil {
		t.Fatalf("BuildFakePayloadPacket failed: %v", err)
	}

	if len(fakePkt) != 40+len(fakePayload) {
		t.Fatalf("expected length %d, got %d", 40+len(fakePayload), len(fakePkt))
	}

	// Verify IPv4 ID increment
	newID := binary.BigEndian.Uint16(fakePkt[4:6])
	if newID != 0x1235 {
		t.Fatalf("expected incremented ID 0x1235, got 0x%04X", newID)
	}

	// Verify PSH flag
	if (fakePkt[33] & tcpFlagPSH) == 0 {
		t.Fatalf("expected PSH flag set")
	}

	// Verify Sequence number
	seq := binary.BigEndian.Uint32(fakePkt[24:28])
	if seq != fakeSeq {
		t.Fatalf("expected seq %d, got %d", fakeSeq, seq)
	}
}

func TestIsCloudflareIP(t *testing.T) {
	// Cloudflare ranges
	if !IsCloudflareIP(net.ParseIP("104.16.1.1")) {
		t.Errorf("expected 104.16.1.1 to be Cloudflare")
	}
	if !IsCloudflareIP(net.ParseIP("172.64.0.50")) {
		t.Errorf("expected 172.64.0.50 to be Cloudflare")
	}
	if !IsCloudflareIP(net.ParseIP("188.114.96.10")) {
		t.Errorf("expected 188.114.96.10 to be Cloudflare")
	}

	// Non-Cloudflare
	if IsCloudflareIP(net.ParseIP("8.8.8.8")) {
		t.Errorf("expected 8.8.8.8 to not be Cloudflare")
	}
	if IsCloudflareIP(net.ParseIP("142.250.190.46")) {
		t.Errorf("expected Google IP to not be Cloudflare")
	}
	if IsCloudflareIP(net.ParseIP("192.168.1.1")) {
		t.Errorf("expected private IP to not be Cloudflare")
	}
}

func TestCleanDomain(t *testing.T) {
	if CleanDomain("https://cloudflare.com/path?query=1") != "cloudflare.com" {
		t.Errorf("unexpected cleaned domain for URL")
	}
	if CleanDomain("  HTTP://SpeedTest.net:443/ ") != "speedtest.net" {
		t.Errorf("unexpected cleaned domain for HTTP with port")
	}
	if CleanDomain("# this is a comment") != "" {
		t.Errorf("comment line should return empty string")
	}
	if CleanDomain("invalidhost") != "" {
		t.Errorf("domain without dot should be rejected")
	}
}

func TestKillSwitchCoordinator(t *testing.T) {
	coord := NewKillSwitchCoordinator(true)
	coord.ArmedSNI = true
	coord.ArmedCore = true

	// Heartbeat while both running -> no block
	block, unblock := coord.OnHeartbeat(true, true)
	if block || unblock || coord.IsBlocked {
		t.Fatalf("heartbeat should not trigger block when both running")
	}

	// Core crashes -> trigger block
	block, _ = coord.OnHeartbeat(true, false)
	if !block || !coord.IsBlocked {
		t.Fatalf("heartbeat should trigger block when core dropped")
	}

	// Subsequent heartbeat while down -> no double trigger
	block, _ = coord.OnHeartbeat(true, false)
	if block {
		t.Fatalf("should not double trigger block")
	}

	// Disarm both -> restore unblock
	coord.Disarm(true, false)
	unblock = coord.Disarm(false, true)
	if !unblock || coord.IsBlocked {
		t.Fatalf("disarming all should restore unblock")
	}

	// Verify Netsh args
	blockArgs := NetshBlockRuleArgs("TestRule")
	if len(blockArgs) < 5 || blockArgs[4] != "name=TestRule" {
		t.Fatalf("unexpected block args: %v", blockArgs)
	}

	unblockArgs := NetshUnblockRuleArgs("TestRule")
	if len(unblockArgs) < 5 || unblockArgs[4] != "name=TestRule" {
		t.Fatalf("unexpected unblock args: %v", unblockArgs)
	}
}
