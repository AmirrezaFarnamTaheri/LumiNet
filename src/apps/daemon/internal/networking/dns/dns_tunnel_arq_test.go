package dns

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// ─── LowerBase32 Tests ────────────────────────────────────────────────────────

func TestEncodeLowerBase32_RoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("hello"),
		[]byte("LumiNet DNS tunnel test payload"),
		{0x00, 0xFF, 0x80, 0x7F, 0x42},
		[]byte("a"),
		[]byte(""),
	}
	for _, tc := range cases {
		encoded := EncodeLowerBase32(tc)
		decoded, err := DecodeLowerBase32String(encoded)
		if err != nil {
			t.Errorf("DecodeLowerBase32String(%q) error: %v", encoded, err)
			continue
		}
		if !bytes.Equal(decoded, tc) {
			t.Errorf("LowerBase32 roundtrip mismatch: input=%v, got=%v", tc, decoded)
		}
	}
}

func TestDecodeLowerBase32_CaseInsensitive(t *testing.T) {
	original := []byte("luminet dns codec")
	lowerEncoded := EncodeLowerBase32(original)
	upperEncoded := strings.ToUpper(lowerEncoded)

	decoded, err := DecodeLowerBase32([]byte(upperEncoded))
	if err != nil {
		t.Fatalf("DecodeLowerBase32 uppercase failed: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Errorf("Uppercase decode mismatch: got %q, want %q", decoded, original)
	}
}

func TestEncodedLenLowerBase32(t *testing.T) {
	for n := 0; n <= 20; n++ {
		l := EncodedLenLowerBase32(n)
		data := make([]byte, n)
		encoded := EncodeLowerBase32(data)
		if len(encoded) != l {
			t.Errorf("EncodedLenLowerBase32(%d) = %d, but actual encoded len = %d", n, l, len(encoded))
		}
	}
}

// ─── LowerBase36 Tests ────────────────────────────────────────────────────────

func TestEncodeLowerBase36_RoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("hello"),
		{0x00},
		{0xFF},
		[]byte("LumiNet 7-byte block"),
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},       // exactly 7 bytes = 1 full block → 11 chars
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, // 8 bytes = 1 full + 1 partial
		[]byte(""),
	}
	for _, tc := range cases {
		encoded := EncodeLowerBase36(tc)
		decoded, err := DecodeLowerBase36([]byte(encoded))
		if err != nil {
			t.Errorf("DecodeLowerBase36(%q) error: %v", encoded, err)
			continue
		}
		if !bytes.Equal(decoded, tc) {
			t.Errorf("LowerBase36 roundtrip mismatch: input=%v, encoded=%q, decoded=%v", tc, encoded, decoded)
		}
	}
}

func TestEncodeLowerBase36_FullBlock7to11(t *testing.T) {
	// 7 bytes must encode to exactly 11 characters
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x00}
	encoded := EncodeLowerBase36(data)
	if len(encoded) != 11 {
		t.Errorf("7 bytes should encode to 11 chars, got %d: %q", len(encoded), encoded)
	}
}

func TestDecodeLowerBase36_CaseInsensitive(t *testing.T) {
	original := []byte("DNS ARQ tunnel")
	lowerEncoded := EncodeLowerBase36(original)
	upperEncoded := strings.ToUpper(lowerEncoded)

	decoded, err := DecodeLowerBase36String(upperEncoded)
	if err != nil {
		t.Fatalf("DecodeLowerBase36String uppercase failed: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Errorf("LowerBase36 uppercase decode mismatch: got %q, want %q", decoded, original)
	}
}

func TestDecodeLowerBase36_InvalidChar(t *testing.T) {
	// Space is not in the Base36 alphabet
	_, err := DecodeLowerBase36([]byte("hello world"))
	if err == nil {
		t.Error("Expected error for invalid Base36 character, got nil")
	}
}

func TestEncodedLenLowerBase36(t *testing.T) {
	expected := map[int]int{
		0: 0, 1: 2, 2: 4, 3: 5, 4: 7, 5: 8, 6: 10, 7: 11,
		8:  13, // 7 + 1 partial → 11 + 2
		14: 22, // 2 full blocks
		15: 24, // 2 full + 1 partial (1 byte → 2 chars)
	}
	for n, wantLen := range expected {
		got := EncodedLenLowerBase36(n)
		if got != wantLen {
			t.Errorf("EncodedLenLowerBase36(%d) = %d, want %d", n, got, wantLen)
		}
	}
}

func TestEncodeLowerBase36_AlphabetChars(t *testing.T) {
	// Encoded string must only contain [0-9a-z]
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}
	encoded := EncodeLowerBase36(data)
	for _, ch := range encoded {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z')) {
			t.Errorf("Non-alphabet character in Base36 output: %c (%d)", ch, ch)
		}
	}
}

// ─── ARQ Tests ────────────────────────────────────────────────────────────────

func TestARQ_BasicEnqueueAndAck(t *testing.T) {
	cfg := DefaultARQConfig()
	arq := NewARQ(1, 0, cfg)
	defer arq.Close()

	payload := []byte("Hello DNS ARQ")
	sn, ok := arq.Enqueue(payload)
	if !ok {
		t.Fatal("Enqueue should succeed when window is empty")
	}

	if arq.PendingCount() != 1 {
		t.Errorf("Expected 1 pending, got %d", arq.PendingCount())
	}

	arq.AckReceived(sn)
	if arq.PendingCount() != 0 {
		t.Errorf("Expected 0 pending after ACK, got %d", arq.PendingCount())
	}
}

func TestARQ_ReceiveInOrder(t *testing.T) {
	cfg := DefaultARQConfig()
	arq := NewARQ(2, 0, cfg)
	defer arq.Close()

	for sn := uint16(0); sn < 3; sn++ {
		data := []byte{byte(sn), 0xAA}
		accepted := arq.ReceiveData(sn, data)
		if !accepted {
			t.Errorf("ReceiveData(%d) should be accepted", sn)
		}
	}

	for i := 0; i < 3; i++ {
		select {
		case pkt, ok := <-arq.ReadCh():
			if !ok {
				t.Fatal("rxChan closed unexpectedly")
			}
			if pkt.sn != uint16(i) {
				t.Errorf("Expected sn=%d, got %d", i, pkt.sn)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("Timeout waiting for packet %d", i)
		}
	}
}

func TestARQ_ReceiveOutOfOrder(t *testing.T) {
	cfg := DefaultARQConfig()
	arq := NewARQ(3, 0, cfg)
	defer arq.Close()

	// Receive sn=1 before sn=0 (out of order)
	arq.ReceiveData(1, []byte("packet 1"))
	select {
	case <-arq.ReadCh():
		t.Error("sn=1 should not be delivered before sn=0")
	default:
		// correct: not delivered yet
	}

	// Now receive sn=0; both sn=0 and sn=1 should be delivered
	arq.ReceiveData(0, []byte("packet 0"))

	count := 0
	for count < 2 {
		select {
		case pkt := <-arq.ReadCh():
			if pkt.sn != uint16(count) {
				t.Errorf("Expected sn=%d, got %d", count, pkt.sn)
			}
			count++
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("Timeout waiting for packet %d", count)
		}
	}
}

func TestARQ_DuplicateReceive(t *testing.T) {
	cfg := DefaultARQConfig()
	arq := NewARQ(4, 0, cfg)
	defer arq.Close()

	arq.ReceiveData(0, []byte("first"))
	select {
	case <-arq.ReadCh():
		// drained first packet
	default:
	}

	// Second receive of sn=0 should be rejected
	accepted := arq.ReceiveData(0, []byte("duplicate"))
	if accepted {
		t.Error("Duplicate receive of sn=0 should be rejected")
	}
}

func TestARQ_RetransmitPending_InitialSend(t *testing.T) {
	cfg := DefaultARQConfig()
	arq := NewARQ(5, 0, cfg)
	defer arq.Close()

	payload := []byte("retransmit me")
	sn, ok := arq.Enqueue(payload)
	if !ok {
		t.Fatal("Enqueue failed")
	}

	// First RetransmitPending should include this packet (not yet dispatched)
	packets := arq.RetransmitPending()
	found := false
	for _, p := range packets {
		if p.sn == sn && bytes.Equal(p.data, payload) {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected sn=%d in RetransmitPending, got: %v", sn, packets)
	}
}

func TestARQ_NackReceived_RateLimiting(t *testing.T) {
	cfg := DefaultARQConfig()
	cfg.DataNackInitialDelay = 0.1
	cfg.DataNackRepeatInterval = 0.2
	arq := NewARQ(6, 0, cfg)
	defer arq.Close()

	sn := uint16(10)

	// First NACK: initial delay hasn't elapsed, should be false
	should := arq.NackReceived(sn)
	if should {
		t.Error("First NACK should be delayed by DataNackInitialDelay")
	}

	// Wait for initial delay
	time.Sleep(110 * time.Millisecond)
	should = arq.NackReceived(sn)
	if !should {
		t.Error("NACK should trigger after initial delay elapsed")
	}

	// Immediate second NACK should be rate-limited
	should = arq.NackReceived(sn)
	if should {
		t.Error("Second NACK should be rate-limited by DataNackRepeatInterval")
	}

	// After repeat interval, should trigger again
	time.Sleep(210 * time.Millisecond)
	should = arq.NackReceived(sn)
	if !should {
		t.Error("NACK should trigger again after DataNackRepeatInterval")
	}
}

func TestARQ_WindowFull(t *testing.T) {
	cfg := DefaultARQConfig()
	cfg.WindowSize = 10 // tiny window for testing
	arq := NewARQ(7, 0, cfg)
	defer arq.Close()

	// Fill window to limit (limit = 80% of windowSize = 8)
	count := 0
	for i := 0; i < 100; i++ {
		_, ok := arq.Enqueue([]byte("data"))
		if !ok {
			break
		}
		count++
	}
	if count == 0 {
		t.Error("Should enqueue at least some items before window fills")
	}
}

func TestARQ_IsInactive(t *testing.T) {
	cfg := DefaultARQConfig()
	cfg.InactivityTimeout = 200.0 // 200 seconds
	arq := NewARQ(8, 0, cfg)
	defer arq.Close()

	if arq.IsInactive() {
		t.Error("Freshly created ARQ should not be inactive")
	}

	// Backdate lastActivity to simulate inactivity
	arq.mu.Lock()
	arq.lastActivity = arq.lastActivity.Add(-300 * time.Second)
	arq.mu.Unlock()

	if !arq.IsInactive() {
		t.Error("ARQ should be inactive after lastActivity was backdated beyond timeout")
	}
}

func TestARQ_CloseIdempotent(t *testing.T) {
	cfg := DefaultARQConfig()
	arq := NewARQ(9, 0, cfg)
	arq.Close()
	arq.Close() // Should not panic
	if !arq.IsClosed() {
		t.Error("ARQ should be closed")
	}
}

func TestUpdateAdaptiveRTO_KarnJacobson(t *testing.T) {
	minRTO := 100 * time.Millisecond
	maxRTO := 30 * time.Second
	state := adaptiveRTOState{}

	// First sample: SRTT = sample, RTTVAR = sample/2
	state = updateAdaptiveRTO(state, 200*time.Millisecond, minRTO, maxRTO)
	if state.srtt != 200*time.Millisecond {
		t.Errorf("Initial SRTT should equal first sample, got %v", state.srtt)
	}
	if state.rttvar != 100*time.Millisecond {
		t.Errorf("Initial RTTVAR should be sample/2=100ms, got %v", state.rttvar)
	}

	// Second sample: 400ms
	state = updateAdaptiveRTO(state, 400*time.Millisecond, minRTO, maxRTO)
	// SRTT = (7/8)*200ms + (1/8)*400ms = 225ms
	// RTTVAR = (3/4)*100ms + (1/4)*200ms = 125ms
	// RTO = SRTT + 4*RTTVAR = 225 + 500 = 725ms
	if state.currentBase < 600*time.Millisecond || state.currentBase > 900*time.Millisecond {
		t.Errorf("RTO after 2 samples should be ~725ms, got %v", state.currentBase)
	}
}
