// Package dns provides DNS tunneling codecs and reliable ARQ (Automatic Repeat
// reQuest) transport for LumiNet's covert channel over DNS/UDP in restricted
// or censored networks.
//
// # LowerBase32 Codec
//
// Case-insensitive Base32 encoding using the lowercase alphabet:
//
//	"abcdefghijklmnopqrstuvwxyz234567" (no padding)
//
// DNS resolvers often capitalize or lowercase labels unpredictably; this codec
// normalizes input to lowercase before decoding, tolerating DNS case permutation.
//
// # LowerBase36 Codec
//
// Case-insensitive custom Base36 encoding for binary-to-DNS-subdomain mapping.
// Encodes 7 bytes → 11 characters (fitting in a single DNS label).
//
// Alphabet: "0123456789abcdefghijklmnopqrstuvwxyz"
//
// The codec handles DNS case permutation by maintaining a 256-entry decode table
// that maps both 'A'-'Z' and 'a'-'z' to their digit values.
//
// # ARQ Transport
//
// Provides a TCP-like reliable stream over DNS queries with:
//   - Sliding window send/receive buffers (sndNxt, rcvNxt)
//   - Karn/Jacobson adaptive RTO: srtt, rttvar, currentBase = srtt + 4*rttvar
//   - NACK-based retransmission (firstDataNackSeen, lastDataNackSent)
//   - Per-packet TTL and max retries
//
package dns

import (
	"encoding/base32"
	"errors"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/protocols/reliable"
)

// ─────────────────────────────────────────────────────────────────────────────
// LowerBase32 Codec
// ─────────────────────────────────────────────────────────────────────────────

// lowerBase32Encoding uses the alphabet "abcdefghijklmnopqrstuvwxyz234567" (no padding).
// DNS resolvers may alter case, so we always normalize to lowercase before decoding.
var lowerBase32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// EncodedLenLowerBase32 returns the number of characters needed to encode n bytes.
func EncodedLenLowerBase32(n int) int {
	if n <= 0 {
		return 0
	}
	return lowerBase32Encoding.EncodedLen(n)
}

// EncodeLowerBase32 encodes data to a lowercase Base32 string without padding.
func EncodeLowerBase32(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	out := make([]byte, lowerBase32Encoding.EncodedLen(len(data)))
	lowerBase32Encoding.Encode(out, data)
	return string(out)
}

// EncodeLowerBase32Bytes encodes data to a lowercase Base32 byte slice without padding.
func EncodeLowerBase32Bytes(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	out := make([]byte, lowerBase32Encoding.EncodedLen(len(data)))
	lowerBase32Encoding.Encode(out, data)
	return out
}

// DecodeLowerBase32 decodes a lowercase (or uppercase) Base32 byte slice.
// It normalizes uppercase letters to lowercase before decoding to handle DNS case permutation.
func DecodeLowerBase32(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}
	normalized := make([]byte, len(data))
	for i, ch := range data {
		if ch >= 'A' && ch <= 'Z' {
			normalized[i] = ch + ('a' - 'A')
		} else {
			normalized[i] = ch
		}
	}
	out := make([]byte, lowerBase32Encoding.DecodedLen(len(normalized)))
	n, err := lowerBase32Encoding.Decode(out, normalized)
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}

// DecodeLowerBase32String decodes a lowercase (or mixed-case) Base32 string.
func DecodeLowerBase32String(data string) ([]byte, error) {
	if data == "" {
		return []byte{}, nil
	}
	return DecodeLowerBase32([]byte(strings.ToLower(data)))
}

// ─────────────────────────────────────────────────────────────────────────────
// LowerBase36 Codec
//
// Block dimensions: 7 bytes → 11 characters (full block)
// Partial blocks supported via lowerBase36EncodedCharsByBytes and
// lowerBase36DecodedBytesByChars lookup tables.
// ─────────────────────────────────────────────────────────────────────────────

// ErrInvalidLowerBase36 is returned when a character outside the Base36 alphabet is encountered.
var ErrInvalidLowerBase36 = errors.New("invalid lower base36 data")

// lowerBase36Alphabet maps digit 0-35 to its character representation.
var lowerBase36Alphabet = [36]byte{
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
	'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
	'u', 'v', 'w', 'x', 'y', 'z',
}

// lowerBase36DecodeMap: 256-entry lookup. 0xFF = invalid character.
// Supports both 'a'-'z' and 'A'-'Z' (case-insensitive DNS tolerance).
var lowerBase36DecodeMap = newLowerBase36DecodeMap()

// Mapping from partial byte count to encoded character count (for 0..7 bytes)
var lowerBase36EncodedCharsByBytes = [8]int{0, 2, 4, 5, 7, 8, 10, 11}

// Mapping from partial encoded character count to decoded byte count (for 0..11 chars)
var lowerBase36DecodedBytesByChars = [12]int{0, 0, 1, 0, 2, 3, 0, 4, 5, 0, 6, 7}

func newLowerBase36DecodeMap() [256]byte {
	var table [256]byte
	for i := range table {
		table[i] = 0xFF // invalid
	}
	for i, ch := range lowerBase36Alphabet {
		table[ch] = byte(i)
		if ch >= 'a' && ch <= 'z' {
			table[ch-'a'+'A'] = byte(i) // uppercase alias
		}
	}
	return table
}

// EncodedLenLowerBase36 returns the encoded length in characters for n input bytes.
func EncodedLenLowerBase36(n int) int {
	if n <= 0 {
		return 0
	}
	blocks := n / 7
	rem := n % 7
	return blocks*11 + lowerBase36EncodedCharsByBytes[rem]
}

// EncodeLowerBase36To encodes data into dst using LowerBase36 encoding.
// dst must have length >= EncodedLenLowerBase36(len(data)).
// Returns the number of bytes written.
func EncodeLowerBase36To(dst []byte, data []byte) int {
	if len(data) == 0 {
		return 0
	}
	offset := 0
	src := data

	for len(src) >= 7 {
		// Pack 7 bytes into a 56-bit uint64
		val := uint64(src[0])<<48 | uint64(src[1])<<40 |
			uint64(src[2])<<32 | uint64(src[3])<<24 |
			uint64(src[4])<<16 | uint64(src[5])<<8 | uint64(src[6])
		writeBase36Block(dst[offset:offset+11], val, 11)
		offset += 11
		src = src[7:]
	}

	if len(src) > 0 {
		var val uint64
		for _, b := range src {
			val = (val << 8) | uint64(b)
		}
		charCount := lowerBase36EncodedCharsByBytes[len(src)]
		writeBase36Block(dst[offset:offset+charCount], val, charCount)
		offset += charCount
	}

	return offset
}

// writeBase36Block writes `count` base36 digits into dst in big-endian (MSB first).
func writeBase36Block(dst []byte, val uint64, count int) {
	for i := count - 1; i >= 0; i-- {
		dst[i] = lowerBase36Alphabet[val%36]
		val /= 36
	}
}

// EncodeLowerBase36Bytes encodes data to a byte slice using LowerBase36.
func EncodeLowerBase36Bytes(data []byte) []byte {
	out := make([]byte, EncodedLenLowerBase36(len(data)))
	n := EncodeLowerBase36To(out, data)
	return out[:n]
}

// EncodeLowerBase36 encodes data to a string using LowerBase36.
func EncodeLowerBase36(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return string(EncodeLowerBase36Bytes(data))
}

// DecodeLowerBase36 decodes a case-insensitive LowerBase36 byte slice.
func DecodeLowerBase36(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	totalBytes, err := decodedLenLowerBase36(len(data))
	if err != nil {
		return nil, err
	}

	out := make([]byte, totalBytes)
	offset := 0
	src := data

	for len(src) > 0 {
		blockSize, charCount := lowerBase36NextDecodeBlock(len(src))
		val, err := readBase36Block(src[:charCount])
		if err != nil {
			return nil, err
		}
		for i := blockSize - 1; i >= 0; i-- {
			out[offset+i] = byte(val)
			val >>= 8
		}
		offset += blockSize
		src = src[charCount:]
	}

	return out, nil
}

// DecodeLowerBase36String decodes a case-insensitive LowerBase36 string.
func DecodeLowerBase36String(data string) ([]byte, error) {
	if data == "" {
		return []byte{}, nil
	}
	return DecodeLowerBase36([]byte(strings.ToLower(data)))
}

// decodedLenLowerBase36 calculates decoded byte count for encodedLen characters.
func decodedLenLowerBase36(encodedLen int) (int, error) {
	if encodedLen <= 0 {
		return 0, nil
	}
	blocks := encodedLen / 11
	rem := encodedLen % 11
	if rem >= len(lowerBase36DecodedBytesByChars) {
		return 0, ErrInvalidLowerBase36
	}
	decodedRem := lowerBase36DecodedBytesByChars[rem]
	if rem != 0 && decodedRem == 0 {
		return 0, ErrInvalidLowerBase36
	}
	return blocks*7 + decodedRem, nil
}

// lowerBase36NextDecodeBlock returns (blockSize, charCount) for the next decode block.
func lowerBase36NextDecodeBlock(remaining int) (blockSize int, charCount int) {
	if remaining >= 11 {
		return 7, 11
	}
	return lowerBase36DecodedBytesByChars[remaining], remaining
}

// readBase36Block decodes a Base36 character sequence to uint64.
func readBase36Block(data []byte) (uint64, error) {
	var val uint64
	for _, ch := range data {
		digit := lowerBase36DecodeMap[ch]
		if digit == 0xFF {
			return 0, ErrInvalidLowerBase36
		}
		val = val*36 + uint64(digit)
	}
	return val, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// ARQ Transport
//
// Provides reliable ARQ stream over DNS/UDP with Karn/Jacobson adaptive RTO,
// NACK-based retransmission, sliding window buffers, and per-packet TTL.
// ─────────────────────────────────────────────────────────────────────────────

// ARQStreamState represents the lifecycle state of an ARQ stream.
type ARQStreamState int

const (
	ARQStateOpen             ARQStreamState = iota
	ARQStateHalfClosedLocal                 // We sent close-read
	ARQStateHalfClosedRemote                // Peer sent close-read
	ARQStateClosing                         // Both sides closing
	ARQStateClosed                          // Fully closed
)

// adaptiveRTOState implements Karn/Jacobson adaptive RTO calculation.
//
// Algorithm (RFC 6298):
//
//	SRTT    ← (7/8)*SRTT + (1/8)*sample
//	RTTVAR  ← (3/4)*RTTVAR + (1/4)*|SRTT - sample|
//	RTO     ← clamp(SRTT + 4*RTTVAR, minRTO, maxRTO)
type adaptiveRTOState struct {
	srtt        time.Duration
	rttvar      time.Duration
	currentBase time.Duration
	initialized bool
}

// updateAdaptiveRTO applies one RTT sample to update the adaptive RTO state.
func updateAdaptiveRTO(state adaptiveRTOState, sample, minRTO, maxRTO time.Duration) adaptiveRTOState {
	sample = clampDuration(sample, minRTO, maxRTO)

	if !state.initialized {
		state.srtt = sample
		state.rttvar = sample / 2
		state.initialized = true
	} else {
		delta := absDuration(state.srtt - sample)
		state.rttvar = (3*state.rttvar + delta) / 4
		state.srtt = (7*state.srtt + sample) / 8
	}
	state.currentBase = clampDuration(state.srtt+4*state.rttvar, minRTO, maxRTO)
	return state
}

// arqDataItem tracks a single enqueued outbound data packet in the send buffer.
type arqDataItem struct {
	data           []byte
	createdAt      time.Time
	lastSentAt     time.Time
	dispatched     bool
	lastNackSentAt time.Time
	retries        int
	currentRTO     time.Duration
	sampleEligible bool
	ttl            time.Duration
}

// ARQConfig holds tuning parameters for an ARQ stream instance.
type ARQConfig struct {
	// Window and buffering
	WindowSize     int
	InboundQueueSz int

	// Timing (seconds as float64 for sub-second precision)
	RTO                    float64
	MaxRTO                 float64
	InactivityTimeout      float64
	DataPacketTTL          float64
	MaxDataRetries         int
	TerminalDrainTimeout   float64
	TerminalAckWaitTimeout float64
	DataNackMaxGap         int
	DataNackInitialDelay   float64
	DataNackRepeatInterval float64

	// Roles
	IsClient bool
}

// DefaultARQConfig returns sensible defaults for a DNS tunnel ARQ stream.
func DefaultARQConfig() ARQConfig {
	return ARQConfig{
		WindowSize:             300,
		InboundQueueSz:         1200,
		RTO:                    0.5,
		MaxRTO:                 30.0,
		InactivityTimeout:      120.0,
		DataPacketTTL:          120.0,
		MaxDataRetries:         60,
		TerminalDrainTimeout:   60.0,
		TerminalAckWaitTimeout: 30.0,
		DataNackMaxGap:         0,
		DataNackInitialDelay:   0.0,
		DataNackRepeatInterval: 0.5,
		IsClient:               true,
	}
}

// ARQ implements a reliable, ordered data stream overlay for DNS tunneling.
//
// Key invariants:
//   - sndNxt: next outbound sequence number to assign
//   - rcvNxt: next expected inbound sequence number
//   - sndBuf: map[seqNum] → pending outbound data (ACK not yet received)
//   - rcvBuf: map[seqNum] → received-but-not-delivered inbound data
//   - firstDataNackSeen/lastDataNackSent: NACK delay tracking per sequence
type ARQ struct {
	mu sync.RWMutex

	streamID  uint16
	sessionID uint8
	isClient  bool

	// Sliding window state
	sndNxt uint16
	rcvNxt uint16
	sndBuf map[uint16]*arqDataItem
	rcvBuf map[uint16][]byte

	// Stream lifecycle
	state  ARQStreamState
	closed bool

	// Adaptive RTO
	rto      time.Duration
	maxRTO   time.Duration
	rtoState adaptiveRTOState

	// NACK tracking for retransmission triggering
	dataNackMu        sync.Mutex
	firstDataNackSeen map[uint16]time.Time
	lastDataNackSent  map[uint16]time.Time

	// Configuration
	windowSize        int
	limit             int // flow control limit = windowSize * 0.8
	maxDataRetries    int
	dataPacketTTL     time.Duration
	inactivityTimeout time.Duration
	dataNackMaxGap    int
	dataNackInitDelay time.Duration
	dataNackRepeat    time.Duration

	// Concurrency
	ctx         chan struct{} // closed when ARQ is shut down
	flushSignal chan struct{} // signals retransmit loop to wake
	rxChan      chan rxPayload

	lastActivity time.Time

	// core owns protocol sequencing, windows, RTO, retries, and NACK policy.
	core *reliable.Stream
}

type rxPayload struct {
	sn   uint16
	data []byte
}

// NewARQ constructs and initialises an ARQ stream instance.
//
// Arguments:
//   - streamID: 16-bit stream identifier (used as echo identifier in DNS packets)
//   - sessionID: 8-bit session identifier for the client/server pair
//   - cfg: tuning configuration (use DefaultARQConfig() as a starting point)
func NewARQ(streamID uint16, sessionID uint8, cfg ARQConfig) *ARQ {
	windowSize := cfg.WindowSize
	if windowSize < 50 {
		windowSize = 300
	}
	limit := int(math.Max(float64(windowSize)*0.8, 50))

	rto := time.Duration(math.Max(0.05, math.Min(cfg.RTO, cfg.MaxRTO)) * float64(time.Second))
	maxRTO := time.Duration(math.Max(0.05, cfg.MaxRTO) * float64(time.Second))

	inboundQSz := cfg.InboundQueueSz
	if inboundQSz <= 0 {
		inboundQSz = windowSize * 4
	}

	a := &ARQ{
		streamID:  streamID,
		sessionID: sessionID,
		isClient:  cfg.IsClient,

		sndBuf: make(map[uint16]*arqDataItem),
		rcvBuf: make(map[uint16][]byte),

		state:        ARQStateOpen,
		lastActivity: time.Now(),

		windowSize: windowSize,
		limit:      limit,

		rto:               rto,
		maxRTO:            maxRTO,
		rtoState:          adaptiveRTOState{currentBase: rto},
		maxDataRetries:    maxI(60, cfg.MaxDataRetries),
		dataPacketTTL:     time.Duration(math.Max(120, cfg.DataPacketTTL) * float64(time.Second)),
		inactivityTimeout: time.Duration(math.Max(120, cfg.InactivityTimeout) * float64(time.Second)),
		dataNackMaxGap:    cfg.DataNackMaxGap,
		dataNackInitDelay: time.Duration(math.Max(0, cfg.DataNackInitialDelay) * float64(time.Second)),
		dataNackRepeat:    time.Duration(math.Max(0.1, cfg.DataNackRepeatInterval) * float64(time.Second)),

		firstDataNackSeen: make(map[uint16]time.Time),
		lastDataNackSent:  make(map[uint16]time.Time),

		ctx:         make(chan struct{}),
		flushSignal: make(chan struct{}, 1),
		rxChan:      make(chan rxPayload, inboundQSz),
		core:        reliable.New(reliable.DNSProfile(windowSize, limit, rto, maxRTO, maxI(60, cfg.MaxDataRetries), time.Duration(math.Max(120, cfg.DataPacketTTL)*float64(time.Second)), time.Duration(math.Max(0, cfg.DataNackInitialDelay)*float64(time.Second)), time.Duration(math.Max(0.1, cfg.DataNackRepeatInterval)*float64(time.Second)))),
	}

	return a
}

// ─── Send path ───────────────────────────────────────────────────────────────

// Enqueue adds a data payload to the outbound send buffer.
//
// Assigns the next available sequence number (sndNxt), stores the item in
// sndBuf, and signals the flush/retransmit loop to wake up.
// Returns false if the window is full (caller should apply back-pressure).
func (a *ARQ) Enqueue(data []byte) (sn uint16, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return 0, false
	}
	r := a.core.Step(reliable.Command{Op: reliable.Send, Payload: data})
	if r.Status == reliable.WouldBlock || r.Status == reliable.Closed {
		return 0, false
	}
	// DNS dispatches frames in RetransmitPending; the core deliberately keeps this manual.
	sn = a.sndNxt
	a.sndNxt++
	a.lastActivity = time.Now()

	a.signalFlush()
	return sn, true
}

// AckReceived processes an incoming ACK for sequence number sn.
//
//   - Removes sn from sndBuf (stops retransmission)
//   - Updates adaptive RTO using Karn/Jacobson (RFC 6298) if sample-eligible
func (a *ARQ) AckReceived(sn uint16) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.core.Step(reliable.Command{Op: reliable.Receive, Frame: reliable.Frame{Kind: reliable.Ack, Seq: sn}})
	a.lastActivity = time.Now()
}

// NackReceived handles a NACK for sequence number sn.
//
// Implements the NACK-based retransmission policy:
//   - firstDataNackSeen: records the first time a NACK was observed for sn
//   - lastDataNackSent: rate-limits repeated retransmissions
//   - Retransmits only if the NACK initial delay has elapsed AND repeat interval has elapsed
//
// Returns true if the packet should be retransmitted now.
func (a *ARQ) NackReceived(sn uint16) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.core.Step(reliable.Command{Op: reliable.Receive, Frame: reliable.Frame{Kind: reliable.Nack, Seq: sn}})
	return r.FastRetransmit
}

// ─── Receive path ─────────────────────────────────────────────────────────────

// ReceiveData processes an inbound data packet with sequence number sn.
//
// Implements sliding window receive buffer:
//   - If sn == rcvNxt: deliver directly to rxChan, advance rcvNxt
//   - If sn > rcvNxt and sn - rcvNxt <= windowSize: buffer in rcvBuf
//   - After delivering sn, drain any consecutively-buffered items from rcvBuf
//
// Returns true if the packet was accepted (in-window), false if duplicate or out-of-window.
func (a *ARQ) ReceiveData(sn uint16, data []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return false
	}
	r := a.core.Step(reliable.Command{Op: reliable.Receive, Frame: reliable.Frame{Kind: reliable.Data, Seq: sn, Payload: data}})
	if r.Status != reliable.Accepted {
		return false
	}
	for _, d := range r.Delivered {
		a.deliverLocked(d.Seq, d.Payload)
	}
	a.lastActivity = time.Now()
	return true
}

// deliverLocked sends data to the inbound channel (non-blocking; drops if full).
// Must be called with a.mu held.
func (a *ARQ) deliverLocked(sn uint16, data []byte) {
	select {
	case a.rxChan <- rxPayload{sn: sn, data: append([]byte(nil), data...)}:
	default:
		// Channel full: drop (caller should increase InboundQueueSz)
	}
}

// ReadCh returns the channel on which in-order received payloads are delivered.
func (a *ARQ) ReadCh() <-chan rxPayload {
	return a.rxChan
}

// ─── Retransmit loop ──────────────────────────────────────────────────────────

// RetransmitPending iterates over sndBuf and returns all items whose RTO has expired.
//
// For each expired item:
//   - Increments retry count
//   - Applies exponential backoff: currentRTO *= 1.35, capped at maxRTO
//   - Sets sampleEligible=false (Karn's algorithm: don't sample retransmitted packets)
//   - Drops the item if retries > maxDataRetries or TTL exceeded
//
// Returns a slice of (sequenceNum, data) pairs to retransmit.
func (a *ARQ) RetransmitPending() []rxPayload {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.core.Step(reliable.Command{Op: reliable.Tick})
	toSend := make([]rxPayload, 0, len(r.Outbound))
	for _, f := range r.Outbound {
		if f.Kind == reliable.Data {
			toSend = append(toSend, rxPayload{sn: f.Seq, data: f.Payload})
		}
	}
	return toSend
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────

// Close shuts down the ARQ stream, releasing all resources.
func (a *ARQ) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.closed {
		return
	}
	a.closed = true
	a.state = ARQStateClosed
	close(a.ctx)
	close(a.rxChan)
}

// IsClosed returns true if the ARQ stream has been closed.
func (a *ARQ) IsClosed() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.closed
}

// IsInactive returns true if no data has been sent or received within the inactivity timeout.
func (a *ARQ) IsInactive() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return time.Since(a.lastActivity) > a.inactivityTimeout
}

// PendingCount returns the number of unacknowledged outbound data packets.
func (a *ARQ) PendingCount() int {
	return a.core.Stats().Pending
}

// SignalFlush wakes the retransmit loop to immediately process the send buffer.
func (a *ARQ) SignalFlush() {
	a.signalFlush()
}

func (a *ARQ) signalFlush() {
	select {
	case a.flushSignal <- struct{}{}:
	default:
	}
}

// Done returns a channel that is closed when the ARQ context is cancelled/closed.
func (a *ARQ) Done() <-chan struct{} {
	return a.ctx
}

// currentDataRTO returns the current adaptive RTO for data packets.
func (a *ARQ) currentDataRTO() time.Duration {
	base := a.rtoState.currentBase
	if base <= 0 {
		return a.rto
	}
	return clampDuration(base, a.rto, a.maxRTO)
}

// ─── Utilities ────────────────────────────────────────────────────────────────

func clampDuration(v, minV, maxV time.Duration) time.Duration {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func maxI(x, y int) int {
	if x > y {
		return x
	}
	return y
}
