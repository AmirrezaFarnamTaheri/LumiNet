package tlsdecoy

import (
	"sync"
)

// ExtendedFragmentStrategy identifies granular evasion strategies including character-by-character SNI splitting.
type ExtendedFragmentStrategy string

const (
	ExtendedStrategySniChars       ExtendedFragmentStrategy = "SNI_CHARS"
	ExtendedStrategyMulti64        ExtendedFragmentStrategy = "MULTI64"
	ExtendedStrategyFull5          ExtendedFragmentStrategy = "FULL5"
	ExtendedStrategyFull10         ExtendedFragmentStrategy = "FULL10"
	ExtendedStrategyFull20         ExtendedFragmentStrategy = "FULL20"
	ExtendedStrategySniBoundary    ExtendedFragmentStrategy = "SNI_BOUNDARY"
	ExtendedStrategySniSplit       ExtendedFragmentStrategy = "SNI_SPLIT"
	ExtendedStrategyTlsRecordFrag  ExtendedFragmentStrategy = "TLS_RECORD_FRAG"
	ExtendedStrategyTlsSniRecords  ExtendedFragmentStrategy = "TLS_SNI_RECORDS"
	ExtendedStrategyHalf           ExtendedFragmentStrategy = "HALF"
	ExtendedStrategyRaw            ExtendedFragmentStrategy = "RAW"
)

// StrategyResponseStatus describes middlebox response categorization.
type StrategyResponseStatus int

const (
	ResponseStatusValid StrategyResponseStatus = iota
	ResponseStatusEmpty
	ResponseStatusAlertRejected
	ResponseStatusTruncatedMalformed
)

// ValidateStrategyResponse inspects initial server response to detect middlebox RST/Alert or corrupted handshakes.
func ValidateStrategyResponse(response []byte) StrategyResponseStatus {
	if len(response) == 0 {
		return ResponseStatusEmpty
	}
	first := response[0]
	if first == 0x15 {
		return ResponseStatusAlertRejected
	}
	if len(response) < 8 && (first == 0x14 || first == 0x16 || first == 0x17) {
		return ResponseStatusTruncatedMalformed
	}
	return ResponseStatusValid
}

// FragmentExtended applies an ExtendedFragmentStrategy to arbitrary byte data.
func FragmentExtended(data []byte, strategy ExtendedFragmentStrategy, chunkSize int) [][]byte {
	if len(data) < 2 {
		return [][]byte{data}
	}

	offset, length, found := LocateSNI(data)

	switch strategy {
	case ExtendedStrategyRaw:
		return [][]byte{data}
	case ExtendedStrategyHalf:
		cut := len(data) / 2
		if cut < 1 {
			cut = 1
		}
		return SplitAt(data, cut)
	case ExtendedStrategyFull5:
		return FixedChunks(data, 5)
	case ExtendedStrategyFull10:
		return FixedChunks(data, 10)
	case ExtendedStrategyFull20:
		return FixedChunks(data, 20)
	case ExtendedStrategyMulti64:
		size := chunkSize
		if size <= 0 {
			size = 64
		}
		return FixedChunks(data, size)
	case ExtendedStrategySniBoundary:
		if found {
			return SplitAt(data, offset)
		}
		return SplitAt(data, len(data)/2)
	case ExtendedStrategySniSplit:
		if found {
			mid := length / 2
			if mid < 1 {
				mid = 1
			}
			return SplitAt(data, offset+mid)
		}
		return SplitAt(data, len(data)/2)
	case ExtendedStrategySniChars:
		if found {
			var out [][]byte
			if offset > 0 {
				prefix := make([]byte, offset)
				copy(prefix, data[:offset])
				out = append(out, prefix)
			}
			for i := 0; i < length; i++ {
				out = append(out, []byte{data[offset+i]})
			}
			if offset+length < len(data) {
				suffix := make([]byte, len(data)-(offset+length))
				copy(suffix, data[offset+length:])
				out = append(out, suffix)
			}
			return out
		}
		return SplitAt(data, len(data)/2)
	case ExtendedStrategyTlsRecordFrag:
		return SplitTlsRecord(data, false)
	case ExtendedStrategyTlsSniRecords:
		return SplitTlsRecord(data, true)
	default:
		return [][]byte{data}
	}
}

// BuildDisposableFakeProbe constructs a lightweight RFC 8446 compliant TLS 1.3 ClientHello with fake SNI and ALPN.
func BuildDisposableFakeProbe(fakeSNI string) []byte {
	hostBytes := []byte(fakeSNI)
	var pkt []byte

	pkt = append(pkt, 0x16, 0x03, 0x01, 0x00, 0x00)

	handshakeStart := len(pkt)
	pkt = append(pkt, 0x01, 0x00, 0x00, 0x00)
	pkt = append(pkt, 0x03, 0x03)

	for i := 0; i < 32; i++ {
		pkt = append(pkt, byte((i*37+11)&0xff))
	}
	pkt = append(pkt, 0x00) // session ID length

	pkt = append(pkt, 0x00, 0x04, 0x13, 0x01, 0x13, 0x03) // ciphers
	pkt = append(pkt, 0x01, 0x00)                         // compression null

	extLenPos := len(pkt)
	pkt = append(pkt, 0x00, 0x00)
	extStart := len(pkt)

	// SNI extension
	sniExtLen := 2 + 1 + 2 + len(hostBytes)
	pkt = append(pkt, 0x00, 0x00, byte((sniExtLen>>8)&0xff), byte(sniExtLen&0xff))
	listLen := 1 + 2 + len(hostBytes)
	pkt = append(pkt, byte((listLen>>8)&0xff), byte(listLen&0xff), 0x00, byte((len(hostBytes)>>8)&0xff), byte(len(hostBytes)&0xff))
	pkt = append(pkt, hostBytes...)

	// ALPN extension (http/1.1, h2)
	pkt = append(pkt, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1', 0x02, 'h', '2')

	extLen := len(pkt) - extStart
	pkt[extLenPos] = byte((extLen >> 8) & 0xff)
	pkt[extLenPos+1] = byte(extLen & 0xff)

	hsLen := len(pkt) - handshakeStart - 4
	pkt[handshakeStart+1] = byte((hsLen >> 16) & 0xff)
	pkt[handshakeStart+2] = byte((hsLen >> 8) & 0xff)
	pkt[handshakeStart+3] = byte(hsLen & 0xff)

	recLen := len(pkt) - 5
	pkt[3] = byte((recLen >> 8) & 0xff)
	pkt[4] = byte(recLen & 0xff)

	return pkt
}

// CarrierMode represents carrier network tuning profile.
type CarrierMode string

const (
	CarrierModeMci      CarrierMode = "mci"
	CarrierModeIrancell CarrierMode = "irancell"
	CarrierModeAdaptive CarrierMode = "adaptive"
)

// StrategyPlanEntry holds strategy and associated pacing delay.
type StrategyPlanEntry struct {
	Strategy ExtendedFragmentStrategy
	DelayMs  int
}

// AdaptiveStrategyRacer tracks preferred strategies and orders plans per host.
type AdaptiveStrategyRacer struct {
	mu                  sync.RWMutex
	carrierMode         CarrierMode
	preferredStrategies map[string]ExtendedFragmentStrategy
	fakeProbeEnabled    bool
	fakeSNI             string
}

// NewAdaptiveStrategyRacer initializes an AdaptiveStrategyRacer.
func NewAdaptiveStrategyRacer(mode CarrierMode, fakeSNI string) *AdaptiveStrategyRacer {
	return &AdaptiveStrategyRacer{
		carrierMode:         mode,
		preferredStrategies: make(map[string]ExtendedFragmentStrategy),
		fakeProbeEnabled:    true,
		fakeSNI:             fakeSNI,
	}
}

// PlanStrategies generates prioritized strategies for a target host.
func (r *AdaptiveStrategyRacer) PlanStrategies(host string) []StrategyPlanEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var base []StrategyPlanEntry
	switch r.carrierMode {
	case CarrierModeMci:
		base = []StrategyPlanEntry{
			{Strategy: ExtendedStrategyFull20, DelayMs: 1},
			{Strategy: ExtendedStrategyFull10, DelayMs: 2},
			{Strategy: ExtendedStrategyFull5, DelayMs: 5},
			{Strategy: ExtendedStrategySniChars, DelayMs: 2},
			{Strategy: ExtendedStrategySniBoundary, DelayMs: 1},
			{Strategy: ExtendedStrategySniSplit, DelayMs: 3},
			{Strategy: ExtendedStrategyTlsRecordFrag, DelayMs: 3},
			{Strategy: ExtendedStrategyTlsSniRecords, DelayMs: 3},
			{Strategy: ExtendedStrategyHalf, DelayMs: 3},
			{Strategy: ExtendedStrategyRaw, DelayMs: 0},
		}
	case CarrierModeIrancell:
		base = []StrategyPlanEntry{
			{Strategy: ExtendedStrategyMulti64, DelayMs: 0},
			{Strategy: ExtendedStrategySniBoundary, DelayMs: 0},
			{Strategy: ExtendedStrategyTlsRecordFrag, DelayMs: 1},
			{Strategy: ExtendedStrategySniChars, DelayMs: 1},
			{Strategy: ExtendedStrategySniSplit, DelayMs: 2},
			{Strategy: ExtendedStrategyHalf, DelayMs: 2},
			{Strategy: ExtendedStrategyRaw, DelayMs: 0},
		}
	case CarrierModeAdaptive:
		fallthrough
	default:
		base = []StrategyPlanEntry{
			{Strategy: ExtendedStrategySniSplit, DelayMs: 2},
			{Strategy: ExtendedStrategySniBoundary, DelayMs: 1},
			{Strategy: ExtendedStrategySniChars, DelayMs: 1},
			{Strategy: ExtendedStrategyTlsSniRecords, DelayMs: 2},
			{Strategy: ExtendedStrategyTlsRecordFrag, DelayMs: 2},
			{Strategy: ExtendedStrategyMulti64, DelayMs: 0},
			{Strategy: ExtendedStrategyHalf, DelayMs: 2},
			{Strategy: ExtendedStrategyRaw, DelayMs: 0},
		}
	}

	if preferred, ok := r.preferredStrategies[host]; ok {
		var prioritized []StrategyPlanEntry
		var others []StrategyPlanEntry
		for _, entry := range base {
			if entry.Strategy == preferred {
				prioritized = append(prioritized, entry)
			} else {
				others = append(others, entry)
			}
		}
		return append(prioritized, others...)
	}

	return base
}

// RecordSuccess caches the winning strategy for a host.
func (r *AdaptiveStrategyRacer) RecordSuccess(host string, strategy ExtendedFragmentStrategy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.preferredStrategies[host] = strategy
}

// PreferredStrategy returns the cached winning strategy if known.
func (r *AdaptiveStrategyRacer) PreferredStrategy(host string) (ExtendedFragmentStrategy, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.preferredStrategies[host]
	return s, ok
}

// BuildFakeProbe generates disposable fake probe bytes if enabled.
func (r *AdaptiveStrategyRacer) BuildFakeProbe() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.fakeProbeEnabled && r.fakeSNI != "" {
		return BuildDisposableFakeProbe(r.fakeSNI)
	}
	return nil
}
