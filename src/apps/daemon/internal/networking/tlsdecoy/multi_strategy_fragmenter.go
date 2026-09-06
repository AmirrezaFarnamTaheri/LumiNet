package tlsdecoy

import (
	"sync"
	"time"
)

// FragmentStrategy enumerates the 10 discrete fragmentation and packet-splitting strategies.
type FragmentStrategy string

const (
	FragmentStrategyFinalMaskTlsHello FragmentStrategy = "FINALMASK_TLS_HELLO"
	FragmentStrategyFull5             FragmentStrategy = "FULL5"
	FragmentStrategyFull10            FragmentStrategy = "FULL10"
	FragmentStrategyFull20            FragmentStrategy = "FULL20"
	FragmentStrategySniBoundary       FragmentStrategy = "SNI_BOUNDARY"
	FragmentStrategySniSplit          FragmentStrategy = "SNI_SPLIT"
	FragmentStrategyTlsRecordFrag     FragmentStrategy = "TLS_RECORD_FRAG"
	FragmentStrategyTlsSniRecords     FragmentStrategy = "TLS_SNI_RECORDS"
	FragmentStrategyHalf              FragmentStrategy = "HALF"
	FragmentStrategyRaw               FragmentStrategy = "RAW"
)

// FinalMaskSettings holds parameter values for TLS record rewriting.
type FinalMaskSettings struct {
	Packet   string
	Length   int
	DelayMs  int
	MaxSplit int
}

// DefaultFinalMaskSettings returns default FinalMask configuration.
func DefaultFinalMaskSettings() FinalMaskSettings {
	return FinalMaskSettings{
		Packet:   "tlshello",
		Length:   5,
		DelayMs:  0,
		MaxSplit: 2,
	}
}

// FinalMaskRewrite represents rewritten TLS records.
type FinalMaskRewrite struct {
	FirstWrite    []byte
	TrailingWrite []byte
}

// Writes returns a slice of byte slices representing sequential network writes.
func (r FinalMaskRewrite) Writes() [][]byte {
	var out [][]byte
	if len(r.FirstWrite) > 0 {
		out = append(out, r.FirstWrite)
	}
	if len(r.TrailingWrite) > 0 {
		out = append(out, r.TrailingWrite)
	}
	return out
}

// Bytes concatenates FirstWrite and TrailingWrite.
func (r FinalMaskRewrite) Bytes() []byte {
	out := make([]byte, 0, len(r.FirstWrite)+len(r.TrailingWrite))
	out = append(out, r.FirstWrite...)
	out = append(out, r.TrailingWrite...)
	return out
}

// LocateSNI scans a TLS ClientHello packet to locate the byte offset and length of the SNI hostname.
func LocateSNI(data []byte) (offset, length int, found bool) {
	if len(data) < 9 || data[0] != 0x16 {
		return 0, 0, false
	}
	recordLen := (int(data[3]) << 8) | int(data[4])
	recordEnd := len(data)
	if 5+recordLen < recordEnd {
		recordEnd = 5 + recordLen
	}

	pos := 5
	if pos >= recordEnd || data[pos] != 0x01 {
		return 0, 0, false
	}
	pos += 4 + 2 + 32 // handshake header (4) + client version (2) + random (32)
	if pos >= recordEnd {
		return 0, 0, false
	}

	sessionLen := int(data[pos])
	pos += 1 + sessionLen
	if pos+2 > recordEnd {
		return 0, 0, false
	}

	cipherLen := (int(data[pos]) << 8) | int(data[pos+1])
	pos += 2 + cipherLen
	if pos+1 > recordEnd {
		return 0, 0, false
	}

	compLen := int(data[pos])
	pos += 1 + compLen
	if pos+2 > recordEnd {
		return 0, 0, false
	}

	extLen := (int(data[pos]) << 8) | int(data[pos+1])
	pos += 2
	extEnd := recordEnd
	if pos+extLen < extEnd {
		extEnd = pos + extLen
	}

	for pos+4 <= extEnd {
		extType := (int(data[pos]) << 8) | int(data[pos+1])
		extDataLen := (int(data[pos+2]) << 8) | int(data[pos+3])
		pos += 4

		if extType == 0x0000 && pos+extDataLen <= extEnd {
			namePos := pos + 2 // skip server_name_list length (2 bytes)
			namesEnd := pos + extDataLen
			for namePos+3 <= namesEnd {
				nameType := data[namePos]
				nameLen := (int(data[namePos+1]) << 8) | int(data[namePos+2])
				namePos += 3
				if nameType == 0 && namePos+nameLen <= namesEnd {
					return namePos, nameLen, true
				}
				namePos += nameLen
			}
		}
		pos += extDataLen
	}

	return 0, 0, false
}

// ExtractSNI extracts the ASCII SNI hostname from a TLS ClientHello packet.
func ExtractSNI(data []byte) string {
	offset, length, found := LocateSNI(data)
	if !found || offset+length > len(data) {
		return ""
	}
	return string(data[offset : offset+length])
}

// BuildTlsRecordFrame encapsulates payload bytes inside a valid TLS record header (0x16, version, length).
func BuildTlsRecordFrame(version [2]byte, payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	frame[0] = 0x16
	frame[1] = version[0]
	frame[2] = version[1]
	frame[3] = byte((len(payload) >> 8) & 0xff)
	frame[4] = byte(len(payload) & 0xff)
	copy(frame[5:], payload)
	return frame
}

// FixedChunks partitions a byte slice into fixed-size chunks.
func FixedChunks(data []byte, size int) [][]byte {
	if len(data) == 0 {
		return [][]byte{data}
	}
	if size <= 0 {
		size = 1
	}
	var out [][]byte
	for i := 0; i < len(data); i += size {
		end := i + size
		if end > len(data) {
			end = len(data)
		}
		chunk := make([]byte, end-i)
		copy(chunk, data[i:end])
		out = append(out, chunk)
	}
	return out
}

// SplitAt partitions a byte slice at the requested index.
func SplitAt(data []byte, requested int) [][]byte {
	if len(data) < 2 {
		return [][]byte{data}
	}
	split := requested
	if split < 1 {
		split = 1
	}
	if split > len(data)-1 {
		split = len(data) - 1
	}
	part1 := make([]byte, split)
	copy(part1, data[:split])
	part2 := make([]byte, len(data)-split)
	copy(part2, data[split:])
	return [][]byte{part1, part2}
}

// SplitTlsRecord splits TLS record payload into two valid TLS records.
func SplitTlsRecord(data []byte, atSni bool) [][]byte {
	if len(data) < 6 || data[0] != 0x16 {
		return [][]byte{data}
	}
	payload := data[5:]
	if len(payload) < 2 {
		return [][]byte{data}
	}

	requested := len(payload) / 2
	if atSni {
		if offset, _, found := LocateSNI(data); found && offset > 5 {
			requested = offset - 5
		}
	}

	if requested < 1 {
		requested = 1
	}
	if requested > len(payload)-1 {
		requested = len(payload) - 1
	}

	version := [2]byte{data[1], data[2]}
	first := BuildTlsRecordFrame(version, payload[:requested])
	second := BuildTlsRecordFrame(version, payload[requested:])
	return [][]byte{first, second}
}

// RewriteFinalMaskWrites rewrites a TLS ClientHello packet into two TLS records plus any trailing writes.
func RewriteFinalMaskWrites(data []byte, settings FinalMaskSettings) FinalMaskRewrite {
	if settings.Packet != "tlshello" || settings.Length <= 0 || settings.MaxSplit < 2 || len(data) < 6 || data[0] != 0x16 {
		return FinalMaskRewrite{FirstWrite: data}
	}

	recordLen := (int(data[3]) << 8) | int(data[4])
	recordEnd := 5 + recordLen
	if recordLen <= settings.Length || recordEnd > len(data) {
		return FinalMaskRewrite{FirstWrite: data}
	}

	version := [2]byte{data[1], data[2]}
	payload := data[5:recordEnd]
	first := BuildTlsRecordFrame(version, payload[:settings.Length])
	second := BuildTlsRecordFrame(version, payload[settings.Length:])

	combined := make([]byte, 0, len(first)+len(second))
	combined = append(combined, first...)
	combined = append(combined, second...)

	var trailing []byte
	if recordEnd < len(data) {
		trailing = make([]byte, len(data)-recordEnd)
		copy(trailing, data[recordEnd:])
	}

	return FinalMaskRewrite{
		FirstWrite:    combined,
		TrailingWrite: trailing,
	}
}

// RewriteFinalMaskTlsHello rewrites a TLS ClientHello into a contiguous byte slice.
func RewriteFinalMaskTlsHello(data []byte, settings FinalMaskSettings) []byte {
	return RewriteFinalMaskWrites(data, settings).Bytes()
}

// FragmentPacket applies the specified strategy to segment a packet.
func FragmentPacket(data []byte, strategy FragmentStrategy, settings FinalMaskSettings) [][]byte {
	switch strategy {
	case FragmentStrategyFinalMaskTlsHello:
		return RewriteFinalMaskWrites(data, settings).Writes()
	case FragmentStrategyFull5:
		return FixedChunks(data, 5)
	case FragmentStrategyFull10:
		return FixedChunks(data, 10)
	case FragmentStrategyFull20:
		return FixedChunks(data, 20)
	case FragmentStrategySniBoundary:
		if offset, _, found := LocateSNI(data); found {
			return SplitAt(data, offset)
		}
		return SplitAt(data, len(data)/2)
	case FragmentStrategySniSplit:
		if offset, length, found := LocateSNI(data); found {
			mid := length / 2
			if mid < 1 {
				mid = 1
			}
			return SplitAt(data, offset+mid)
		}
		return SplitAt(data, len(data)/2)
	case FragmentStrategyTlsRecordFrag:
		return SplitTlsRecord(data, false)
	case FragmentStrategyTlsSniRecords:
		return SplitTlsRecord(data, true)
	case FragmentStrategyHalf:
		return SplitAt(data, len(data)/2)
	case FragmentStrategyRaw:
		fallthrough
	default:
		return [][]byte{data}
	}
}

// CarrierEdgeProfile encapsulates edge routing node coordinates and split thresholds.
type CarrierEdgeProfile struct {
	Address           string
	Port              int
	Role              string
	FinalmaskMaxSplit int
}

// CarrierRouteSelector provides stateful health tracking, failure cooldown, and priority ordering across edges.
type CarrierRouteSelector struct {
	mu               sync.RWMutex
	cooldownDuration time.Duration
	failedUntil      map[string]time.Time
}

// NewCarrierRouteSelector constructs a route selector with the given failure cooldown duration.
func NewCarrierRouteSelector(cooldown time.Duration) *CarrierRouteSelector {
	return &CarrierRouteSelector{
		cooldownDuration: cooldown,
		failedUntil:      make(map[string]time.Time),
	}
}

// DefaultMciRouteSelector constructs a carrier selector matching MCI defaults (12s cooldown).
func DefaultMciRouteSelector() *CarrierRouteSelector {
	return NewCarrierRouteSelector(12 * time.Second)
}

// OrderedEdges returns a copy of edges with healthy nodes first, followed by nodes in cooldown.
func (s *CarrierRouteSelector) OrderedEdges(edges []CarrierEdgeProfile) []CarrierEdgeProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	var healthy []CarrierEdgeProfile
	var coolingDown []CarrierEdgeProfile

	for _, edge := range edges {
		if until, ok := s.failedUntil[edge.Address]; ok && until.After(now) {
			coolingDown = append(coolingDown, edge)
			continue
		}
		healthy = append(healthy, edge)
	}

	return append(healthy, coolingDown...)
}

// RecordFailure flags an edge as failed and triggers its cooldown timer.
func (s *CarrierRouteSelector) RecordFailure(edge CarrierEdgeProfile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failedUntil[edge.Address] = time.Now().Add(s.cooldownDuration)
}

// RecordSuccess clears any failure cooldown for the given edge.
func (s *CarrierRouteSelector) RecordSuccess(edge CarrierEdgeProfile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failedUntil, edge.Address)
}

// IsInCooldown checks whether an edge node is currently cooling down.
func (s *CarrierRouteSelector) IsInCooldown(edge CarrierEdgeProfile) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if until, ok := s.failedUntil[edge.Address]; ok {
		return until.After(time.Now())
	}
	return false
}
