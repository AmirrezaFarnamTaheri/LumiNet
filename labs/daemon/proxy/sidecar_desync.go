// Package proxy implements proxy server handlers and protocol parsers.
// Ported from: MaybeEdgeScanner (go-sidecar/sidecar_desync.go)
// Target path: server/internal/proxy/sidecar_desync.go

package proxy

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"
)

// TlsRecordStats logs stats for outbound TLS records and SNIs.
type TlsRecordStats struct {
	TotalBytes     int64     `json:"total_bytes"`
	RecordCount    int64     `json:"record_count"`
	SniFoundCount  int64     `json:"sni_found_count"`
	FragmentsCount int64     `json:"fragments_count"`
	LastSniSeen    string    `json:"last_sni_seen"`
	LastRecordTime time.Time `json:"last_record_time"`
}

// Getters & Setters for TlsRecordStats
func (s *TlsRecordStats) GetTotalBytes() int64          { return atomic.LoadInt64(&s.TotalBytes) }
func (s *TlsRecordStats) SetTotalBytes(v int64)         { atomic.StoreInt64(&s.TotalBytes, v) }
func (s *TlsRecordStats) GetRecordCount() int64         { return atomic.LoadInt64(&s.RecordCount) }
func (s *TlsRecordStats) SetRecordCount(v int64)        { atomic.StoreInt64(&s.RecordCount, v) }
func (s *TlsRecordStats) GetSniFoundCount() int64       { return atomic.LoadInt64(&s.SniFoundCount) }
func (s *TlsRecordStats) SetSniFoundCount(v int64)      { atomic.StoreInt64(&s.SniFoundCount, v) }
func (s *TlsRecordStats) GetFragmentsCount() int64      { return atomic.LoadInt64(&s.FragmentsCount) }
func (s *TlsRecordStats) SetFragmentsCount(v int64)     { atomic.StoreInt64(&s.FragmentsCount, v) }
func (s *TlsRecordStats) GetLastSniSeen() string        { return s.LastSniSeen }
func (s *TlsRecordStats) SetLastSniSeen(v string)       { s.LastSniSeen = v }
func (s *TlsRecordStats) GetLastRecordTime() time.Time  { return s.LastRecordTime }
func (s *TlsRecordStats) SetLastRecordTime(v time.Time) { s.LastRecordTime = v }

// Builders for TlsRecordStats
func (s *TlsRecordStats) WithTotalBytes(v int64) *TlsRecordStats    { s.SetTotalBytes(v); return s }
func (s *TlsRecordStats) WithRecordCount(v int64) *TlsRecordStats   { s.SetRecordCount(v); return s }
func (s *TlsRecordStats) WithSniFoundCount(v int64) *TlsRecordStats { s.SetSniFoundCount(v); return s }
func (s *TlsRecordStats) WithFragmentsCount(v int64) *TlsRecordStats {
	s.SetFragmentsCount(v)
	return s
}
func (s *TlsRecordStats) WithLastSniSeen(v string) *TlsRecordStats { s.SetLastSniSeen(v); return s }
func (s *TlsRecordStats) WithLastRecordTime(v time.Time) *TlsRecordStats {
	s.SetLastRecordTime(v)
	return s
}

// DesyncConfig configures packet desynchronization parameters.
type DesyncConfig struct {
	mu                 sync.RWMutex
	BypassMode         string
	SniChunkSize       int
	FragmentPayload    bool
	WrongChecksumValue uint32
	FakeSeqOffset      int64
	ActiveEvasion      bool
	MinPacketSize      int
	DelayMs            int
	TargetHost         string
	IsActive           bool
}

// Getters & Setters for DesyncConfig
func (c *DesyncConfig) GetBypassMode() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.BypassMode
}
func (c *DesyncConfig) SetBypassMode(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.BypassMode = v }
func (c *DesyncConfig) GetSniChunkSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.SniChunkSize
}
func (c *DesyncConfig) SetSniChunkSize(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.SniChunkSize = v }
func (c *DesyncConfig) GetFragmentPayload() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.FragmentPayload
}
func (c *DesyncConfig) SetFragmentPayload(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.FragmentPayload = v
}
func (c *DesyncConfig) GetWrongChecksumValue() uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.WrongChecksumValue
}
func (c *DesyncConfig) SetWrongChecksumValue(v uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.WrongChecksumValue = v
}
func (c *DesyncConfig) GetFakeSeqOffset() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.FakeSeqOffset
}
func (c *DesyncConfig) SetFakeSeqOffset(v int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.FakeSeqOffset = v
}
func (c *DesyncConfig) GetActiveEvasion() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ActiveEvasion
}
func (c *DesyncConfig) SetActiveEvasion(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ActiveEvasion = v
}
func (c *DesyncConfig) GetMinPacketSize() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.MinPacketSize
}
func (c *DesyncConfig) SetMinPacketSize(v int) { c.mu.Lock(); defer c.mu.Unlock(); c.MinPacketSize = v }
func (c *DesyncConfig) GetDelayMs() int        { c.mu.RLock(); defer c.mu.RUnlock(); return c.DelayMs }
func (c *DesyncConfig) SetDelayMs(v int)       { c.mu.Lock(); defer c.mu.Unlock(); c.DelayMs = v }
func (c *DesyncConfig) GetTargetHost() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.TargetHost
}
func (c *DesyncConfig) SetTargetHost(v string) { c.mu.Lock(); defer c.mu.Unlock(); c.TargetHost = v }
func (c *DesyncConfig) GetIsActive() bool      { c.mu.RLock(); defer c.mu.RUnlock(); return c.IsActive }
func (c *DesyncConfig) SetIsActive(v bool)     { c.mu.Lock(); defer c.mu.Unlock(); c.IsActive = v }

// Builders for DesyncConfig
func (c *DesyncConfig) WithBypassMode(v string) *DesyncConfig    { c.SetBypassMode(v); return c }
func (c *DesyncConfig) WithSniChunkSize(v int) *DesyncConfig     { c.SetSniChunkSize(v); return c }
func (c *DesyncConfig) WithFragmentPayload(v bool) *DesyncConfig { c.SetFragmentPayload(v); return c }
func (c *DesyncConfig) WithActiveEvasion(v bool) *DesyncConfig   { c.SetActiveEvasion(v); return c }
func (c *DesyncConfig) WithMinPacketSize(v int) *DesyncConfig    { c.SetMinPacketSize(v); return c }
func (c *DesyncConfig) WithDelayMs(v int) *DesyncConfig          { c.SetDelayMs(v); return c }
func (c *DesyncConfig) WithTargetHost(v string) *DesyncConfig    { c.SetTargetHost(v); return c }
func (c *DesyncConfig) WithIsActive(v bool) *DesyncConfig        { c.SetIsActive(v); return c }

// Operations
func NewDesyncConfig() *DesyncConfig {
	return &DesyncConfig{
		BypassMode:    "wrong_checksum",
		SniChunkSize:  2,
		ActiveEvasion: true,
		MinPacketSize: 10,
		IsActive:      true,
	}
}

func (c *DesyncConfig) IsClientHello(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01
}

func (c *DesyncConfig) FindSNI(rec []byte) (start, end int, host string, ok bool) {
	if !c.IsClientHello(rec) {
		return 0, 0, "", false
	}
	p := 5 + 4
	if p+2+32 > len(rec) {
		return 0, 0, "", false
	}
	p += 2 + 32
	if p >= len(rec) {
		return 0, 0, "", false
	}
	sid := int(rec[p])
	p += 1 + sid
	if p+2 > len(rec) {
		return 0, 0, "", false
	}
	cs := int(binary.BigEndian.Uint16(rec[p:]))
	p += 2 + cs
	if p >= len(rec) {
		return 0, 0, "", false
	}
	comp := int(rec[p])
	p += 1 + comp
	if p+2 > len(rec) {
		return 0, 0, "", false
	}
	extTotal := int(binary.BigEndian.Uint16(rec[p:]))
	p += 2
	extEnd := p + extTotal
	if extEnd > len(rec) {
		extEnd = len(rec)
	}
	for p+4 <= extEnd {
		etype := binary.BigEndian.Uint16(rec[p:])
		elen := int(binary.BigEndian.Uint16(rec[p+2:]))
		body := p + 4
		if body+elen > len(rec) {
			return 0, 0, "", false
		}
		if etype == 0x0000 { // server_name
			q := body
			if q+2 > len(rec) {
				return 0, 0, "", false
			}
			q += 2
			if q+3 > len(rec) {
				return 0, 0, "", false
			}
			nlen := int(binary.BigEndian.Uint16(rec[q+1:]))
			ns := q + 3
			ne := ns + nlen
			if ne > len(rec) {
				return 0, 0, "", false
			}
			return ns, ne, string(rec[ns:ne]), true
		}
		p = body + elen
	}
	return 0, 0, "", false
}

func (c *DesyncConfig) FragmentWrites(rec []byte) [][]byte {
	s, e, _, ok := c.FindSNI(rec)
	if !ok {
		if len(rec) < 2 {
			return [][]byte{rec}
		}
		mid := len(rec) / 2
		return [][]byte{rec[:mid], rec[mid:]}
	}

	chunks := [][]byte{}
	chunks = append(chunks, rec[:s])

	chunkSize := c.GetSniChunkSize()
	if chunkSize <= 0 {
		chunks = append(chunks, rec[s:e])
	} else {
		for i := s; i < e; i += chunkSize {
			end := i + chunkSize
			if end > e {
				end = e
			}
			chunks = append(chunks, rec[i:end])
		}
	}

	chunks = append(chunks, rec[e:])
	return chunks
}

func (c *DesyncConfig) CorruptChecksum(packet []byte) []byte {
	if len(packet) < 20 {
		return packet
	}
	binary.BigEndian.PutUint16(packet[16:], uint16(c.GetWrongChecksumValue()))
	return packet
}

func (c *DesyncConfig) ApplyFakeSeq(packet []byte) []byte {
	if len(packet) < 8 {
		return packet
	}
	seq := binary.BigEndian.Uint32(packet[4:])
	binary.BigEndian.PutUint32(packet[4:], uint32(int64(seq)+c.GetFakeSeqOffset()))
	return packet
}

func (c *DesyncConfig) ProcessOutboundPacket(packet []byte) []byte {
	if !c.GetIsActive() || !c.GetActiveEvasion() {
		return packet
	}
	if c.GetBypassMode() == "wrong_checksum" {
		return c.CorruptChecksum(packet)
	}
	if c.GetBypassMode() == "wrong_seq" {
		return c.ApplyFakeSeq(packet)
	}
	return packet
}

func (c *DesyncConfig) ValidatePacket(packet []byte) bool {
	return len(packet) >= c.GetMinPacketSize()
}

func (c *DesyncConfig) GetStatusMessage() string {
	if c.GetIsActive() {
		return "Desynchronization evasion is active using mode: " + c.GetBypassMode()
	}
	return "Desynchronization evasion is inactive"
}

func (c *DesyncConfig) ResetEvasion() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.BypassMode = "none"
	c.SniChunkSize = 0
	c.ActiveEvasion = false
}

func GenerateRandomPayload(size int) []byte {
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	return buf
}
