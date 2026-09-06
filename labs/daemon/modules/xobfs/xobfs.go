// Package xobfs provides lightweight UDP packet obfuscation and QUIC-aware
// fragmentation, transplanted from Xray-core's finalmask/salamander.
//
// Ported from:
//   - Xray-core transport/internet/finalmask/salamander/conn.go
//     (SalamanderObfuscator, geckoConn, reassembly, GC loop)
//   - Xray-core transport/internet/finalmask/finalmask.go
//     (UdpmaskManager, TcpmaskManager, headerManagerConn)
//
// Key micro-logic transplanted:
//   - BLAKE3/SHA-256-based per-packet salt obfuscation (salamander)
//   - QUIC long-header detection (0x80 bit) → gecko fragment/reassembly
//   - TTL-based reassembly GC with per-source cap (geckoMaxPerSource=8)
//   - Oldest-entry eviction at global cap (geckoMaxReassembly=4096)
//   - Random padding to [minPkt, maxPkt] range
//   - Layer-stacking via Tcpmask / Udpmask interfaces
package xobfs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ── Salamander Obfuscator ─────────────────────────────────────────────────────

const smSaltLen = 8

// Obfuscator applies deterministic per-packet XOR keying using a shared
// password, matching Xray's SalamanderObfuscator interface.
type Obfuscator struct {
	key []byte // SHA-256(password)
}

// NewObfuscator derives a key from password via SHA-256.
func NewObfuscator(password []byte) *Obfuscator {
	h := sha256.Sum256(password)
	return &Obfuscator{key: h[:]}
}

// Obfuscate writes an 8-byte salt prefix then XOR-encodes payload into dst.
// dst must be len(src)+smSaltLen bytes.
func (o *Obfuscator) Obfuscate(src, dst []byte) {
	if _, err := rand.Read(dst[:smSaltLen]); err != nil {
		panic("xobfs: crypto/rand failed")
	}
	ks := o.deriveKeystream(dst[:smSaltLen], len(src))
	for i, b := range src {
		dst[smSaltLen+i] = b ^ ks[i]
	}
}

// Deobfuscate reads a salt prefix and XOR-decodes the remainder into dst.
// src[:smSaltLen] is the salt; dst must be at least len(src)-smSaltLen bytes.
func (o *Obfuscator) Deobfuscate(src, dst []byte) {
	if len(src) < smSaltLen {
		return
	}
	ks := o.deriveKeystream(src[:smSaltLen], len(src)-smSaltLen)
	for i, b := range src[smSaltLen:] {
		dst[i] = b ^ ks[i]
	}
}

// deriveKeystream generates n bytes of keystream for the given salt.
func (o *Obfuscator) deriveKeystream(salt []byte, n int) []byte {
	h := sha256.New()
	h.Write(o.key)
	h.Write(salt)
	seed := h.Sum(nil)
	// Expand via counter-mode SHA-256
	out := make([]byte, 0, n)
	for counter := uint32(0); len(out) < n; counter++ {
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], counter)
		block := sha256.Sum256(append(seed, ctr[:]...))
		out = append(out, block[:]...)
	}
	return out[:n]
}

// ── Gecko Conn ────────────────────────────────────────────────────────────────
// Gecko fragments QUIC long-header packets and reassembles them on the other
// side, with per-source caps and TTL-based GC.

const (
	geckoReassemblyTTL       = 8 * time.Second
	geckoMaxReassembly       = 4096
	geckoMaxPerSource        = 8
	geckoBufferSize          = 2048
	geckoDefaultMinPacket    = 512
	geckoDefaultMaxPacket    = 1200
	geckoMinFragmentChunks   = 2
	geckoMaxFragmentChunks   = 4
	geckoHeaderSize          = 4 // msgID(1) + chunkIdx(1) + totalChunks(1) + padLen(1)
)

// GeckoConfig configures the gecko fragmentation layer.
type GeckoConfig struct {
	Password      string
	MinPacketSize int32
	MaxPacketSize int32
}

type reassemblyKey struct {
	addr  string
	msgID uint8
}

type reassemblyEntry struct {
	chunks   [][]byte
	received int
	total    uint8
	deadline time.Time
}

type frameHeader struct {
	padLen      uint8
	msgID       uint8
	chunkIdx    uint8
	totalChunks uint8
}

// GeckoConn implements net.PacketConn with salamander obfuscation and
// QUIC-long-header fragmentation/reassembly.
type GeckoConn struct {
	net.PacketConn
	obfs           *Obfuscator
	minPkt, maxPkt int

	msgID atomic.Uint32

	mu         sync.Mutex
	reassembly map[reassemblyKey]*reassemblyEntry
	perSource  map[string]int

	closeCh   chan struct{}
	closeOnce sync.Once
}

// NewGeckoConn wraps a raw PacketConn with gecko obfuscation.
func NewGeckoConn(cfg GeckoConfig, raw net.PacketConn) (*GeckoConn, error) {
	minPkt, maxPkt := int(cfg.MinPacketSize), int(cfg.MaxPacketSize)
	if minPkt == 0 {
		minPkt = geckoDefaultMinPacket
	}
	if maxPkt == 0 {
		maxPkt = geckoDefaultMaxPacket
	}
	if minPkt <= 0 || minPkt > maxPkt || maxPkt > geckoBufferSize {
		return nil, errors.New("xobfs: gecko invalid min/max packet size")
	}
	g := &GeckoConn{
		PacketConn: raw,
		obfs:       NewObfuscator([]byte(cfg.Password)),
		minPkt:     minPkt,
		maxPkt:     maxPkt,
		reassembly: make(map[reassemblyKey]*reassemblyEntry),
		perSource:  make(map[string]int),
		closeCh:    make(chan struct{}),
	}
	go g.gcLoop()
	return g, nil
}

// WriteTo obfuscates and optionally fragments before sending.
func (g *GeckoConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if p[0]&0x80 != 0 {
		// QUIC long header → fragment
		return g.writeFragmented(p, addr)
	}
	return g.writeObfs(p, addr)
}

func (g *GeckoConn) writeObfs(p []byte, addr net.Addr) (int, error) {
	buf := make([]byte, smSaltLen+len(p))
	g.obfs.Obfuscate(p, buf)
	return g.PacketConn.WriteTo(buf, addr)
}

func (g *GeckoConn) writeFragmented(p []byte, addr net.Addr) (int, error) {
	chunks := geckoMinFragmentChunks + randN(geckoMaxFragmentChunks-geckoMinFragmentChunks+1)
	chunkSize := len(p) / chunks
	msgID := uint8(g.msgID.Add(1))
	for i := 0; i < chunks; i++ {
		start := i * chunkSize
		end := len(p)
		if i < chunks-1 {
			end = start + chunkSize
		}
		chunk := p[start:end]
		padLen := g.randomPadLen(len(chunk))
		frame := make([]byte, geckoHeaderSize+int(padLen)+len(chunk))
		encodeFrame(frameHeader{
			padLen:      padLen,
			msgID:       msgID,
			chunkIdx:    uint8(i),
			totalChunks: uint8(chunks),
		}, chunk, frame)
		if _, err := g.writeObfs(frame, addr); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (g *GeckoConn) randomPadLen(chunkLen int) uint8 {
	base := smSaltLen + geckoHeaderSize + chunkLen
	lo := g.minPkt
	if lo < base {
		lo = base
	}
	if lo > g.maxPkt {
		return 0
	}
	return uint8(lo - base + randN(g.maxPkt-lo+1))
}

// ReadFrom deobfuscates, then either returns short-header packets directly
// or accumulates gecko fragments until a message is complete.
func (g *GeckoConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, geckoBufferSize)
	for {
		n, addr, err := g.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n < smSaltLen {
			continue
		}
		g.obfs.Deobfuscate(buf[:n], buf)
		payload := buf[:n-smSaltLen]

		if len(payload) == 0 || payload[0]&0x80 == 0 {
			// Short header or empty; pass through
			return copy(p, payload), addr, nil
		}
		h, data, err := decodeFrame(payload)
		if err != nil {
			continue
		}
		out, ready := g.acceptChunk(addr, h, data)
		if !ready {
			continue
		}
		return copy(p, out), addr, nil
	}
}

func (g *GeckoConn) acceptChunk(addr net.Addr, h frameHeader, payload []byte) ([]byte, bool) {
	key := reassemblyKey{addr: addr.String(), msgID: h.msgID}
	g.mu.Lock()
	defer g.mu.Unlock()

	e, exists := g.reassembly[key]
	if !exists {
		if g.perSource[key.addr] >= geckoMaxPerSource {
			return nil, false
		}
		if len(g.reassembly) >= geckoMaxReassembly {
			g.evictOldestLocked()
		}
		e = &reassemblyEntry{
			chunks:   make([][]byte, h.totalChunks),
			total:    h.totalChunks,
			deadline: time.Now().Add(geckoReassemblyTTL),
		}
		g.reassembly[key] = e
		g.perSource[key.addr]++
	} else if e.total != h.totalChunks {
		return nil, false
	}
	if int(h.chunkIdx) >= len(e.chunks) || e.chunks[h.chunkIdx] != nil {
		return nil, false
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	e.chunks[h.chunkIdx] = cp
	e.received++
	if e.received < int(e.total) {
		return nil, false
	}
	total := 0
	for _, c := range e.chunks {
		total += len(c)
	}
	out := make([]byte, total)
	off := 0
	for _, c := range e.chunks {
		off += copy(out[off:], c)
	}
	g.dropEntryLocked(key)
	return out, true
}

func (g *GeckoConn) gcLoop() {
	t := time.NewTicker(geckoReassemblyTTL / 2)
	defer t.Stop()
	for {
		select {
		case <-g.closeCh:
			return
		case now := <-t.C:
			g.gcExpired(now)
		}
	}
}

func (g *GeckoConn) gcExpired(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, e := range g.reassembly {
		if now.After(e.deadline) {
			g.dropEntryLocked(k)
		}
	}
}

func (g *GeckoConn) dropEntryLocked(k reassemblyKey) {
	if _, ok := g.reassembly[k]; !ok {
		return
	}
	delete(g.reassembly, k)
	g.perSource[k.addr]--
	if g.perSource[k.addr] <= 0 {
		delete(g.perSource, k.addr)
	}
}

func (g *GeckoConn) evictOldestLocked() {
	var oldestKey reassemblyKey
	var oldestDeadline time.Time
	first := true
	for k, e := range g.reassembly {
		if first || e.deadline.Before(oldestDeadline) {
			oldestKey = k
			oldestDeadline = e.deadline
			first = false
		}
	}
	if !first {
		g.dropEntryLocked(oldestKey)
	}
}

func (g *GeckoConn) Close() error {
	g.closeOnce.Do(func() { close(g.closeCh) })
	return g.PacketConn.Close()
}

// ── Frame encoding ─────────────────────────────────────────────────────────────

func encodeFrame(h frameHeader, payload, dst []byte) int {
	if len(dst) < geckoHeaderSize+int(h.padLen)+len(payload) {
		return 0
	}
	dst[0] = 0x80 | h.padLen // top bit always set to mark gecko frame
	dst[1] = h.msgID
	dst[2] = h.chunkIdx
	dst[3] = h.totalChunks
	// Random padding
	if h.padLen > 0 {
		_, _ = rand.Read(dst[geckoHeaderSize : geckoHeaderSize+int(h.padLen)])
	}
	n := copy(dst[geckoHeaderSize+int(h.padLen):], payload)
	return geckoHeaderSize + int(h.padLen) + n
}

func decodeFrame(p []byte) (frameHeader, []byte, error) {
	if len(p) < geckoHeaderSize {
		return frameHeader{}, nil, errors.New("xobfs: frame too short")
	}
	padLen := p[0] & 0x7F
	h := frameHeader{
		padLen:      padLen,
		msgID:       p[1],
		chunkIdx:    p[2],
		totalChunks: p[3],
	}
	if h.totalChunks == 0 {
		return frameHeader{}, nil, errors.New("xobfs: zero totalChunks")
	}
	offset := geckoHeaderSize + int(padLen)
	if offset > len(p) {
		return frameHeader{}, nil, errors.New("xobfs: pad overflows frame")
	}
	return h, p[offset:], nil
}

func randN(n int) int {
	if n <= 1 {
		return 0
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n))
}
