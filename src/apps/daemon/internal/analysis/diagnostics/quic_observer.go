// SPDX-License-Identifier: MIT
//
// Live QUIC observation service (roadmap item 3). Wraps ScanQuicInitial
// with a cheap byte-level prefilter so the FFI/native decrypt is only
// attempted for datagrams that look like QUIC Initial long headers.
// Intended to be attached to any UDP packet path (TUN adapter, proxy
// sniffers) via a non-blocking ObservePacket call.

package diagnostics

import (
	"encoding/binary"
	"net"
	"sync"
)

// QuicObserverService observes UDP datagrams and, for plausible QUIC
// Initials, runs the native scan and forwards completed client
// fingerprints to the registered callback. Safe for concurrent use.
type QuicObserverService struct {
	mu       sync.Mutex
	enabled  bool
	attempts uint64
	found    uint64
	failed   uint64
	onResult func(QuicScanResult)
}

// NewQuicObserverService creates an enabled observer. onResult (may be
// nil) receives each completed fingerprint.
func NewQuicObserverService(onResult func(QuicScanResult)) *QuicObserverService {
	return &QuicObserverService{enabled: true, onResult: onResult}
}

// SetEnabled toggles observation without dropping counters.
func (s *QuicObserverService) SetEnabled(v bool) {
	s.mu.Lock()
	s.enabled = v
	s.mu.Unlock()
}

// Counters returns the (attempts, found, failed) statistics snapshot.
func (s *QuicObserverService) Counters() (uint64, uint64, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts, s.found, s.failed
}

// looksLikeQuicInitial applies the cheap prefilter: QUIC long header
// (bit 7 set), version != 0 (Initial, not Version Negotiation), and a
// plausible minimum length (fixed header + at least one payload byte).
func looksLikeQuicInitial(payload []byte) bool {
	if len(payload) < 14 {
		return false
	}
	if payload[0]&0x80 == 0 {
		return false // short header
	}
	if binary.BigEndian.Uint32(payload[1:5]) == 0 {
		return false // version negotiation
	}
	return true
}

// ObservePacket inspects one datagram from the packet path. It never
// blocks on the caller beyond the (fast) native scan and never returns
// errors — failures are counted only. Safe to call for every datagram.
func (s *QuicObserverService) ObservePacket(src *net.UDPAddr, payload []byte) {
	s.mu.Lock()
	if !s.enabled {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	if !looksLikeQuicInitial(payload) {
		return
	}
	s.mu.Lock()
	s.attempts++
	s.mu.Unlock()

	res, err := ScanQuicInitial(src.String(), payload, false)
	s.mu.Lock()
	switch {
	case err != nil:
		s.failed++
	case res != nil:
		s.found++
	}
	s.mu.Unlock()

	if err == nil && res != nil && s.onResult != nil {
		s.onResult(*res)
	}
}
