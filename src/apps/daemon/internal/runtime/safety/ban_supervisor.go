package safety

import (
	"sync"
)

type AccessDecision int

const (
	AccessAllowed AccessDecision = iota
	AccessThrottled
	AccessBanned
)

type clientRecord struct {
	failureCount    int
	tokens          float64
	lastAccessUnix  int64
	bannedUntilUnix int64
}

type ClientBanSupervisor struct {
	mu               sync.Mutex
	clients          map[string]*clientRecord
	maxFailures      int
	banDurationSecs  int64
	bucketCapacity   float64
	refillRatePerSec float64
}

func NewClientBanSupervisor(maxFailures int, banDurationSecs int64, capacity, refillRate float64) *ClientBanSupervisor {
	return &ClientBanSupervisor{
		clients:          make(map[string]*clientRecord),
		maxFailures:      maxFailures,
		banDurationSecs:  banDurationSecs,
		bucketCapacity:   capacity,
		refillRatePerSec: refillRate,
	}
}

func (s *ClientBanSupervisor) CheckAccess(ip string, nowUnix int64) (AccessDecision, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.clients[ip]
	if !ok {
		rec = &clientRecord{
			tokens:         s.bucketCapacity,
			lastAccessUnix: nowUnix,
		}
		s.clients[ip] = rec
	}

	if rec.bannedUntilUnix > nowUnix {
		return AccessBanned, rec.bannedUntilUnix - nowUnix
	}

	// Refill
	elapsed := float64(nowUnix - rec.lastAccessUnix)
	if elapsed > 0 {
		rec.tokens += elapsed * s.refillRatePerSec
		if rec.tokens > s.bucketCapacity {
			rec.tokens = s.bucketCapacity
		}
		rec.lastAccessUnix = nowUnix
	}

	if rec.tokens < 1.0 {
		return AccessThrottled, 0
	}

	rec.tokens -= 1.0
	return AccessAllowed, 0
}

func (s *ClientBanSupervisor) RecordAuthResult(ip string, success bool, nowUnix int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.clients[ip]
	if !ok {
		rec = &clientRecord{
			tokens:         s.bucketCapacity,
			lastAccessUnix: nowUnix,
		}
		s.clients[ip] = rec
	}

	if success {
		rec.failureCount = 0
	} else {
		rec.failureCount++
		if rec.failureCount >= s.maxFailures {
			rec.bannedUntilUnix = nowUnix + s.banDurationSecs
		}
	}
}

func (s *ClientBanSupervisor) Unban(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, ok := s.clients[ip]; ok {
		rec.bannedUntilUnix = 0
		rec.failureCount = 0
	}
}

func (s *ClientBanSupervisor) IsBanned(ip string, nowUnix int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, ok := s.clients[ip]; ok {
		return rec.bannedUntilUnix > nowUnix
	}
	return false
}
