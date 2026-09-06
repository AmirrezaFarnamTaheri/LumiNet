// Package reliable provides a deterministic, transport-neutral ARQ reducer.
package reliable

import (
	"sync"
	"time"
)

type Kind uint8

const (
	Data Kind = iota + 1
	Ack
	Nack
)

type Frame struct {
	Kind    Kind
	Seq     uint16
	Payload []byte
}
type Delivery struct {
	Seq     uint16
	Payload []byte
}
type Op uint8

const (
	Send Op = iota + 1
	Receive
	Tick
	Stop
)

type Command struct {
	Op      Op
	Payload []byte
	Frame   Frame
	Now     time.Time
}
type Status uint8

const (
	Accepted Status = iota
	WouldBlock
	Closed
	Ignored
	Stopped
)

type Result struct {
	Outbound       []Frame
	Delivered      []Delivery
	Status         Status
	Pending        int
	FastRetransmit bool
}
type Config struct {
	InitialSeq                           uint16
	Window, SendLimit                    int
	MinRTO, MaxRTO                       time.Duration
	MaxRetries                           int
	PacketTTL                            time.Duration
	Backoff                              float64
	NackInitialDelay, NackRepeatInterval time.Duration
	CloseOnExhaustion, ManualDispatch    bool
}

// DirectProfile preserves the eager, blocking ARQ behaviour used by direct packet links.
func DirectProfile(window int, minRTO, maxRTO time.Duration, retries int) Config {
	return Config{InitialSeq: 1, Window: window, MinRTO: minRTO, MaxRTO: maxRTO, MaxRetries: retries, CloseOnExhaustion: true}
}

// DNSProfile preserves DNS tunnelling's manual dispatch, bounded send window,
// TTL eviction, and NACK backoff behaviour.
func DNSProfile(window, sendLimit int, minRTO, maxRTO time.Duration, retries int, ttl, nackDelay, nackRepeat time.Duration) Config {
	return Config{InitialSeq: 0, Window: window, SendLimit: sendLimit, MinRTO: minRTO, MaxRTO: maxRTO, MaxRetries: retries, PacketTTL: ttl, Backoff: 1.35, NackInitialDelay: nackDelay, NackRepeatInterval: nackRepeat, ManualDispatch: true}
}

type Stats struct {
	Pending        int
	Closed         bool
	RTO            time.Duration
	RTOInitialized bool
	LastActivity   time.Time
}
type item struct {
	data                       []byte
	created, sent              time.Time
	dispatched, sampleEligible bool
	retries                    int
	rto                        time.Duration
}
type Stream struct {
	mu                  sync.Mutex
	cfg                 Config
	sndNxt, rcvNxt      uint16
	snd                 map[uint16]*item
	rcv                 map[uint16][]byte
	firstNack, lastNack map[uint16]time.Time
	srtt, rttvar, base  time.Duration
	initialized, closed bool
	lastActivity        time.Time
}

func New(cfg Config) *Stream {
	if cfg.Window <= 0 {
		cfg.Window = 128
	}
	if cfg.SendLimit <= 0 || cfg.SendLimit > cfg.Window {
		cfg.SendLimit = cfg.Window
	}
	if cfg.MinRTO <= 0 {
		cfg.MinRTO = 300 * time.Millisecond
	}
	if cfg.MaxRTO <= 0 {
		cfg.MaxRTO = 5 * time.Second
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 30
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = 1
	}
	return &Stream{cfg: cfg, sndNxt: cfg.InitialSeq, rcvNxt: cfg.InitialSeq, snd: map[uint16]*item{}, rcv: map[uint16][]byte{}, firstNack: map[uint16]time.Time{}, lastNack: map[uint16]time.Time{}, lastActivity: time.Now()}
}
func (s *Stream) Step(c Command) Result {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := c.Now
	if now.IsZero() {
		now = time.Now()
	}
	r := Result{Status: Accepted}
	if s.closed && c.Op != Stop {
		r.Status = Closed
		return r
	}
	switch c.Op {
	case Send:
		if len(s.snd) >= s.cfg.SendLimit {
			r.Status = WouldBlock
			break
		}
		seq := s.sndNxt
		s.sndNxt++
		p := append([]byte(nil), c.Payload...)
		s.snd[seq] = &item{data: p, created: now, rto: s.currentRTO(), sampleEligible: true}
		if !s.cfg.ManualDispatch {
			r.Outbound = append(r.Outbound, Frame{Kind: Data, Seq: seq, Payload: append([]byte(nil), p...)})
			s.snd[seq].sent = now
			s.snd[seq].dispatched = true
		}
		s.lastActivity = now
	case Receive:
		s.receive(c.Frame, now, &r)
	case Tick:
		s.tick(now, &r)
	case Stop:
		if !s.closed {
			s.closed = true
		}
		r.Status = Stopped
	}
	r.Pending = len(s.snd)
	return r
}
func (s *Stream) receive(f Frame, now time.Time, r *Result) {
	switch f.Kind {
	case Ack:
		if it, ok := s.snd[f.Seq]; ok {
			if it.sampleEligible && !it.sent.IsZero() {
				s.updateRTO(now.Sub(it.sent))
			}
			delete(s.snd, f.Seq)
			s.lastActivity = now
		} else {
			r.Status = Ignored
		}
	case Nack:
		if _, seen := s.firstNack[f.Seq]; !seen {
			s.firstNack[f.Seq] = now
		}
		if now.Sub(s.firstNack[f.Seq]) < s.cfg.NackInitialDelay || (!s.lastNack[f.Seq].IsZero() && now.Sub(s.lastNack[f.Seq]) < s.cfg.NackRepeatInterval) {
			r.Status = Ignored
			return
		}
		s.lastNack[f.Seq] = now
		r.FastRetransmit = true
		it, ok := s.snd[f.Seq]
		if !ok {
			return
		}
		it.sent = now
		it.sampleEligible = false
		r.Outbound = append(r.Outbound, Frame{Kind: Data, Seq: f.Seq, Payload: append([]byte(nil), it.data...)})
	case Data:
		d := seqDistance(s.rcvNxt, f.Seq)
		if d < 0 || d >= s.cfg.Window {
			r.Status = Ignored
			r.Outbound = append(r.Outbound, Frame{Kind: Ack, Seq: f.Seq})
			return
		}
		r.Outbound = append(r.Outbound, Frame{Kind: Ack, Seq: f.Seq})
		if _, dup := s.rcv[f.Seq]; dup {
			r.Status = Ignored
			return
		}
		s.rcv[f.Seq] = append([]byte(nil), f.Payload...)
		for {
			p, ok := s.rcv[s.rcvNxt]
			if !ok {
				break
			}
			delete(s.rcv, s.rcvNxt)
			r.Delivered = append(r.Delivered, Delivery{Seq: s.rcvNxt, Payload: append([]byte(nil), p...)})
			s.rcvNxt++
		}
		s.lastActivity = now
	}
}
func (s *Stream) tick(now time.Time, r *Result) {
	for seq, it := range s.snd {
		if !it.dispatched {
			it.dispatched = true
			it.sent = now
			r.Outbound = append(r.Outbound, Frame{Kind: Data, Seq: seq, Payload: append([]byte(nil), it.data...)})
			continue
		}
		if s.cfg.PacketTTL > 0 && now.Sub(it.created) > s.cfg.PacketTTL {
			delete(s.snd, seq)
			continue
		}
		if now.Sub(it.sent) < it.rto {
			continue
		}
		it.retries++
		if it.retries > s.cfg.MaxRetries {
			delete(s.snd, seq)
			if s.cfg.CloseOnExhaustion {
				s.closed = true
			}
			continue
		}
		it.rto = time.Duration(float64(it.rto) * s.cfg.Backoff)
		if it.rto > s.cfg.MaxRTO {
			it.rto = s.cfg.MaxRTO
		}
		it.sent = now
		it.sampleEligible = false
		r.Outbound = append(r.Outbound, Frame{Kind: Data, Seq: seq, Payload: append([]byte(nil), it.data...)})
	}
}
func (s *Stream) currentRTO() time.Duration {
	if s.initialized {
		return s.base
	}
	return s.cfg.MinRTO
}
func (s *Stream) updateRTO(sample time.Duration) {
	if sample < s.cfg.MinRTO {
		sample = s.cfg.MinRTO
	}
	if sample > s.cfg.MaxRTO {
		sample = s.cfg.MaxRTO
	}
	if !s.initialized {
		s.srtt = sample
		s.rttvar = sample / 2
		s.initialized = true
	} else {
		d := s.srtt - sample
		if d < 0 {
			d = -d
		}
		s.rttvar = (3*s.rttvar + d) / 4
		s.srtt = (7*s.srtt + sample) / 8
	}
	s.base = s.srtt + 4*s.rttvar
	if s.base < s.cfg.MinRTO {
		s.base = s.cfg.MinRTO
	}
	if s.base > s.cfg.MaxRTO {
		s.base = s.cfg.MaxRTO
	}
}
func (s *Stream) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{len(s.snd), s.closed, s.currentRTO(), s.initialized, s.lastActivity}
}
func seqDistance(from, to uint16) int { return int(int16(to - from)) }
