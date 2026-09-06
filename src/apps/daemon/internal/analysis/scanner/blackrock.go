// Package scanner implements host and dns probing operations.

package scanner

import (
	"encoding/json"
	"errors"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// BlackRockStats logs shuffling statistics.
type BlackRockStats struct {
	Seed              uint64 `json:"seed"`
	Rounds            uint32 `json:"rounds"`
	MaxRange          uint64 `json:"max_range"`
	ElementsShuffled  uint64 `json:"elements_shuffled"`
	ElementsRemaining uint64 `json:"elements_remaining"`
	DurationMs        int64  `json:"duration_ms"`
}

// Getters & Setters for BlackRockStats
func (s *BlackRockStats) GetSeed() uint64 { return s.Seed }
func (s *BlackRockStats) SetSeed(v uint64) { s.Seed = v }
func (s *BlackRockStats) GetRounds() uint32 { return s.Rounds }
func (s *BlackRockStats) SetRounds(v uint32) { s.Rounds = v }
func (s *BlackRockStats) GetMaxRange() uint64 { return s.MaxRange }
func (s *BlackRockStats) SetMaxRange(v uint64) { s.MaxRange = v }
func (s *BlackRockStats) GetElementsShuffled() uint64 { return s.ElementsShuffled }
func (s *BlackRockStats) SetElementsShuffled(v uint64) { s.ElementsShuffled = v }
func (s *BlackRockStats) GetElementsRemaining() uint64 { return s.ElementsRemaining }
func (s *BlackRockStats) SetElementsRemaining(v uint64) { s.ElementsRemaining = v }
func (s *BlackRockStats) GetDurationMs() int64 { return s.DurationMs }
func (s *BlackRockStats) SetDurationMs(v int64) { s.DurationMs = v }

// Builders for BlackRockStats
func (s *BlackRockStats) WithSeed(v uint64) *BlackRockStats { s.SetSeed(v); return s }
func (s *BlackRockStats) WithRounds(v uint32) *BlackRockStats { s.SetRounds(v); return s }
func (s *BlackRockStats) WithMaxRange(v uint64) *BlackRockStats { s.SetMaxRange(v); return s }
func (s *BlackRockStats) WithElementsShuffled(v uint64) *BlackRockStats { s.SetElementsShuffled(v); return s }
func (s *BlackRockStats) WithElementsRemaining(v uint64) *BlackRockStats { s.SetElementsRemaining(v); return s }
func (s *BlackRockStats) WithDurationMs(v int64) *BlackRockStats { s.SetDurationMs(v); return s }

// BlackRock implements the generalized Feistel cipher.
type BlackRock struct {
	mu           sync.RWMutex
	Range        uint64
	A            uint64
	B            uint64
	Seed         uint64
	Rounds       uint32
	ABits        uint64
	AMask        uint64
	BBits        uint64
	BMask        uint64
	CurrentIndex uint64
	Status       string
}

// Getters & Setters for BlackRock
func (b *BlackRock) GetRange() uint64 { b.mu.RLock(); defer b.mu.RUnlock(); return b.Range }
func (b *BlackRock) SetRange(v uint64) { b.mu.Lock(); defer b.mu.Unlock(); b.Range = v }
func (b *BlackRock) GetA() uint64 { b.mu.RLock(); defer b.mu.RUnlock(); return b.A }
func (b *BlackRock) SetA(v uint64) { b.mu.Lock(); defer b.mu.Unlock(); b.A = v }
func (b *BlackRock) GetB() uint64 { b.mu.RLock(); defer b.mu.RUnlock(); return b.B }
func (b *BlackRock) SetB(v uint64) { b.mu.Lock(); defer b.mu.Unlock(); b.B = v }
func (b *BlackRock) GetSeed() uint64 { b.mu.RLock(); defer b.mu.RUnlock(); return b.Seed }
func (b *BlackRock) SetSeed(v uint64) { b.mu.Lock(); defer b.mu.Unlock(); b.Seed = v }
func (b *BlackRock) GetRounds() uint32 { b.mu.RLock(); defer b.mu.RUnlock(); return b.Rounds }
func (b *BlackRock) SetRounds(v uint32) { b.mu.Lock(); defer b.mu.Unlock(); b.Rounds = v }
func (b *BlackRock) GetABits() uint64 { b.mu.RLock(); defer b.mu.RUnlock(); return b.ABits }
func (b *BlackRock) SetABits(v uint64) { b.mu.Lock(); defer b.mu.Unlock(); b.ABits = v }
func (b *BlackRock) GetAMask() uint64 { b.mu.RLock(); defer b.mu.RUnlock(); return b.AMask }
func (b *BlackRock) SetAMask(v uint64) { b.mu.Lock(); defer b.mu.Unlock(); b.AMask = v }
func (b *BlackRock) GetBBits() uint64 { b.mu.RLock(); defer b.mu.RUnlock(); return b.BBits }
func (b *BlackRock) SetBBits(v uint64) { b.mu.Lock(); defer b.mu.Unlock(); b.BBits = v }
func (b *BlackRock) GetBMask() uint64 { b.mu.RLock(); defer b.mu.RUnlock(); return b.BMask }
func (b *BlackRock) SetBMask(v uint64) { b.mu.Lock(); defer b.mu.Unlock(); b.BMask = v }
func (b *BlackRock) GetCurrentIndex() uint64 { return atomic.LoadUint64(&b.CurrentIndex) }
func (b *BlackRock) SetCurrentIndex(v uint64) { atomic.StoreUint64(&b.CurrentIndex, v) }
func (b *BlackRock) GetStatus() string { b.mu.RLock(); defer b.mu.RUnlock(); return b.Status }
func (b *BlackRock) SetStatus(v string) { b.mu.Lock(); defer b.mu.Unlock(); b.Status = v }

// Builders for BlackRock
func (b *BlackRock) WithRange(v uint64) *BlackRock { b.SetRange(v); return b }
func (b *BlackRock) WithA(v uint64) *BlackRock { b.SetA(v); return b }
func (b *BlackRock) WithB(v uint64) *BlackRock { b.SetB(v); return b }
func (b *BlackRock) WithSeed(v uint64) *BlackRock { b.SetSeed(v); return b }
func (b *BlackRock) WithRounds(v uint32) *BlackRock { b.SetRounds(v); return b }
func (b *BlackRock) WithABits(v uint64) *BlackRock { b.SetABits(v); return b }
func (b *BlackRock) WithAMask(v uint64) *BlackRock { b.SetAMask(v); return b }
func (b *BlackRock) WithBBits(v uint64) *BlackRock { b.SetBBits(v); return b }
func (b *BlackRock) WithBMask(v uint64) *BlackRock { b.SetBMask(v); return b }
func (b *BlackRock) WithCurrentIndex(v uint64) *BlackRock { b.SetCurrentIndex(v); return b }
func (b *BlackRock) WithStatus(v string) *BlackRock { b.SetStatus(v); return b }

// Operations & Shuffling
func NewBlackRock(maxRange uint64, seed uint64, rounds uint32) *BlackRock {
	if maxRange == 0 {
		maxRange = 1000
	}
	b := &BlackRock{
		Range:  maxRange,
		Seed:   seed,
		Rounds: rounds,
		Status: "Initialized",
	}
	b.InitBlackRock()
	return b
}

func (b *BlackRock) InitBlackRock() {
	b.mu.Lock()
	defer b.mu.Unlock()

	rangeFloat := float64(b.Range)
	b.ABits = uint64(math.Ceil(math.Log2(math.Sqrt(rangeFloat))))
	b.A = 1 << b.ABits
	b.AMask = b.A - 1

	b.BBits = uint64(math.Ceil(math.Log2(rangeFloat / float64(b.A))))
	b.B = 1 << b.BBits
	b.BMask = b.B - 1

	for b.A*b.B < b.Range {
		b.BBits++
		b.B = 1 << b.BBits
		b.BMask = b.B - 1
	}
}

func (b *BlackRock) Shuffle(index uint64) uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Cycle(index, b.A, b.B, b.AMask, b.BMask, b.Rounds, b.Seed)
}

func (b *BlackRock) Unshuffle(index uint64) uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Cycle(index, b.B, b.A, b.BMask, b.AMask, b.Rounds, b.Seed)
}

func (b *BlackRock) Cycle(index uint64, rA, rB, maskA, maskB uint64, rounds uint32, seed uint64) uint64 {
	var L, R uint64

	L = index & maskA
	R = index >> b.ABits

	for round := uint32(0); round < rounds; round++ {
		var nextL, nextR uint64
		// Feistel round function
		h := b.RoundFunction(R, round, seed)
		if round&1 == 0 {
			nextL = (L + h) % rA
			nextR = R
		} else {
			nextL = L
			nextR = (R + h) % rB
		}
		L = nextR
		R = nextL
	}

	if rounds&1 == 0 {
		return (R << b.ABits) | L
	}
	return (L << b.ABits) | R
}

var sb1 = [64]uint32{
	0x01010400, 0x00000000, 0x00010000, 0x01010404,
	0x01010004, 0x00010404, 0x00000004, 0x00010000,
	0x00000400, 0x01010400, 0x01010404, 0x00000400,
	0x01000404, 0x01010004, 0x01000000, 0x00000004,
	0x00000404, 0x01000400, 0x01000400, 0x00010400,
	0x00010400, 0x01010000, 0x01010000, 0x01000404,
	0x00010004, 0x01000004, 0x01000004, 0x00010004,
	0x00000000, 0x00000404, 0x00010404, 0x01000000,
	0x00010000, 0x01010404, 0x00000004, 0x01010000,
	0x01010400, 0x01000000, 0x01000000, 0x00000400,
	0x01010004, 0x00010000, 0x00010400, 0x01000004,
	0x00000400, 0x00000004, 0x01000404, 0x00010404,
	0x01010404, 0x00010004, 0x01010000, 0x01000404,
	0x01000004, 0x00000404, 0x00010404, 0x01010400,
	0x00000404, 0x01000400, 0x01000400, 0x00000000,
	0x00010004, 0x00010400, 0x00000000, 0x01010004,
}

var sb2 = [64]uint32{
	0x80108020, 0x80008000, 0x00008000, 0x00108020,
	0x00100000, 0x00000020, 0x80100020, 0x80008020,
	0x80000020, 0x80108020, 0x80108000, 0x80000000,
	0x80008000, 0x00100000, 0x00000020, 0x80100020,
	0x00108000, 0x00100020, 0x80008020, 0x00000000,
	0x80000000, 0x00008000, 0x00108020, 0x80100000,
	0x00100020, 0x80000020, 0x00000000, 0x00108000,
	0x00008020, 0x80108000, 0x80100000, 0x00008020,
	0x00000000, 0x00108020, 0x80100020, 0x00100000,
	0x80008020, 0x80100000, 0x80108000, 0x00008000,
	0x80100000, 0x80008000, 0x00000020, 0x80108020,
	0x00108020, 0x00000020, 0x00008000, 0x80000000,
	0x00008020, 0x80108000, 0x00100000, 0x80000020,
	0x00100020, 0x80008020, 0x80000020, 0x00100020,
	0x00108000, 0x00000000, 0x80008000, 0x00008020,
	0x80000000, 0x80100020, 0x80108020, 0x00108000,
}

var sb3 = [64]uint32{
	0x00000208, 0x08020200, 0x00000000, 0x08020008,
	0x08000200, 0x00000000, 0x00020208, 0x08000200,
	0x00020008, 0x08000008, 0x08000008, 0x00020000,
	0x08020208, 0x00020008, 0x08020000, 0x00000208,
	0x08000000, 0x00000008, 0x08020200, 0x00000200,
	0x00020200, 0x08020000, 0x08020008, 0x00020208,
	0x08000208, 0x00020200, 0x00020000, 0x08000208,
	0x00000008, 0x08020208, 0x00000200, 0x08000000,
	0x08020200, 0x08000000, 0x00020008, 0x00000208,
	0x00020000, 0x08020200, 0x08000200, 0x00000000,
	0x00000200, 0x00020008, 0x08020208, 0x08000200,
	0x08000008, 0x00000200, 0x00000000, 0x08020008,
	0x08000208, 0x00020000, 0x08000000, 0x08020208,
	0x00000008, 0x00020208, 0x00020200, 0x08000008,
	0x08020000, 0x08000208, 0x00000208, 0x08020000,
	0x00020208, 0x00000008, 0x08020008, 0x00020200,
}

var sb4 = [64]uint32{
	0x00802001, 0x00002081, 0x00002081, 0x00000080,
	0x00802080, 0x00800081, 0x00800001, 0x00002001,
	0x00000000, 0x00802000, 0x00802000, 0x00802081,
	0x00000081, 0x00000000, 0x00800080, 0x00800001,
	0x00000001, 0x00002000, 0x00800000, 0x00802001,
	0x00000080, 0x00800000, 0x00002001, 0x00002080,
	0x00800081, 0x00000001, 0x00002080, 0x00800080,
	0x00002000, 0x00802080, 0x00802081, 0x00000081,
	0x00800080, 0x00800001, 0x00802000, 0x00802081,
	0x00000081, 0x00000000, 0x00000000, 0x00802000,
	0x00002080, 0x00800080, 0x00800081, 0x00000001,
	0x00802001, 0x00002081, 0x00002081, 0x00000080,
	0x00802081, 0x00000081, 0x00000001, 0x00002000,
	0x00800001, 0x00002001, 0x00802080, 0x00800081,
	0x00002001, 0x00002080, 0x00800000, 0x00802001,
	0x00000080, 0x00800000, 0x00002000, 0x00802080,
}

var sb5 = [68]uint32{
	0x00000100, 0x02080100, 0x02080000, 0x42000100,
	0x00080000, 0x00000100, 0x40000000, 0x02080000,
	0x40080100, 0x00080000, 0x02000100, 0x40080100,
	0x42000100, 0x42080000, 0x00080100, 0x40000000,
	0x42000100, 0x42080000, 0x00080100, 0x40000000,
	0x02000000, 0x40080000, 0x40080000, 0x00000000,
	0x40000100, 0x42080100, 0x42080100, 0x02000100,
	0x42080000, 0x40000100, 0x00000000, 0x42000000,
	0x02080100, 0x02000000, 0x42000000, 0x00080100,
	0x00080000, 0x42000100, 0x00000100, 0x02000000,
	0x40000000, 0x02080000, 0x42000100, 0x40080100,
	0x02000100, 0x40000000, 0x42080000, 0x02080100,
	0x40080100, 0x00000100, 0x02000000, 0x42080000,
	0x42080100, 0x00080100, 0x42000000, 0x42080100,
	0x02080000, 0x00000000, 0x40080000, 0x42000000,
	0x00080100, 0x02000100, 0x40000100, 0x00080000,
	0x00000000, 0x40080000, 0x02080100, 0x40000100,
}

var sb6 = [64]uint32{
	0x20000010, 0x20400000, 0x00004000, 0x20404010,
	0x20400000, 0x00000010, 0x20404010, 0x00400000,
	0x20004000, 0x00404010, 0x00400000, 0x20000010,
	0x00400010, 0x20004000, 0x20000000, 0x00004010,
	0x00000000, 0x00400010, 0x20004010, 0x00004000,
	0x00404000, 0x20004010, 0x00000010, 0x20400010,
	0x20400010, 0x00000000, 0x00404010, 0x20404000,
	0x00004010, 0x00404000, 0x20404000, 0x20000000,
	0x20004000, 0x00000010, 0x20400010, 0x00404000,
	0x20404010, 0x00400000, 0x00004010, 0x20000010,
	0x00400000, 0x20004000, 0x20000000, 0x00004010,
	0x20000010, 0x20404010, 0x00404000, 0x20400000,
	0x00404010, 0x20404000, 0x00000000, 0x20400010,
	0x00000010, 0x00004000, 0x20400000, 0x00404010,
	0x00004000, 0x00400010, 0x20004010, 0x00000000,
	0x20404000, 0x20000000, 0x00400010, 0x20004010,
}

var sb7 = [64]uint32{
	0x00200000, 0x04200002, 0x04000802, 0x00000000,
	0x00000800, 0x04000802, 0x00200802, 0x04200800,
	0x04200802, 0x00200000, 0x00000000, 0x04000002,
	0x00000002, 0x04000000, 0x04200002, 0x00000802,
	0x04000800, 0x00200802, 0x00200002, 0x04000800,
	0x04000002, 0x04200000, 0x04200800, 0x00200002,
	0x04200000, 0x00000800, 0x00000802, 0x04200802,
	0x00200800, 0x00000002, 0x04000000, 0x00200800,
	0x04000000, 0x00200800, 0x00200000, 0x04000802,
	0x04000802, 0x04200002, 0x04200002, 0x00000002,
	0x00200002, 0x04000000, 0x04000800, 0x00200000,
	0x04200800, 0x00000802, 0x00200802, 0x04200800,
	0x00000802, 0x04000002, 0x04200802, 0x04200000,
	0x00200800, 0x00000000, 0x00000002, 0x04200802,
	0x00000000, 0x00200802, 0x04200000, 0x00000800,
	0x04000002, 0x04000800, 0x00000800, 0x00200002,
}

var sb8 = [64]uint32{
	0x10001040, 0x00001000, 0x00040000, 0x10041040,
	0x10000000, 0x10001040, 0x00000040, 0x10000000,
	0x00040040, 0x10040000, 0x10041040, 0x00041000,
	0x10041000, 0x00041040, 0x00001000, 0x00000040,
	0x10040000, 0x10000040, 0x10001000, 0x00001040,
	0x00041000, 0x00040040, 0x10040040, 0x10041000,
	0x00001040, 0x00000000, 0x00000000, 0x10040040,
	0x10000040, 0x10001000, 0x00041040, 0x00040000,
	0x00041040, 0x00040000, 0x10041000, 0x00001000,
	0x00000040, 0x10040040, 0x00001000, 0x00041040,
	0x10001000, 0x00000040, 0x10000040, 0x10040000,
	0x10040040, 0x10000000, 0x00040000, 0x10001040,
	0x00000000, 0x10041040, 0x00040040, 0x10000040,
	0x10040000, 0x10001000, 0x10001040, 0x00000000,
	0x10041040, 0x00041000, 0x00041000, 0x00001040,
	0x00001040, 0x00040040, 0x10000000, 0x10041000,
}

func (b *BlackRock) RoundFunction(R uint64, round uint32, seed uint64) uint64 {
	T := R ^ ((seed >> round) | (seed << (64 - round)))
	var Y uint32
	if (round & 1) != 0 {
		Y = sb8[T&0x3F] ^ sb6[(T>>8)&0x3F] ^ sb4[(T>>16)&0x3F] ^ sb2[(T>>24)&0x3F]
	} else {
		Y = sb7[T&0x3F] ^ sb5[(T>>8)&0x3F] ^ sb3[(T>>16)&0x3F] ^ sb1[(T>>24)&0x3F]
	}
	return uint64(Y)
}

func (b *BlackRock) VerifyShuffler() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.Range > 0 && b.Rounds > 0
}

func (b *BlackRock) ResetShuffler() {
	b.SetCurrentIndex(0)
}

func (b *BlackRock) GetNextIndex() (uint64, error) {
	idx := atomic.AddUint64(&b.CurrentIndex, 1) - 1
	if idx >= b.GetRange() {
		return 0, errors.New("range limit reached")
	}
	return b.Shuffle(idx), nil
}

func (b *BlackRock) GetPreviousIndex() (uint64, error) {
	idx := atomic.LoadUint64(&b.CurrentIndex)
	if idx == 0 {
		return 0, errors.New("at start")
	}
	newIdx := atomic.AddUint64(&b.CurrentIndex, ^uint64(0))
	return b.Shuffle(newIdx), nil
}

func (b *BlackRock) GetRangeLimit() uint64 {
	return b.GetRange()
}

func (b *BlackRock) IsComplete() bool {
	return b.GetCurrentIndex() >= b.GetRange()
}

func (b *BlackRock) ExportParamsJSON() (string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	res, err := json.Marshal(b)
	return string(res), err
}

func (b *BlackRock) LoadParamsJSON(data string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return json.Unmarshal([]byte(data), b)
}

func (b *BlackRock) ValidateMasks() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return (b.AMask+1) == b.A && (b.BMask+1) == b.B
}

func GenerateSeed() uint64 {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	return r.Uint64()
}
