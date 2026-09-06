package proxy

import (
	"bytes"
	"math/rand"
	"strings"
)

type DPIDesyncMode string

const (
	DesyncSplit DPIDesyncMode = "split"
)

type DPIDesyncConfig struct {
	Enabled        bool
	Mode           DPIDesyncMode
	SplitPosition  int
	HTTPCaseRandom bool
}

type DPIDesyncEngine struct {
	cfg DPIDesyncConfig
}

func NewDPIDesyncEngine(cfg DPIDesyncConfig) *DPIDesyncEngine {
	return &DPIDesyncEngine{cfg: cfg}
}

// DesyncHTTP mutates HTTP request headers or splits HTTP payloads to evade middleboxes.
func (e *DPIDesyncEngine) DesyncHTTP(payload []byte) [][]byte {
	if !e.cfg.Enabled {
		return [][]byte{payload}
	}

	mutated := make([]byte, len(payload))
	copy(mutated, payload)

	// Apply HTTP case randomization
	if e.cfg.HTTPCaseRandom && bytes.HasPrefix(mutated, []byte("GET ")) {
		for i := 0; i < 3; i++ {
			if rand.Float32() > 0.5 {
				mutated[i] = byte(strings.ToUpper(string(mutated[i]))[0])
			} else {
				mutated[i] = byte(strings.ToLower(string(mutated[i]))[0])
			}
		}
	}

	// Apply packet splitting
	if e.cfg.Mode == DesyncSplit && e.cfg.SplitPosition > 0 && len(mutated) > e.cfg.SplitPosition {
		return [][]byte{
			mutated[:e.cfg.SplitPosition],
			mutated[e.cfg.SplitPosition:],
		}
	}

	return [][]byte{mutated}
}
