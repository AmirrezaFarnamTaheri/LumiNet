// Censorship-event detector: a faithful Go port of the OONI backend
// moving-average blocking detector (backend-master/detector, GPL-3 upstream;
// algorithm re-expressed here, not copied verbatim).
//
// Semantics: each measurement carries a blocking score (anomaly → 0.8,
// confirmed → 2.0, clean → 0). Scores feed an exponential moving average per
// (probe_cc, test_name, input) key with p=0.02. State enters "blocked" when
// the mean crosses UpperLimit (0.10) and clears only below LowerLimit (0.05),
// giving hysteresis so single outliers do not flap state.
package diagnostics

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Detector tuning constants .py.
const (
	// ScoreUpperLimit is the mean above which a key becomes blocked.
	ScoreUpperLimit = 0.10
	// ScoreLowerLimit is the mean below which a blocked key clears.
	ScoreLowerLimit = 0.05
	// ScoreEMAAlpha is the EMA weight of each new measurement.
	ScoreEMAAlpha = 0.02
	// ScoreAnomaly is the score contribution of an unconfirmed anomaly.
	ScoreAnomaly = 0.8
	// ScoreConfirmed is the score contribution of a confirmed block.
	ScoreConfirmed = 2.0
)

// Measurement is one scored observation arriving from the pipeline.
type CensorshipMeasurement struct {
	ProbeCC  string    `json:"probe_cc"`
	TestName string    `json:"test_name"`
	Input    string    `json:"input"`
	TID      string    `json:"tid,omitempty"`
	ReportID string    `json:"report_id,omitempty"`
	StartAt  time.Time `json:"measurement_start_time"`
	Anomaly  bool      `json:"anomaly"`
	Confirmed bool     `json:"confirmed"`
}

// Score returns the blocking_general contribution of the measurement.
// Anomaly takes precedence over confirmed, matching backfill_scores.
func (m CensorshipMeasurement) Score() float64 {
	if m.Anomaly {
		return ScoreAnomaly
	}
	if m.Confirmed {
		return ScoreConfirmed
	}
	return 0
}

// BlockingChange is emitted when a key transitions between states.
type BlockingChange struct {
	Key        string    `json:"key"`
	ProbeCC    string    `json:"probe_cc"`
	TestName   string    `json:"test_name"`
	Input      string    `json:"input"`
	Blocked    bool      `json:"blocked"`
	Mean       float64   `json:"mean"`
	ObservedAt time.Time `json:"observed_at"`
}

type meanState struct {
	mean    float64
	blocked bool
	at      time.Time
}

// EventDetector maintains per-key EMA state and emits hysteresis-gated
// blocking changes. Safe for concurrent use.
type EventDetector struct {
	mu    sync.Mutex
	means map[string]meanState

	Warmup bool // suppress change emission while replaying history
}

// NewEventDetector builds an empty detector.
func NewEventDetector() *EventDetector {
	return &EventDetector{means: make(map[string]meanState)}
}

func measurementKey(m CensorshipMeasurement) (string, error) {
	if m.Input == "" {
		return "", fmt.Errorf("input is empty")
	}
	return m.ProbeCC + "|" + m.TestName + "|" + m.Input, nil
}

// Observe feeds one measurement and returns the transition it caused, if any.
// Keys with empty input are skipped (upstream TODO: list inputs).
func (d *EventDetector) Observe(m CensorshipMeasurement) (*BlockingChange, error) {
	key, err := measurementKey(m)
	if err != nil {
		return nil, err
	}
	score := m.Score()

	d.mu.Lock()
	defer d.mu.Unlock()
	state, seen := d.means[key]
	if !seen {
		blocked := score > ScoreUpperLimit
		d.means[key] = meanState{mean: score, blocked: blocked, at: m.StartAt}
		if !blocked || d.Warmup {
			return nil, nil
		}
		return &BlockingChange{Key: key, ProbeCC: m.ProbeCC, TestName: m.TestName,
			Input: m.Input, Blocked: true, Mean: score, ObservedAt: m.StartAt}, nil
	}
	newMean := (1-ScoreEMAAlpha)*state.mean + ScoreEMAAlpha*score
	updated := meanState{mean: newMean, blocked: state.blocked, at: m.StartAt}
	switch {
	case state.blocked && newMean < ScoreLowerLimit:
		updated.blocked = false
	case !state.blocked && newMean > ScoreUpperLimit:
		updated.blocked = true
	}
	d.means[key] = updated

	if updated.blocked == state.blocked || d.Warmup {
		return nil, nil
	}
	return &BlockingChange{Key: key, ProbeCC: m.ProbeCC, TestName: m.TestName,
		Input: m.Input, Blocked: updated.blocked, Mean: newMean, ObservedAt: m.StartAt}, nil
}

// Status reports current blocked/mean state for a key.
func (d *EventDetector) Status(probeCC, testName, input string) (mean float64, blocked bool, known bool) {
	key := probeCC + "|" + testName + "|" + input
	d.mu.Lock()
	defer d.mu.Unlock()
	state, ok := d.means[key]
	return state.mean, state.blocked, ok
}

type persistedMean struct {
	Mean    float64 `json:"mean"`
	Blocked bool    `json:"blocked"`
	At      time.Time `json:"at"`
}

// MarshalState serialises internal means for warm-restart persistence.
func (d *EventDetector) MarshalState() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]persistedMean, len(d.means))
	for key, st := range d.means {
		out[key] = persistedMean{Mean: st.mean, Blocked: st.blocked, At: st.at}
	}
	return json.Marshal(out)
}

// UnmarshalState restores persisted means (restart fast path).
func (d *EventDetector) UnmarshalState(data []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out map[string]persistedMean
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	means := make(map[string]meanState, len(out))
	for key, pm := range out {
		means[key] = meanState{mean: pm.Mean, blocked: pm.Blocked, at: pm.At}
	}
	d.means = means
	return nil
}
