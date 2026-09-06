package diagnostics

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

type WorkerObservation struct {
	ID       string `json:"id"`
	Healthy  bool   `json:"healthy"`
	Inflight int    `json:"inflight"`
	Capacity int    `json:"capacity"`
}

type WorkerAffinityPlanRequest struct {
	PoolSize              int                 `json:"pool_size"`
	AffinityKey           string              `json:"affinity_key"`
	Workers               []WorkerObservation `json:"workers"`
	HardDeadlineMS        int                 `json:"hard_deadline_ms,omitempty"`
	MaxRestarts           int                 `json:"max_restarts,omitempty"`
	MaxProtocolFrameBytes int                 `json:"max_protocol_frame_bytes,omitempty"`
	ReadyTimeoutMS        int                 `json:"ready_timeout_ms,omitempty"`
}

type WorkerAffinityPlan struct {
	PreferredWorker            string   `json:"preferred_worker,omitempty"`
	SelectedWorker             string   `json:"selected_worker,omitempty"`
	Spillover                  bool     `json:"spillover"`
	FailOpen                   bool     `json:"fail_open"`
	HardDeadlineMS             int      `json:"hard_deadline_ms"`
	RestartBackoffMS           []int    `json:"restart_backoff_ms"`
	StartsProcess              bool     `json:"starts_process"`
	Invariants                 []string `json:"invariants"`
	ProtocolFraming            string   `json:"protocol_framing"`
	ReadyHandshake             string   `json:"ready_handshake"`
	CorrelatesRequestIDs       bool     `json:"correlates_request_ids"`
	AffinityQueueDepth         int      `json:"affinity_queue_depth"`
	SharedQueueDepth           int      `json:"shared_queue_depth"`
	MaxProtocolFrameBytes      int      `json:"max_protocol_frame_bytes"`
	ReadyTimeoutMS             int      `json:"ready_timeout_ms"`
	CallerCancellationFailOpen bool     `json:"caller_cancellation_fail_open"`
	WorkerContinuesAfterCancel bool     `json:"worker_continues_after_cancel"`
	RecycleOnProtocolError     bool     `json:"recycle_on_protocol_error"`
	ColdFirstCallTelemetry     bool     `json:"cold_first_call_telemetry"`
}

func BuildWorkerAffinityPlan(req WorkerAffinityPlanRequest) (WorkerAffinityPlan, error) {
	if req.PoolSize < 1 || req.PoolSize > 64 {
		return WorkerAffinityPlan{}, fmt.Errorf("worker pool_size must be 1..64")
	}
	if len(req.Workers) == 0 || len(req.Workers) > req.PoolSize {
		return WorkerAffinityPlan{}, fmt.Errorf("worker observations must be between 1 and pool_size")
	}
	key := strings.TrimSpace(req.AffinityKey)
	if key == "" || len(key) > 1024 {
		return WorkerAffinityPlan{}, fmt.Errorf("affinity_key must be 1..1024 bytes")
	}
	deadline := req.HardDeadlineMS
	if deadline == 0 {
		deadline = 30000
	}
	if deadline < 100 || deadline > 120000 {
		return WorkerAffinityPlan{}, fmt.Errorf("hard deadline must be 100..120000 ms")
	}
	restarts := req.MaxRestarts
	if restarts == 0 {
		restarts = 4
	}
	if restarts < 0 || restarts > 8 {
		return WorkerAffinityPlan{}, fmt.Errorf("max_restarts must be 0..8")
	}
	frameBytes := req.MaxProtocolFrameBytes
	if frameBytes == 0 {
		frameBytes = 1 << 20
	}
	if frameBytes < 1024 || frameBytes > 64<<20 {
		return WorkerAffinityPlan{}, fmt.Errorf("max_protocol_frame_bytes must be 1024..67108864")
	}
	readyTimeout := req.ReadyTimeoutMS
	if readyTimeout == 0 {
		readyTimeout = 60000
	}
	if readyTimeout < 100 || readyTimeout > 120000 {
		return WorkerAffinityPlan{}, fmt.Errorf("ready_timeout_ms must be 100..120000")
	}
	seen := map[string]bool{}
	workers := append([]WorkerObservation(nil), req.Workers...)
	for _, w := range workers {
		if strings.TrimSpace(w.ID) == "" || seen[w.ID] || w.Inflight < 0 || w.Capacity < 1 || w.Inflight > w.Capacity {
			return WorkerAffinityPlan{}, fmt.Errorf("invalid worker observation %q", w.ID)
		}
		seen[w.ID] = true
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].ID < workers[j].ID })
	digest := sha256.Sum256([]byte(key))
	preferred := workers[int(binary.BigEndian.Uint64(digest[:8])%uint64(len(workers)))].ID
	plan := WorkerAffinityPlan{
		PreferredWorker: preferred, HardDeadlineMS: deadline,
		ProtocolFraming: "ndjson", ReadyHandshake: `{"ready":true}`, CorrelatesRequestIDs: true,
		AffinityQueueDepth: 1, SharedQueueDepth: 0, MaxProtocolFrameBytes: frameBytes, ReadyTimeoutMS: readyTimeout,
		CallerCancellationFailOpen: true, WorkerContinuesAfterCancel: true, RecycleOnProtocolError: true, ColdFirstCallTelemetry: true,
	}
	for i := 0; i < restarts; i++ {
		d := 250 * (1 << i)
		if d > 8000 {
			d = 8000
		}
		plan.RestartBackoffMS = append(plan.RestartBackoffMS, d)
	}
	eligible := make([]WorkerObservation, 0, len(workers))
	for _, w := range workers {
		if w.Healthy && w.Inflight < w.Capacity {
			eligible = append(eligible, w)
		}
	}
	for _, w := range eligible {
		if w.ID == preferred {
			plan.SelectedWorker = w.ID
			break
		}
	}
	if plan.SelectedWorker == "" && len(eligible) > 0 {
		sort.Slice(eligible, func(i, j int) bool {
			if eligible[i].Inflight != eligible[j].Inflight {
				return eligible[i].Inflight < eligible[j].Inflight
			}
			return eligible[i].ID < eligible[j].ID
		})
		plan.SelectedWorker = eligible[0].ID
		plan.Spillover = plan.SelectedWorker != preferred
	}
	if plan.SelectedWorker == "" {
		plan.FailOpen = true
	}
	plan.Invariants = []string{"affinity selection is deterministic for the same bounded worker set", "unhealthy or saturated workers cannot be selected", "saturation may spill to another eligible worker instead of blocking the caller", "no eligible worker yields fail-open evidence rather than an unbounded wait", "hard deadlines and restart backoff are bounded", "worker protocol uses one correlated request per line after an explicit ready handshake", "affinity buffering is depth one and spillover is unbuffered backpressure", "caller cancellation may fail open while a bounded worker call continues to become warm", "protocol desynchronization or hard-cap failure requires worker recycle", "protocol frames and readiness time are explicitly bounded", "the planner starts and restarts no process"}
	return plan, nil
}
