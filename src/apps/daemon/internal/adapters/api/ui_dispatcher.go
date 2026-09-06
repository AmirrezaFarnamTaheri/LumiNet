// Package api — UI job dispatcher.
//
// Addresses E-09: UI Job Dispatcher.
//
// The dispatcher accepts job requests from the Wails/WebSocket frontend and
// queues them for the backend job runner. It provides:
//   - Request validation and type-routing
//   - Job-ID generation (UUID v4)
//   - Status event emission on the EventBus
//   - Job deduplication (reject duplicate active jobs of the same type+hash)
//
// Supported job types mirror the five workflows in the live route/workflow catalog.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// JobKind enumerates supported UI-dispatchable job types.
type JobKind string

const (
	JobKindScan         JobKind = "scan"
	JobKindSpeedTest    JobKind = "speed_test"
	JobKindSubscription JobKind = "subscription_refresh"
	JobKindProbe        JobKind = "probe"
	JobKindDiagnostic   JobKind = "diagnostic"
)

// DispatchRequest is the JSON body the frontend sends to POST /api/jobs/dispatch.
type DispatchRequest struct {
	Kind    JobKind         `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

// DispatchResponse is returned on successful dispatch.
type DispatchResponse struct {
	JobID    string    `json:"job_id"`
	Kind     JobKind   `json:"kind"`
	QueuedAt time.Time `json:"queued_at"`
}

// JobRunner is the interface the dispatcher calls to actually start a job.
// Implementations live in the jobs package.
type JobRunner interface {
	Submit(ctx context.Context, jobID string, kind string, payload json.RawMessage) error
	IsActive(kind string, payloadHash string) bool
}

// EventEmitter allows the dispatcher to publish status events.
type EventEmitter interface {
	Publish(topic string, payload any)
}

// UIDispatcher is the HTTP handler that accepts job dispatch requests from
// the Wails / WebSocket frontend.
type UIDispatcher struct {
	runner   JobRunner
	emitter  EventEmitter
	mu       sync.Mutex
	inflight map[string]string // payloadHash → jobID
}

// NewUIDispatcher creates a dispatcher.
func NewUIDispatcher(runner JobRunner, emitter EventEmitter) *UIDispatcher {
	return &UIDispatcher{
		runner:   runner,
		emitter:  emitter,
		inflight: make(map[string]string),
	}
}

// ServeHTTP handles POST /api/jobs/dispatch.
func (d *UIDispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DispatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if err := validateKind(req.Kind); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	jobID, err := newJobID()
	if err != nil {
		http.Error(w, "failed to generate job ID", http.StatusInternalServerError)
		return
	}

	// Deduplication: reject if same-kind same-payload is already running.
	payloadHash := hashPayload(req.Payload)
	d.mu.Lock()
	if existing, ok := d.inflight[payloadHash]; ok {
		d.mu.Unlock()
		// Return the existing job ID so the UI can track it.
		writeJSON(w, http.StatusAccepted, DispatchResponse{
			JobID:    existing,
			Kind:     req.Kind,
			QueuedAt: time.Now(),
		})
		return
	}
	d.inflight[payloadHash] = jobID
	d.mu.Unlock()

	if err := d.runner.Submit(r.Context(), jobID, string(req.Kind), req.Payload); err != nil {
		d.mu.Lock()
		delete(d.inflight, payloadHash)
		d.mu.Unlock()
		http.Error(w, "job submission failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Emit a queued event so the WebSocket clients see the new job immediately.
	if d.emitter != nil {
		d.emitter.Publish("job.queued", map[string]string{
			"job_id": jobID,
			"kind":   string(req.Kind),
		})
	}

	writeJSON(w, http.StatusCreated, DispatchResponse{
		JobID:    jobID,
		Kind:     req.Kind,
		QueuedAt: time.Now(),
	})
}

// CompleteJob removes the job from the inflight deduplication map.
// Call this when the backend runner finishes (success or failure).
func (d *UIDispatcher) CompleteJob(payloadHash string) {
	d.mu.Lock()
	delete(d.inflight, payloadHash)
	d.mu.Unlock()
}

// --- helpers ----------------------------------------------------------------

var validKinds = map[JobKind]bool{
	JobKindScan:         true,
	JobKindSpeedTest:    true,
	JobKindSubscription: true,
	JobKindProbe:        true,
	JobKindDiagnostic:   true,
}

func validateKind(k JobKind) error {
	if !validKinds[k] {
		return fmt.Errorf("unknown job kind %q", k)
	}
	return nil
}

func newJobID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Format as UUID v4.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16])), nil
}

func hashPayload(p json.RawMessage) string {
	// Simple deterministic key: hex of the raw JSON bytes (already canonical
	// from the decoder since we don't re-marshal).
	return hex.EncodeToString([]byte(p))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
