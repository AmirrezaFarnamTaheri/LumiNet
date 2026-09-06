package evidence

import (
	"context"
	"io"
	"time"
)

type ProbeKind string

const (
	ProbeICMP      ProbeKind = "icmp"
	ProbeTCP       ProbeKind = "tcp"
	ProbeDNS       ProbeKind = "dns"
	ProbeTLS       ProbeKind = "tls"
	ProbeSNI       ProbeKind = "sni"
	ProbeHTTP      ProbeKind = "http"
	ProbeWireGuard ProbeKind = "wireguard"
	ProbeSpeed     ProbeKind = "speed"
)

type ProbeState string

const (
	StateAlive    ProbeState = "alive"
	StateDead     ProbeState = "dead"
	StateFiltered ProbeState = "filtered"
	StateUnknown  ProbeState = "unknown"
	StateError    ProbeState = "error"
)

type ProbeEvidence struct {
	ID          string         `json:"id"`
	JobID       string         `json:"job_id"`
	Kind        ProbeKind      `json:"kind"`
	Target      string         `json:"target"`
	IP          string         `json:"ip,omitempty"`
	Port        int            `json:"port,omitempty"`
	State       ProbeState     `json:"state"`
	Reason      string         `json:"reason,omitempty"` // Structured reason code
	LatencyMs   float64        `json:"latency_ms,omitempty"`
	StartedAt   time.Time      `json:"started_at"`
	CompletedAt time.Time      `json:"completed_at"`
	Error       string         `json:"error,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"` // TLS cert, banner, etc.
	TTL         int            `json:"ttl,omitempty"`
	ReasonCode  int            `json:"reason_code,omitempty"` // Nmap-compatible reason codes
}

// Repository interface for evidence persistence
type Repository interface {
	Save(ctx context.Context, e *ProbeEvidence) error
	ListByJob(ctx context.Context, jobID string, limit, offset int) ([]*ProbeEvidence, error)
	CountByJob(ctx context.Context, jobID string) (int, error)
	ExportJobNmapXML(ctx context.Context, jobID string, w io.Writer) error
	ExportJobJSONL(ctx context.Context, jobID string, w io.Writer) error
}
