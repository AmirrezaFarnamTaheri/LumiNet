package jobs

import (
	"context"
	"testing"

	"github.com/maybeknott/luminet/internal/workflows/scheduler"
)

func assertQueuedAfterAdmissionFailure(t *testing.T, m *JobManager, id string) {
	t.Helper()
	m.mu.RLock()
	job := m.jobs[id]
	m.mu.RUnlock()
	if job == nil {
		t.Fatalf("job %s missing", id)
	}
	job.mu.RLock()
	defer job.mu.RUnlock()
	if job.Status != JobStatusQueued {
		t.Fatalf("status=%s want queued", job.Status)
	}
	if job.StartedAt != nil {
		t.Fatalf("StartedAt=%v want nil", job.StartedAt)
	}
}

func TestStartJobRejectedByStoppedSchedulerStaysQueued(t *testing.T) {
	m := NewJobManager(context.Background(), nil)
	m.Stop()
	id, err := m.CreateJob(DiagnosticIntent{})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	if err := m.StartJob(id); err == nil {
		t.Fatal("StartJob succeeded with stopped scheduler")
	}
	assertQueuedAfterAdmissionFailure(t, m, id)
}

func TestStartJobRejectedByFullSchedulerStaysQueued(t *testing.T) {
	m := NewJobManager(context.Background(), nil)
	m.Stop()
	m.sched = scheduler.NewScheduler(scheduler.BudgetPolicy{MaxGlobalRunning: 1, MaxQueueDepth: 1})
	if err := m.sched.Submit(scheduler.NewFuncJob("filler", "test", func(context.Context) error { return nil })); err != nil {
		t.Fatalf("fill scheduler queue: %v", err)
	}
	id, err := m.CreateJob(DiagnosticIntent{})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	if err := m.StartJob(id); err == nil {
		t.Fatal("StartJob succeeded with saturated scheduler")
	}
	assertQueuedAfterAdmissionFailure(t, m, id)
	m.sched.Stop()
}
