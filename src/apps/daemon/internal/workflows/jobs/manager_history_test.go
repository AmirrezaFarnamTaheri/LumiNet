package jobs

import (
	"context"
	"testing"

	"github.com/maybeknott/luminet/internal/foundation/store"
)

func TestClearHistoryPreservesActiveDatabaseJobs(t *testing.T) {
	db, err := store.OpenDB(t.TempDir() + "/jobs.db")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	statuses := []JobStatus{
		JobStatusQueued,
		JobStatusRunning,
		JobStatusCompleted,
		JobStatusFailed,
		JobStatusCancelled,
	}
	for _, status := range statuses {
		if _, err := db.Conn().ExecContext(context.Background(),
			"INSERT INTO jobs (job_id, type, status) VALUES (?, ?, ?)",
			string(status), "test", string(status)); err != nil {
			t.Fatalf("insert %s: %v", status, err)
		}
	}

	manager := &JobManager{db: db, jobs: map[string]*Job{}}
	if err := manager.ClearHistory(); err != nil {
		t.Fatalf("ClearHistory: %v", err)
	}

	for _, status := range []JobStatus{JobStatusQueued, JobStatusRunning} {
		var count int
		if err := db.Conn().QueryRow("SELECT COUNT(*) FROM jobs WHERE status = ?", status).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", status, err)
		}
		if count != 1 {
			t.Errorf("active status %s count = %d, want 1", status, count)
		}
	}

	var remaining int
	if err := db.Conn().QueryRow("SELECT COUNT(*) FROM jobs").Scan(&remaining); err != nil {
		t.Fatalf("count remaining jobs: %v", err)
	}
	if remaining != 2 {
		t.Errorf("remaining jobs = %d, want 2 active jobs", remaining)
	}
}
