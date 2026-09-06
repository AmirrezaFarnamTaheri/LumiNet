package store

import (
	"context"
	"testing"
	"time"
)

func TestSaveJobRecordUpdatesConfigOnConflict(t *testing.T) {
	db, err := OpenDB(t.TempDir() + "/jobs.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := &JobRecord{ID: "job-1", Type: "test", Status: "completed", Config: `{"secret":"old"}`}
	if err := db.SaveJobRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	r.Config = `{"secret":"[REDACTED]"}`
	if err := db.SaveJobRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetJobRecord(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Config != r.Config {
		t.Fatalf("Config=%q want %q", got.Config, r.Config)
	}
}

func TestSaveJobRecordPersistsRecoveryLineage(t *testing.T) {
	db, err := OpenDB(t.TempDir() + "/jobs-lineage.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r := &JobRecord{
		ID: "recovered-job", Type: "dns_scan", Status: "queued", CreatedAt: time.Now(),
		Config: `{"domain":"example.com"}`, RecoveredFrom: "interrupted-source",
	}
	if err := db.SaveJobRecord(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetJobRecord(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RecoveredFrom != r.RecoveredFrom {
		t.Fatalf("recovered_from=%q want %q", got.RecoveredFrom, r.RecoveredFrom)
	}
	id, ok, err := db.FindActiveRecoveredJob(ctx, r.RecoveredFrom)
	if err != nil || !ok || id != r.ID {
		t.Fatalf("active lineage lookup id=%q ok=%v err=%v", id, ok, err)
	}
}
