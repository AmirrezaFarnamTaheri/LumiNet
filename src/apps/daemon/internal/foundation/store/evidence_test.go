package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/evidence"
)

func TestEvidenceRepository(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_evidence.db")

	db, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	if err := db.Migrate(); err != nil {
		t.Fatalf("database migration failed: %v", err)
	}

	ctx := context.Background()
	jobID := "test-job-uuid-12345"

	// Create test job record first (due to foreign key constraint on job_id)
	jr := &JobRecord{
		ID:        jobID,
		Type:      "icmp_scan",
		Status:    "running",
		CreatedAt: time.Now(),
	}
	if err := db.SaveJobRecord(ctx, jr); err != nil {
		t.Fatalf("failed to save job record: %v", err)
	}

	// 1. Save evidence
	e1 := &evidence.ProbeEvidence{
		ID:          "ev-1",
		JobID:       jobID,
		Kind:        evidence.ProbeICMP,
		Target:      "1.1.1.1",
		IP:          "1.1.1.1",
		State:       evidence.StateAlive,
		LatencyMs:   12.5,
		StartedAt:   time.Now().Add(-20 * time.Millisecond),
		CompletedAt: time.Now(),
		TTL:         64,
		ReasonCode:  0,
		Metadata: map[string]interface{}{
			"foo": "bar",
		},
	}

	e2 := &evidence.ProbeEvidence{
		ID:          "ev-2",
		JobID:       jobID,
		Kind:        evidence.ProbeTCP,
		Target:      "8.8.8.8",
		IP:          "8.8.8.8",
		Port:        53,
		State:       evidence.StateDead,
		LatencyMs:   100.0,
		StartedAt:   time.Now().Add(-110 * time.Millisecond),
		CompletedAt: time.Now(),
		Error:       "connection refused",
	}

	if err := db.Save(ctx, e1); err != nil {
		t.Errorf("failed to save e1: %v", err)
	}
	if err := db.Save(ctx, e2); err != nil {
		t.Errorf("failed to save e2: %v", err)
	}

	// 2. Count evidence
	count, err := db.CountByJob(ctx, jobID)
	if err != nil {
		t.Fatalf("failed to count: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 evidence rows, got %d", count)
	}

	// 3. List evidence
	list, err := db.ListByJob(ctx, jobID, 10, 0)
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected list of length 2, got %d", len(list))
	}

	// Verify e1 unpacked
	res1 := list[0]
	if res1.Target != "1.1.1.1" || res1.State != evidence.StateAlive || res1.Kind != evidence.ProbeICMP {
		t.Errorf("e1 unpacked incorrectly: %+v", res1)
	}
	if val, ok := res1.Metadata["foo"].(string); !ok || val != "bar" {
		t.Errorf("e1 metadata unpacked incorrectly: %+v", res1.Metadata)
	}

	// Verify e2 unpacked
	res2 := list[1]
	if res2.Target != "8.8.8.8" || res2.State != evidence.StateDead || res2.Kind != evidence.ProbeTCP || res2.Error != "connection refused" {
		t.Errorf("e2 unpacked incorrectly: %+v", res2)
	}

	// 4. Export JSONL
	var jsonlBuf bytes.Buffer
	if err := db.ExportJobJSONL(ctx, jobID, &jsonlBuf); err != nil {
		t.Fatalf("failed to export JSONL: %v", err)
	}
	if bytes.Count(jsonlBuf.Bytes(), []byte{'\n'}) != 2 {
		t.Errorf("expected 2 lines in JSONL export, got %d", bytes.Count(jsonlBuf.Bytes(), []byte{'\n'}))
	}

	// 5. Export Nmap XML
	var xmlBuf bytes.Buffer
	if err := db.ExportJobNmapXML(ctx, jobID, &xmlBuf); err != nil {
		t.Fatalf("failed to export XML: %v", err)
	}
	xmlStr := xmlBuf.String()
	if !bytes.Contains(xmlBuf.Bytes(), []byte("<nmaprun")) {
		t.Errorf("expected <nmaprun> in XML export, got:\n%s", xmlStr)
	}
	if !bytes.Contains(xmlBuf.Bytes(), []byte("addr=\"1.1.1.1\"")) {
		t.Errorf("expected host address in XML export, got:\n%s", xmlStr)
	}
}
