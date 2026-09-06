package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestUpdateMetadataSequenceHighWaterIsMonotonicAndIdempotent(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "luminet.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, err := db.HighestUpdateMetadataSequence(ctx, "luminet"); err != nil || got != 0 {
		t.Fatalf("initial high-water=%d err=%v", got, err)
	}
	if got, ok, err := db.AcceptUpdateMetadataSequence(ctx, "luminet", 10); err != nil || !ok || got != 10 {
		t.Fatalf("initial accept got=%d ok=%v err=%v", got, ok, err)
	}
	if got, ok, err := db.AcceptUpdateMetadataSequence(ctx, "luminet", 10); err != nil || !ok || got != 10 {
		t.Fatalf("idempotent accept got=%d ok=%v err=%v", got, ok, err)
	}
	if got, ok, err := db.AcceptUpdateMetadataSequence(ctx, "luminet", 9); err != nil || ok || got != 10 {
		t.Fatalf("stale accept got=%d ok=%v err=%v", got, ok, err)
	}
	if got, ok, err := db.AcceptUpdateMetadataSequence(ctx, "luminet", 11); err != nil || !ok || got != 11 {
		t.Fatalf("advance got=%d ok=%v err=%v", got, ok, err)
	}
	if got, err := db.HighestUpdateMetadataSequence(ctx, "luminet"); err != nil || got != 11 {
		t.Fatalf("final high-water=%d err=%v", got, err)
	}
}
