package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// HighestUpdateMetadataSequence returns the persisted high-water mark for a
// signed-update product. A missing row is represented as zero.
func (d *DB) HighestUpdateMetadataSequence(ctx context.Context, product string) (uint64, error) {
	if d == nil || d.conn == nil {
		return 0, fmt.Errorf("update metadata store is unavailable")
	}
	product = strings.TrimSpace(product)
	if product == "" {
		return 0, fmt.Errorf("update metadata product is required")
	}
	var value int64
	err := d.conn.QueryRowContext(ctx, `SELECT highest_sequence FROM update_metadata_state WHERE product = ?`, product).Scan(&value)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read update metadata high-water mark: %w", err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("stored update metadata high-water mark is invalid")
	}
	return uint64(value), nil
}

// AcceptUpdateMetadataSequence atomically rejects stale metadata and advances
// the high-water mark for newer metadata. Equal sequence is accepted without
// mutation so a failed download/stage can safely be retried idempotently.
//
// The monotonic comparison is performed by SQLite in the UPSERT predicate,
// rather than by a read-then-write race in application code. The transaction's
// final read classifies the request as stale (< current) or accepted (= current).
func (d *DB) AcceptUpdateMetadataSequence(ctx context.Context, product string, sequence uint64) (uint64, bool, error) {
	if d == nil || d.conn == nil {
		return 0, false, fmt.Errorf("update metadata store is unavailable")
	}
	product = strings.TrimSpace(product)
	if product == "" {
		return 0, false, fmt.Errorf("update metadata product is required")
	}
	if sequence == 0 || sequence > uint64(^uint64(0)>>1) {
		return 0, false, fmt.Errorf("update metadata sequence is outside persistent integer range")
	}

	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Unix()
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO update_metadata_state(product, highest_sequence, updated_at)
		VALUES(?, ?, ?)
		ON CONFLICT(product) DO UPDATE SET
			highest_sequence = excluded.highest_sequence,
			updated_at = excluded.updated_at
		WHERE excluded.highest_sequence > update_metadata_state.highest_sequence`,
		product, int64(sequence), now,
	); err != nil {
		return 0, false, fmt.Errorf("accept update metadata high-water mark: %w", err)
	}

	var current int64
	if err = tx.QueryRowContext(ctx, `SELECT highest_sequence FROM update_metadata_state WHERE product = ?`, product).Scan(&current); err != nil {
		return 0, false, fmt.Errorf("read accepted update metadata high-water mark: %w", err)
	}
	if current <= 0 {
		return 0, false, fmt.Errorf("stored update metadata high-water mark is invalid")
	}
	if err = tx.Commit(); err != nil {
		return 0, false, err
	}
	if sequence < uint64(current) {
		return uint64(current), false, nil
	}
	return uint64(current), true, nil
}
