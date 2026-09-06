// Package store — SQLite migrations.
//
// Addresses D-01: SQLite FK + Migrations.
//
// Rules:
//   - PRAGMA foreign_keys = ON is set by EnableForeignKeys() which must be
//     called after every new connection (SQLite FKs are per-connection).
//   - Migrations are applied in strict ascending version order.
//   - Each migration is a single SQL statement executed inside the same
//     transaction as the schema_version update, so version tracking is atomic.
//   - Indices are added in separate migration steps so they can be dropped
//     and recreated without touching data rows.
package store

import (
	"database/sql"
	"fmt"
)

// EnableForeignKeys turns on FK enforcement for the given connection.
// SQLite foreign key support is OFF by default and must be enabled per
// connection.  Call this immediately after opening or borrowing a connection.
func EnableForeignKeys(db *sql.DB) error {
	_, err := db.Exec("PRAGMA foreign_keys = ON;")
	return err
}

// Migration is a single versioned schema change.
type Migration struct {
	Version int
	SQL     string
}

var migrations = []Migration{
	{1, "CREATE TABLE config (key TEXT PRIMARY KEY, val TEXT);"},
	{2, "CREATE TABLE scan_evidence (target TEXT, rtt INTEGER, timestamp DATETIME);"},
	{3, `CREATE TABLE IF NOT EXISTS jobs (
		job_id       TEXT PRIMARY KEY,
		type         TEXT NOT NULL,
		status       TEXT NOT NULL DEFAULT 'queued',
		progress     INTEGER DEFAULT 0,
		data         BLOB,
		error        TEXT,
		created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at   DATETIME,
		started_at   DATETIME,
		completed_at DATETIME,
		config       TEXT,
		results      TEXT,
		next_run_at  DATETIME,
		attempts     INTEGER DEFAULT 0,
		max_attempts INTEGER DEFAULT 3
	);`},
	{4, `CREATE TABLE IF NOT EXISTS results (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		job_id     TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
		target     TEXT,
		ip         TEXT,
		port       INTEGER,
		success    INTEGER NOT NULL DEFAULT 0,
		latency_ms REAL,
		error      TEXT,
		timestamp  INTEGER NOT NULL,
		metadata   TEXT
	);`},
	{5, `CREATE TABLE IF NOT EXISTS covert_links (
		link_id    TEXT PRIMARY KEY,
		label      TEXT,
		created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		hits       INTEGER NOT NULL DEFAULT 0
	);`},
	{6, `CREATE TABLE IF NOT EXISTS covert_visits (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp    INTEGER NOT NULL,
		ip           TEXT,
		country      TEXT,
		country_code TEXT,
		region       TEXT,
		city         TEXT,
		latitude     REAL,
		longitude    REAL,
		isp          TEXT,
		browser      TEXT,
		os           TEXT,
		device       TEXT,
		user_agent   TEXT,
		referrer     TEXT,
		language     TEXT,
		link_id      TEXT REFERENCES covert_links(link_id) ON DELETE CASCADE
	);`},
	// D-01: Performance indices
	{7, `CREATE INDEX IF NOT EXISTS idx_jobs_status    ON jobs(status);`},
	{7, `CREATE INDEX IF NOT EXISTS idx_jobs_type      ON jobs(type, status);`},
	{8, `CREATE INDEX IF NOT EXISTS idx_results_job    ON results(job_id, timestamp);`},
	{9, `CREATE INDEX IF NOT EXISTS idx_visits_link    ON covert_visits(link_id, timestamp);`},
	{10, `CREATE INDEX IF NOT EXISTS idx_visits_ts      ON covert_visits(timestamp);`},
	// D-02: Probe evidence table owned by the canonical store migration path.
	{11, `CREATE TABLE IF NOT EXISTS probe_evidence (
		id           TEXT PRIMARY KEY,
		job_id       TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
		kind         TEXT NOT NULL,
		target       TEXT NOT NULL,
		ip           TEXT,
		port         INTEGER,
		state        TEXT NOT NULL,
		reason       TEXT,
		latency_ms   REAL,
		started_at   INTEGER NOT NULL,
		completed_at INTEGER NOT NULL,
		error        TEXT,
		metadata     TEXT,
		ttl          INTEGER,
		reason_code  INTEGER
	);`},
	{12, `CREATE INDEX IF NOT EXISTS idx_pe_job    ON probe_evidence(job_id);`},
	{13, `CREATE INDEX IF NOT EXISTS idx_pe_target ON probe_evidence(target);`},
	{14, `CREATE INDEX IF NOT EXISTS idx_pe_state  ON probe_evidence(state);`},
	// D-03: Seed the 'default' sentinel covert link so anonymous /track visits
	// always satisfy the FK constraint on covert_visits(link_id).
	{15, `INSERT OR IGNORE INTO covert_links (link_id, label, created_at, hits)
		VALUES ('default', 'Anonymous / Direct', strftime('%s','now'), 0);`},
	// D-04: Relax the FK on covert_visits so any unknown link_id (e.g. from
	// external shares or typos) never silently drops a visit row.  We keep the
	// column for filtering but drop the referential constraint.
	{16, `CREATE TABLE IF NOT EXISTS covert_visits_v2 (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp    INTEGER NOT NULL,
		ip           TEXT,
		country      TEXT,
		country_code TEXT,
		region       TEXT,
		city         TEXT,
		latitude     REAL,
		longitude    REAL,
		isp          TEXT,
		browser      TEXT,
		os           TEXT,
		device       TEXT,
		user_agent   TEXT,
		referrer     TEXT,
		language     TEXT,
		link_id      TEXT
	);`},
	{17, `INSERT OR IGNORE INTO covert_visits_v2
		SELECT id,timestamp,ip,country,country_code,region,city,latitude,longitude,
		       isp,browser,os,device,user_agent,referrer,language,link_id
		FROM covert_visits;`},
	{18, `DROP TABLE IF EXISTS covert_visits;`},
	{19, `ALTER TABLE covert_visits_v2 RENAME TO covert_visits;`},
	{20, `CREATE INDEX IF NOT EXISTS idx_visits_link2 ON covert_visits(link_id, timestamp);`},
	{21, `CREATE INDEX IF NOT EXISTS idx_visits_ts2   ON covert_visits(timestamp);`},
	// 22: Control Panel Inbounds & client_traffic tracking tables
	{22, `CREATE TABLE IF NOT EXISTS inbounds (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		remark TEXT,
		enable INTEGER NOT NULL DEFAULT 1,
		port INTEGER,
		protocol TEXT,
		settings TEXT,
		tag TEXT UNIQUE
	);`},
	{22, `CREATE TABLE IF NOT EXISTS client_traffic (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		inbound_id INTEGER REFERENCES inbounds(id) ON DELETE CASCADE,
		email TEXT UNIQUE,
		up INTEGER NOT NULL DEFAULT 0,
		down INTEGER NOT NULL DEFAULT 0,
		total INTEGER NOT NULL DEFAULT 0,
		expiry_time INTEGER NOT NULL DEFAULT 0
	);`},
	{22, `CREATE TABLE IF NOT EXISTS inbound_client_ips (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_email TEXT REFERENCES client_traffic(email) ON DELETE CASCADE,
		ips TEXT
	);`},
	// 23: Performance indexes for control panel tables
	{23, `CREATE INDEX IF NOT EXISTS idx_ct_inbound ON client_traffic(inbound_id);`},
	{23, `CREATE INDEX IF NOT EXISTS idx_ct_email   ON client_traffic(email);`},
	// 24: Preserve immutable lineage when an operator explicitly requeues an
	// interrupted, reconstructible job after a daemon restart. This is audit
	// metadata only; it never causes automatic replay.
	{24, `ALTER TABLE jobs ADD COLUMN recovered_from TEXT;`},
	{25, `CREATE INDEX IF NOT EXISTS idx_jobs_recovered_from ON jobs(recovered_from, status);`},
	// 26: Persist the highest accepted schema-v2 signed-update metadata sequence.
	// Equal sequence is intentionally idempotent; lower sequence is rejected by
	// the update admission path before any artifact staging.
	{26, `CREATE TABLE IF NOT EXISTS update_metadata_state (
		product          TEXT PRIMARY KEY,
		highest_sequence INTEGER NOT NULL CHECK(highest_sequence > 0),
		updated_at       INTEGER NOT NULL
	);`},
}

// ApplyMigrations applies all pending schema migrations inside a transaction.
// Call EnableForeignKeys before this function on the same *sql.DB.
func ApplyMigrations(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// 1. Ensure schema version table exists.
	_, err = tx.Exec("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);")
	if err != nil {
		return err
	}

	// 2. Fetch current version.
	var currentVersion int
	err = tx.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&currentVersion)
	if err != nil {
		return err
	}

	// 3. Apply migrations in order.
	seen := make(map[int]bool)
	for _, m := range migrations {
		if m.Version <= currentVersion {
			continue
		}
		_, err = tx.Exec(m.SQL)
		if err != nil {
			return fmt.Errorf("migration version %d failed: %w", m.Version, err)
		}
		if !seen[m.Version] {
			_, err = tx.Exec("INSERT INTO schema_version (version) VALUES (?)", m.Version)
			if err != nil {
				return err
			}
			seen[m.Version] = true
		}
	}

	return tx.Commit()
}

// CheckIntegrity runs PRAGMA integrity_check and returns an error if the
// database is corrupt.  Intended for use in the doctor command (O-02).
func CheckIntegrity(db *sql.DB) error {
	rows, err := db.Query("PRAGMA integrity_check;")
	if err != nil {
		return fmt.Errorf("integrity_check failed: %w", err)
	}
	defer rows.Close()
	var result string
	for rows.Next() {
		if err := rows.Scan(&result); err != nil {
			return err
		}
		if result != "ok" {
			return fmt.Errorf("SQLite integrity_check: %s", result)
		}
	}
	return rows.Err()
}
