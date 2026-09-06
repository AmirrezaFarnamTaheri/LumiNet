// Package store implements local SQLite schema migrations, connection bootstrapping, and persistence interfaces.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// DB represents a connection wrapper to the persistent SQLite instance.
type DB struct {
	conn *sql.DB
}

// Store is an alias for DB to support source compatibility.
// Deprecated: use DB.
type Store = DB

// OpenDB opens a connection to the SQLite database specified by the directory filepath.
func OpenDB(dbPath string) (*DB, error) {
	// Ensure parent directory exists
	dir := filepath.Dir(dbPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create db directory: %w", err)
		}
	}

	// Open connection with pure-go sqlite driver
	// Enforce foreign keys and configure WAL mode journal on connection startup
	conn, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Configure connection pool parameters to avoid database locking/busy bugs and race conditions
	conn.SetMaxOpenConns(1) // Single writer/reader connection prevents SQLite lock contention
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(time.Hour)

	db := &DB{conn: conn}

	return db, nil
}

// Migrate executes standard SQL schema migrations for configuration, events, profiles, and job entries.
func (d *DB) Migrate() error {
	return ApplyMigrations(d.conn)
}

// Conn returns the raw database connection object.
func (d *DB) Conn() *sql.DB {
	return d.conn
}

// Close closes the database connection.
func (d *DB) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}
