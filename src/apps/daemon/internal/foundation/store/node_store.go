package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// StoredNode represents a proxy node persisted in SQLite.
type StoredNode struct {
	ID          int64     `json:"id"`
	URI         string    `json:"uri"`
	Protocol    string    `json:"protocol"`
	Address     string    `json:"address"`
	Port        int       `json:"port"`
	LatencyMs   int       `json:"latency_ms"`
	Quarantine  bool      `json:"quarantine"`
	Until       time.Time `json:"quarantined_until"`
	CreatedAt   time.Time `json:"created_at"`
}

// NodeStore manages node persistence using modernc.org/sqlite (CGO-free).
type NodeStore struct {
	db *sql.DB
}

// NewNodeStore opens a SQLite database and initializes the schema.
func NewNodeStore(dsn string) (*NodeStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		uri TEXT UNIQUE,
		protocol TEXT,
		address TEXT,
		port INTEGER,
		latency_ms INTEGER DEFAULT -1,
		quarantine INTEGER DEFAULT 0,
		quarantined_until DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema migration failed: %w", err)
	}

	return &NodeStore{db: db}, nil
}

// SaveNode inserts or updates a node configuration entry.
func (s *NodeStore) SaveNode(ctx context.Context, uri, protocol, address string, port int) error {
	query := `INSERT INTO nodes (uri, protocol, address, port) VALUES (?, ?, ?, ?)
			  ON CONFLICT(uri) DO UPDATE SET address=excluded.address, port=excluded.port`
	_, err := s.db.ExecContext(ctx, query, uri, protocol, address, port)
	return err
}

// GetHealthyNodes fetches active non-quarantined nodes sorted by latency.
func (s *NodeStore) GetHealthyNodes(ctx context.Context, limit int) ([]StoredNode, error) {
	query := `SELECT id, uri, protocol, address, port, latency_ms, quarantine, created_at
			  FROM nodes WHERE quarantine = 0 ORDER BY latency_ms ASC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []StoredNode
	for rows.Next() {
		var n StoredNode
		var quar int
		var createdAtStr sql.NullString
		if err := rows.Scan(&n.ID, &n.URI, &n.Protocol, &n.Address, &n.Port, &n.LatencyMs, &quar, &createdAtStr); err != nil {
			return nil, err
		}
		n.Quarantine = (quar == 1)
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// Close closes the database connection.
func (s *NodeStore) Close() error {
	return s.db.Close()
}
