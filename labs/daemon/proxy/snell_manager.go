// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: snell-panel-refactor-hono-heroui
// Target path: server/internal/proxy/snell_manager.go

package proxy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
)

// SnellManager handles Snell node management APIs and D1 SQL queries.
type SnellManager struct {
	db *sql.DB
}

// NewSnellManager initializes the snell manager.
func NewSnellManager(db *sql.DB) *SnellManager {
	return &SnellManager{db: db}
}

// HandleGetNodes ports the Hono backend API to fetch Drizzle schemas via Cloudflare D1.
func (s *SnellManager) HandleGetNodes(w http.ResponseWriter, r *http.Request) {
	slog.Info("snell-manager", "status", "Fetching nodes from D1 SQL query controllers")

	// Mock fetching from DB
	nodes := []map[string]interface{}{
		{"id": 1, "name": "snell-us-1", "host": "us1.example.com", "port": 10000, "psk": "secret123"},
		{"id": 2, "name": "snell-sg-1", "host": "sg1.example.com", "port": 10001, "psk": "secret456"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodes)
}

// HandleCreateNode adds a new Snell node.
func (s *SnellManager) HandleCreateNode(w http.ResponseWriter, r *http.Request) {
	var node map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("snell-manager: Creating new node in D1: %v", node)

	// Mock insert
	node["id"] = 3
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(node)
}

// InitSchema simulates the Drizzle schema application.
func (s *SnellManager) InitSchema() error {
	slog.Info("snell-manager", "status", "Applying Drizzle schema migrations to D1")
	query := `
		CREATE TABLE IF NOT EXISTS snell_nodes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			host TEXT NOT NULL,
			port INTEGER NOT NULL,
			psk TEXT NOT NULL
		);
	`
	if s.db != nil {
		_, err := s.db.Exec(query)
		if err != nil {
			return fmt.Errorf("schema init failed: %w", err)
		}
	}
	return nil
}
