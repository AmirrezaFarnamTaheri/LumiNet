package store

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/evidence"
)

// Save writes a ProbeEvidence row to the SQLite results table.
func (d *DB) Save(ctx context.Context, e *evidence.ProbeEvidence) error {
	query := `INSERT INTO results (job_id, target, ip, port, success, latency_ms, error, timestamp, metadata)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	success := 0
	if e.State == evidence.StateAlive {
		success = 1
	}

	// Marshal metadata containing extra fields to avoid schema bloat
	metaMap := make(map[string]interface{})
	if e.Metadata != nil {
		for k, v := range e.Metadata {
			metaMap[k] = v
		}
	}
	metaMap["_kind"] = string(e.Kind)
	metaMap["_state"] = string(e.State)
	metaMap["_reason"] = e.Reason
	metaMap["_started_at"] = e.StartedAt.Format(time.RFC3339)
	metaMap["_completed_at"] = e.CompletedAt.Format(time.RFC3339)
	metaMap["_ttl"] = e.TTL
	metaMap["_reason_code"] = e.ReasonCode
	metaMap["_evidence_id"] = e.ID

	metaBytes, err := json.Marshal(metaMap)
	if err != nil {
		return fmt.Errorf("failed to marshal evidence metadata: %w", err)
	}

	_, err = d.conn.ExecContext(ctx, query,
		e.JobID, e.Target, e.IP, e.Port, success, e.LatencyMs, e.Error, e.CompletedAt.Unix(), string(metaBytes),
	)
	if err != nil {
		return fmt.Errorf("failed to save evidence: %w", err)
	}
	return nil
}

// ListByJob returns evidence rows for a specific job ID.
func (d *DB) ListByJob(ctx context.Context, jobID string, limit, offset int) ([]*evidence.ProbeEvidence, error) {
	query := `SELECT id, job_id, target, ip, port, success, latency_ms, error, timestamp, metadata 
	          FROM results WHERE job_id = ? ORDER BY id ASC LIMIT ? OFFSET ?`

	rows, err := d.conn.QueryContext(ctx, query, jobID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query evidence list: %w", err)
	}
	defer rows.Close()

	var evs []*evidence.ProbeEvidence
	for rows.Next() {
		var id int
		var jobIDFromDB, target, ip, errStr, metaStr string
		var port int
		var success int
		var latencyMs float64
		var timestamp int64

		if err := rows.Scan(&id, &jobIDFromDB, &target, &ip, &port, &success, &latencyMs, &errStr, &timestamp, &metaStr); err != nil {
			return nil, fmt.Errorf("failed to scan evidence row: %w", err)
		}

		// Unmarshal metadata to restore fields
		var metaMap map[string]interface{}
		if metaStr != "" {
			if err := json.Unmarshal([]byte(metaStr), &metaMap); err != nil {
				// Log warning but don't fail — row is still partially usable
				fmt.Fprintf(os.Stderr, "warning: evidence row %d has corrupt metadata: %v\n", id, err)
			}
		}

		e := &evidence.ProbeEvidence{
			ID:          fmt.Sprintf("%d", id),
			JobID:       jobIDFromDB,
			Target:      target,
			IP:          ip,
			Port:        port,
			LatencyMs:   latencyMs,
			CompletedAt: time.Unix(timestamp, 0),
			Error:       errStr,
		}

		if success == 1 {
			e.State = evidence.StateAlive
		} else {
			e.State = evidence.StateDead
		}

		if metaMap != nil {
			if kind, ok := metaMap["_kind"].(string); ok {
				e.Kind = evidence.ProbeKind(kind)
			}
			if state, ok := metaMap["_state"].(string); ok {
				e.State = evidence.ProbeState(state)
			}
			if reason, ok := metaMap["_reason"].(string); ok {
				e.Reason = reason
			}
			if startStr, ok := metaMap["_started_at"].(string); ok {
				if t, err := time.Parse(time.RFC3339, startStr); err == nil {
					e.StartedAt = t
				}
			}
			if ttl, ok := metaMap["_ttl"].(float64); ok {
				e.TTL = int(ttl)
			}
			if rc, ok := metaMap["_reason_code"].(float64); ok {
				e.ReasonCode = int(rc)
			}
			if evidenceID, ok := metaMap["_evidence_id"].(string); ok {
				e.ID = evidenceID
			}

			// Clean up private metadata keys
			delete(metaMap, "_kind")
			delete(metaMap, "_state")
			delete(metaMap, "_reason")
			delete(metaMap, "_started_at")
			delete(metaMap, "_completed_at")
			delete(metaMap, "_ttl")
			delete(metaMap, "_reason_code")
			delete(metaMap, "_evidence_id")
			e.Metadata = metaMap
		}

		evs = append(evs, e)
	}

	return evs, rows.Err()
}

// CountByJob returns the total count of evidence rows for a job ID.
func (d *DB) CountByJob(ctx context.Context, jobID string) (int, error) {
	query := `SELECT COUNT(*) FROM results WHERE job_id = ?`
	var count int
	err := d.conn.QueryRowContext(ctx, query, jobID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count evidence: %w", err)
	}
	return count, nil
}

// ExportJobJSONL exports all results for a job in JSON Lines format.
func (d *DB) ExportJobJSONL(ctx context.Context, jobID string, w io.Writer) error {
	offset := 0
	limit := 100
	for {
		list, err := d.ListByJob(ctx, jobID, limit, offset)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			break
		}
		for _, e := range list {
			bytes, err := json.Marshal(e)
			if err != nil {
				return err
			}
			if _, err := w.Write(append(bytes, '\n')); err != nil {
				return err
			}
		}
		offset += len(list)
	}
	return nil
}

// XML models for Nmap format export
type nmapRun struct {
	XMLName          xml.Name   `xml:"nmaprun"`
	Scanner          string     `xml:"scanner,attr"`
	Args             string     `xml:"args,attr"`
	Start            int64      `xml:"start,attr"`
	Version          string     `xml:"version,attr"`
	XmlOutputVersion string     `xml:"xmloutputversion,attr"`
	Hosts            []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus  `xml:"status"`
	Addresses []nmapAddr  `xml:"address"`
	Ports     []nmapPorts `xml:"ports,omitempty"`
}

type nmapStatus struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL int    `xml:"reason_ttl,attr,omitempty"`
}

type nmapAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string    `xml:"protocol,attr"`
	PortID   int       `xml:"portid,attr"`
	State    nmapState `xml:"state"`
}

type nmapState struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL int    `xml:"reason_ttl,attr,omitempty"`
}

// ExportJobNmapXML exports all results for a job in Nmap XML format.
func (d *DB) ExportJobNmapXML(ctx context.Context, jobID string, w io.Writer) error {
	var list []*evidence.ProbeEvidence
	offset := 0
	limit := 100
	for {
		batch, err := d.ListByJob(ctx, jobID, limit, offset)
		if err != nil {
			return err
		}
		if len(batch) == 0 {
			break
		}
		list = append(list, batch...)
		offset += len(batch)
	}

	hostsMap := make(map[string]*nmapHost)
	var hostsList []*nmapHost

	for _, e := range list {
		hostKey := e.IP
		if hostKey == "" {
			hostKey = e.Target
		}
		if hostKey == "" {
			continue
		}

		h, exists := hostsMap[hostKey]
		if !exists {
			addrType := "ipv4"
			if len(e.IP) > 0 && (e.IP[0] == ':' || len(e.IP) > 15) {
				addrType = "ipv6"
			}
			state := "down"
			if e.State == evidence.StateAlive {
				state = "up"
			}

			h = &nmapHost{
				Status: nmapStatus{
					State:     state,
					Reason:    e.Reason,
					ReasonTTL: e.TTL,
				},
				Addresses: []nmapAddr{
					{Addr: hostKey, AddrType: addrType},
				},
			}
			hostsMap[hostKey] = h
			hostsList = append(hostsList, h)
		}

		if e.Port > 0 {
			portState := "closed"
			if e.State == evidence.StateAlive {
				portState = "open"
			} else if e.State == evidence.StateFiltered {
				portState = "filtered"
			}

			protocol := "tcp"
			if e.Kind == evidence.ProbeWireGuard {
				protocol = "udp"
			}

			p := nmapPort{
				Protocol: protocol,
				PortID:   e.Port,
				State: nmapState{
					State:     portState,
					Reason:    e.Reason,
					ReasonTTL: e.TTL,
				},
			}

			if len(h.Ports) == 0 {
				h.Ports = append(h.Ports, nmapPorts{})
			}
			h.Ports[0].Ports = append(h.Ports[0].Ports, p)
		}
	}

	run := nmapRun{
		Scanner:          "luminet",
		Args:             "luminet scan " + jobID,
		Start:            time.Now().Unix(),
		Version:          "3.0.0",
		XmlOutputVersion: "1.05",
	}
	for _, h := range hostsList {
		run.Hosts = append(run.Hosts, *h)
	}

	if _, err := w.Write([]byte(xml.Header)); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(run); err != nil {
		return err
	}
	return nil
}
