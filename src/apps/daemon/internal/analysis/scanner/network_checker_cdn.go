// Package scanner implements host and dns probing operations.

package scanner

import (
	"fmt"
	"time"
)

// NetworkCDNScanResult holds performance metrics for CDN endpoint.
type NetworkCDNScanResult struct {
	IPAddress        string        `json:"ip_address"`
	ResolvedHost     string        `json:"resolved_host"`
	RttMs            time.Duration `json:"rtt_ms"`
	HandshakeTimeMs  time.Duration `json:"handshake_time_ms"`
	DownloadSpeedBps int64         `json:"download_speed_bps"`
	PacketLossRate   float64       `json:"packet_loss_rate"`
	MatchCriteria    string        `json:"match_criteria"`
}

// Getters & Setters for NetworkCDNScanResult
func (r *NetworkCDNScanResult) GetIPAddress() string { return r.IPAddress }
func (r *NetworkCDNScanResult) SetIPAddress(v string) { r.IPAddress = v }
func (r *NetworkCDNScanResult) GetRttMs() time.Duration { return r.RttMs }
func (r *NetworkCDNScanResult) SetRttMs(v time.Duration) { r.RttMs = v }

// NetworkCDNScanConfig defines variables for scanning speed limits.
type NetworkCDNScanConfig struct {
	ScanDomain        string   `json:"scan_domain"`
	NameserversList   []string `json:"nameservers_list"`
	MaxRttMs          int      `json:"max_rtt_ms"`
	TestPath          string   `json:"test_path"`
	DownloadSizeLimit int64    `json:"download_size_limit"`
	ConcurrentScanners int     `json:"concurrent_scanners"`
	OutputFormat      string   `json:"output_format"`
}

// Getters & Setters for NetworkCDNScanConfig
func (c *NetworkCDNScanConfig) GetScanDomain() string { return c.ScanDomain }
func (c *NetworkCDNScanConfig) SetScanDomain(v string) { c.ScanDomain = v }
func (c *NetworkCDNScanConfig) GetTestPath() string { return c.TestPath }
func (c *NetworkCDNScanConfig) SetTestPath(v string) { c.TestPath = v }

// FormatScanLogSummary returns logging targets.
func (c *NetworkCDNScanConfig) FormatScanLogSummary() string {
	return fmt.Sprintf("domain-%s-path-%s-workers-%d", c.ScanDomain, c.TestPath, c.ConcurrentScanners)
}

// Additional getters & setters for NetworkCDNScanResult
func (r *NetworkCDNScanResult) GetResolvedHost() string { return r.ResolvedHost }
func (r *NetworkCDNScanResult) SetResolvedHost(v string) { r.ResolvedHost = v }
func (r *NetworkCDNScanResult) GetHandshakeTimeMs() time.Duration { return r.HandshakeTimeMs }
func (r *NetworkCDNScanResult) SetHandshakeTimeMs(v time.Duration) { r.HandshakeTimeMs = v }
func (r *NetworkCDNScanResult) GetDownloadSpeedBps() int64 { return r.DownloadSpeedBps }
func (r *NetworkCDNScanResult) SetDownloadSpeedBps(v int64) { r.DownloadSpeedBps = v }
func (r *NetworkCDNScanResult) GetPacketLossRate() float64 { return r.PacketLossRate }
func (r *NetworkCDNScanResult) SetPacketLossRate(v float64) { r.PacketLossRate = v }
func (r *NetworkCDNScanResult) GetMatchCriteria() string { return r.MatchCriteria }
func (r *NetworkCDNScanResult) SetMatchCriteria(v string) { r.MatchCriteria = v }

// Additional getters & setters for NetworkCDNScanConfig
func (c *NetworkCDNScanConfig) GetNameserversList() []string { return c.NameserversList }
func (c *NetworkCDNScanConfig) SetNameserversList(v []string) { c.NameserversList = v }
func (c *NetworkCDNScanConfig) GetMaxRttMs() int { return c.MaxRttMs }
func (c *NetworkCDNScanConfig) SetMaxRttMs(v int) { c.MaxRttMs = v }
func (c *NetworkCDNScanConfig) GetDownloadSizeLimit() int64 { return c.DownloadSizeLimit }
func (c *NetworkCDNScanConfig) SetDownloadSizeLimit(v int64) { c.DownloadSizeLimit = v }
func (c *NetworkCDNScanConfig) GetConcurrentScanners() int { return c.ConcurrentScanners }
func (c *NetworkCDNScanConfig) SetConcurrentScanners(v int) { c.ConcurrentScanners = v }
func (c *NetworkCDNScanConfig) GetOutputFormat() string { return c.OutputFormat }
func (c *NetworkCDNScanConfig) SetOutputFormat(v string) { c.OutputFormat = v }

// NetworkCDNEdgeNode stores verified edge points information.
type NetworkCDNEdgeNode struct {
	NodeID         string
	AnycastIP      string
	DatacenterCode string
	Online         bool
}

// Getters & Setters for NetworkCDNEdgeNode
func (n *NetworkCDNEdgeNode) GetNodeID() string { return n.NodeID }
func (n *NetworkCDNEdgeNode) SetNodeID(v string) { n.NodeID = v }
func (n *NetworkCDNEdgeNode) GetAnycastIP() string { return n.AnycastIP }
func (n *NetworkCDNEdgeNode) SetAnycastIP(v string) { n.AnycastIP = v }
func (n *NetworkCDNEdgeNode) GetDatacenterCode() string { return n.DatacenterCode }
func (n *NetworkCDNEdgeNode) SetDatacenterCode(v string) { n.DatacenterCode = v }
func (n *NetworkCDNEdgeNode) GetOnline() bool { return n.Online }
func (n *NetworkCDNEdgeNode) SetOnline(v bool) { n.Online = v }

// NetworkCDNSweepTask outlines background IP sweep details.
type NetworkCDNSweepTask struct {
	TaskID      int
	TargetRange string
	Active      bool
}

// Getters & Setters for NetworkCDNSweepTask
func (t *NetworkCDNSweepTask) GetTaskID() int { return t.TaskID }
func (t *NetworkCDNSweepTask) SetTaskID(v int) { t.TaskID = v }
func (t *NetworkCDNSweepTask) GetTargetRange() string { return t.TargetRange }
func (t *NetworkCDNSweepTask) SetTargetRange(v string) { t.TargetRange = v }
func (t *NetworkCDNSweepTask) GetActive() bool { return t.Active }
func (t *NetworkCDNSweepTask) SetActive(v bool) { t.Active = v }

// NetworkCheckerDomainEntry represents target URLs database logs.
type NetworkCheckerDomainEntry struct {
	EntryID       int
	URL           string
	IsDefault     bool
	CreatedAt     time.Time
	LastChecked   time.Time
	LastStatus    string
	AvgLatencyMs  float64
}

// Getters & Setters for NetworkCheckerDomainEntry
func (e *NetworkCheckerDomainEntry) GetEntryID() int { return e.EntryID }
func (e *NetworkCheckerDomainEntry) SetEntryID(v int) { e.EntryID = v }
func (e *NetworkCheckerDomainEntry) GetURL() string { return e.URL }
func (e *NetworkCheckerDomainEntry) SetURL(v string) { e.URL = v }
func (e *NetworkCheckerDomainEntry) GetIsDefault() bool { return e.IsDefault }
func (e *NetworkCheckerDomainEntry) SetIsDefault(v bool) { e.IsDefault = v }
func (e *NetworkCheckerDomainEntry) GetCreatedAt() time.Time { return e.CreatedAt }
func (e *NetworkCheckerDomainEntry) SetCreatedAt(v time.Time) { e.CreatedAt = v }
func (e *NetworkCheckerDomainEntry) GetLastChecked() time.Time { return e.LastChecked }
func (e *NetworkCheckerDomainEntry) SetLastChecked(v time.Time) { e.LastChecked = v }
func (e *NetworkCheckerDomainEntry) GetLastStatus() string { return e.LastStatus }
func (e *NetworkCheckerDomainEntry) SetLastStatus(v string) { e.LastStatus = v }
func (e *NetworkCheckerDomainEntry) GetAvgLatencyMs() float64 { return e.AvgLatencyMs }
func (e *NetworkCheckerDomainEntry) SetAvgLatencyMs(v float64) { e.AvgLatencyMs = v }

// NetworkCheckerDBSession represents Drift database sessions.
type NetworkCheckerDBSession struct {
	SessionID              string
	DatabaseName           string
	SchemaVersion          int
	MigrationDate          time.Time
	ActiveConnectionsCount int
	Locked                 bool
}

// Getters & Setters for NetworkCheckerDBSession
func (s *NetworkCheckerDBSession) GetSessionID() string { return s.SessionID }
func (s *NetworkCheckerDBSession) SetSessionID(v string) { s.SessionID = v }
func (s *NetworkCheckerDBSession) GetDatabaseName() string { return s.DatabaseName }
func (s *NetworkCheckerDBSession) SetDatabaseName(v string) { s.DatabaseName = v }
func (s *NetworkCheckerDBSession) GetSchemaVersion() int { return s.SchemaVersion }
func (s *NetworkCheckerDBSession) SetSchemaVersion(v int) { s.SchemaVersion = v }
func (s *NetworkCheckerDBSession) GetMigrationDate() time.Time { return s.MigrationDate }
func (s *NetworkCheckerDBSession) SetMigrationDate(v time.Time) { s.MigrationDate = v }
func (s *NetworkCheckerDBSession) GetActiveConnectionsCount() int { return s.ActiveConnectionsCount }
func (s *NetworkCheckerDBSession) SetActiveConnectionsCount(v int) { s.ActiveConnectionsCount = v }
func (s *NetworkCheckerDBSession) GetLocked() bool { return s.Locked }
func (s *NetworkCheckerDBSession) SetLocked(v bool) { s.Locked = v }

// NetworkCheckerCDNIPRange maps verified CDN networks blocks.
type NetworkCheckerCDNIPRange struct {
	RangeID      int
	CIDRBlock    string
	ProviderName string
}

// Getters & Setters for NetworkCheckerCDNIPRange
func (r *NetworkCheckerCDNIPRange) GetRangeID() int { return r.RangeID }
func (r *NetworkCheckerCDNIPRange) SetRangeID(v int) { r.RangeID = v }
func (r *NetworkCheckerCDNIPRange) GetCIDRBlock() string { return r.CIDRBlock }
func (r *NetworkCheckerCDNIPRange) SetCIDRBlock(v string) { r.CIDRBlock = v }
func (r *NetworkCheckerCDNIPRange) GetProviderName() string { return r.ProviderName }
func (r *NetworkCheckerCDNIPRange) SetProviderName(v string) { r.ProviderName = v }
