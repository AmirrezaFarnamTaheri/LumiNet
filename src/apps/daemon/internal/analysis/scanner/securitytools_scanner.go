// Package scanner implements host and dns probing operations.

package scanner

import "time"

// SecurityToolRules defines scan signature definitions.
type SecurityToolRules struct {
	RuleID    int
	RuleName  string
	Signature string
	Severity  string
}

// Getters & Setters for SecurityToolRules
func (r *SecurityToolRules) GetRuleID() int { return r.RuleID }
func (r *SecurityToolRules) SetRuleID(v int) { r.RuleID = v }
func (r *SecurityToolRules) GetRuleName() string { return r.RuleName }
func (r *SecurityToolRules) SetRuleName(v string) { r.RuleName = v }
func (r *SecurityToolRules) GetSignature() string { return r.Signature }
func (r *SecurityToolRules) SetSignature(v string) { r.Signature = v }
func (r *SecurityToolRules) GetSeverity() string { return r.Severity }
func (r *SecurityToolRules) SetSeverity(v string) { r.Severity = v }

// SecurityToolScan holds diagnostic scanning inputs.
type SecurityToolScan struct {
	ScanID int
	Target string
	Result string
}

// Getters & Setters for SecurityToolScan
func (s *SecurityToolScan) GetScanID() int { return s.ScanID }
func (s *SecurityToolScan) SetScanID(v int) { s.ScanID = v }
func (s *SecurityToolScan) GetTarget() string { return s.Target }
func (s *SecurityToolScan) SetTarget(v string) { s.Target = v }
func (s *SecurityToolScan) GetResult() string { return s.Result }
func (s *SecurityToolScan) SetResult(v string) { s.Result = v }

// SecurityToolTorConfig represents Tor service configuration parameters.
type SecurityToolTorConfig struct {
	ControlPort           int
	SocksPort             int
	Interval              int
	ExitNodes             string
	StrictNodes           int
	CircuitBuildTimeout   int
	TorPass               string
	HashedControlPassword string
}

// Getters & Setters for SecurityToolTorConfig
func (c *SecurityToolTorConfig) GetControlPort() int { return c.ControlPort }
func (c *SecurityToolTorConfig) SetControlPort(v int) { c.ControlPort = v }
func (c *SecurityToolTorConfig) GetSocksPort() int { return c.SocksPort }
func (c *SecurityToolTorConfig) SetSocksPort(v int) { c.SocksPort = v }
func (c *SecurityToolTorConfig) GetInterval() int { return c.Interval }
func (c *SecurityToolTorConfig) SetInterval(v int) { c.Interval = v }
func (c *SecurityToolTorConfig) GetExitNodes() string { return c.ExitNodes }
func (c *SecurityToolTorConfig) SetExitNodes(v string) { c.ExitNodes = v }
func (c *SecurityToolTorConfig) GetStrictNodes() int { return c.StrictNodes }
func (c *SecurityToolTorConfig) SetStrictNodes(v int) { c.StrictNodes = v }
func (c *SecurityToolTorConfig) GetCircuitBuildTimeout() int { return c.CircuitBuildTimeout }
func (c *SecurityToolTorConfig) SetCircuitBuildTimeout(v int) { c.CircuitBuildTimeout = v }
func (c *SecurityToolTorConfig) GetTorPass() string { return c.TorPass }
func (c *SecurityToolTorConfig) SetTorPass(v string) { c.TorPass = v }
func (c *SecurityToolTorConfig) GetHashedControlPassword() string { return c.HashedControlPassword }
func (c *SecurityToolTorConfig) SetHashedControlPassword(v string) { c.HashedControlPassword = v }

// SecurityToolTorCircuit logs individual IP circuit rotations.
type SecurityToolTorCircuit struct {
	CircuitID   string
	CurrentIP   string
	CountryCode string
	Status      string
	LatencyMs   int
	RotatedAt   time.Time
}

// Getters & Setters for SecurityToolTorCircuit
func (t *SecurityToolTorCircuit) GetCircuitID() string { return t.CircuitID }
func (t *SecurityToolTorCircuit) SetCircuitID(v string) { t.CircuitID = v }
func (t *SecurityToolTorCircuit) GetCurrentIP() string { return t.CurrentIP }
func (t *SecurityToolTorCircuit) SetCurrentIP(v string) { t.CurrentIP = v }
func (t *SecurityToolTorCircuit) GetCountryCode() string { return t.CountryCode }
func (t *SecurityToolTorCircuit) SetCountryCode(v string) { t.CountryCode = v }
func (t *SecurityToolTorCircuit) GetStatus() string { return t.Status }
func (t *SecurityToolTorCircuit) SetStatus(v string) { t.Status = v }
func (t *SecurityToolTorCircuit) GetLatencyMs() int { return t.LatencyMs }
func (t *SecurityToolTorCircuit) SetLatencyMs(v int) { t.LatencyMs = v }

// SecurityToolTorService outlines systemd service options.
type SecurityToolTorService struct {
	Description string
	ExecStart   string
	RestartSec  int
	Enabled     bool
}

// Getters & Setters for SecurityToolTorService
func (v *SecurityToolTorService) GetDescription() string { return v.Description }
func (v *SecurityToolTorService) SetDescription(val string) { v.Description = val }
func (v *SecurityToolTorService) GetExecStart() string { return v.ExecStart }
func (v *SecurityToolTorService) SetExecStart(val string) { v.ExecStart = val }
func (v *SecurityToolTorService) GetEnabled() bool { return v.Enabled }
func (v *SecurityToolTorService) SetEnabled(val bool) { v.Enabled = val }
