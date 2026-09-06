// Package scanner implements host and dns probing operations.

package scanner

import (
	"fmt"
	"time"
)

// NetProbeResult holds the outcome of single network reachability check.
type NetProbeResult struct {
	ProbeID        string        `json:"probe_id"`
	Success        bool          `json:"success"`
	HTTPStatus     int           `json:"http_status"`
	LatencyMs      time.Duration `json:"latency_ms"`
	IPResolved     string        `json:"ip_resolved"`
	HeaderServer   string        `json:"header_server,omitempty"`
	CertExpiryDays int           `json:"cert_expiry_days,omitempty"`
	ErrorMsg       string        `json:"error_msg,omitempty"`
}

// Getters & Setters for NetProbeResult
func (r *NetProbeResult) GetProbeID() string { return r.ProbeID }
func (r *NetProbeResult) SetProbeID(v string) { r.ProbeID = v }
func (r *NetProbeResult) GetSuccess() bool { return r.Success }
func (r *NetProbeResult) SetSuccess(v bool) { r.Success = v }

// NetProbeConfig defines parameters for periodic network probe test.
type NetProbeConfig struct {
	ProbeID             string        `json:"probe_id"`
	TargetURL           string        `json:"target_url"`
	HTTPMethod          string        `json:"http_method"` // GET, HEAD
	MaxRedirects        int           `json:"max_redirects"`
	DNSResolver         string        `json:"dns_resolver,omitempty"`
	RequestIntervalSecs int           `json:"request_interval_secs"`
	LatencyWarningMs    time.Duration `json:"latency_warning_ms"`
	FailureThreshold    int           `json:"failure_threshold"`
}

// Getters & Setters for NetProbeConfig
func (c *NetProbeConfig) GetTargetURL() string { return c.TargetURL }
func (c *NetProbeConfig) SetTargetURL(v string) { c.TargetURL = v }
func (c *NetProbeConfig) GetHTTPMethod() string { return c.HTTPMethod }
func (c *NetProbeConfig) SetHTTPMethod(v string) { c.HTTPMethod = v }

// FormatProbeIdentifier generates reachability tokens.
func (c *NetProbeConfig) FormatProbeIdentifier() string {
	return fmt.Sprintf("probe-%s-url-%s", c.ProbeID, c.TargetURL)
}

// Additional getters & setters for NetProbeResult
func (r *NetProbeResult) GetHTTPStatus() int { return r.HTTPStatus }
func (r *NetProbeResult) SetHTTPStatus(v int) { r.HTTPStatus = v }
func (r *NetProbeResult) GetLatencyMs() time.Duration { return r.LatencyMs }
func (r *NetProbeResult) SetLatencyMs(v time.Duration) { r.LatencyMs = v }
func (r *NetProbeResult) GetIPResolved() string { return r.IPResolved }
func (r *NetProbeResult) SetIPResolved(v string) { r.IPResolved = v }
func (r *NetProbeResult) GetHeaderServer() string { return r.HeaderServer }
func (r *NetProbeResult) SetHeaderServer(v string) { r.HeaderServer = v }
func (r *NetProbeResult) GetCertExpiryDays() int { return r.CertExpiryDays }
func (r *NetProbeResult) SetCertExpiryDays(v int) { r.CertExpiryDays = v }
func (r *NetProbeResult) GetErrorMsg() string { return r.ErrorMsg }
func (r *NetProbeResult) SetErrorMsg(v string) { r.ErrorMsg = v }

// Additional getters & setters for NetProbeConfig
func (c *NetProbeConfig) GetProbeID() string { return c.ProbeID }
func (c *NetProbeConfig) SetProbeID(v string) { c.ProbeID = v }
func (c *NetProbeConfig) GetMaxRedirects() int { return c.MaxRedirects }
func (c *NetProbeConfig) SetMaxRedirects(v int) { c.MaxRedirects = v }
func (c *NetProbeConfig) GetDNSResolver() string { return c.DNSResolver }
func (c *NetProbeConfig) SetDNSResolver(v string) { c.DNSResolver = v }
func (c *NetProbeConfig) GetRequestIntervalSecs() int { return c.RequestIntervalSecs }
func (c *NetProbeConfig) SetRequestIntervalSecs(v int) { c.RequestIntervalSecs = v }
func (c *NetProbeConfig) GetLatencyWarningMs() time.Duration { return c.LatencyWarningMs }
func (c *NetProbeConfig) SetLatencyWarningMs(v time.Duration) { c.LatencyWarningMs = v }
func (c *NetProbeConfig) GetFailureThreshold() int { return c.FailureThreshold }
func (c *NetProbeConfig) SetFailureThreshold(v int) { c.FailureThreshold = v }

// NetProbeHistory logs raw latency and cert parameters over time.
type NetProbeHistory struct {
	HistoryID     int
	RttMs         int
	DnsDurationMs int
	CertValid     bool
}

// Getters & Setters for NetProbeHistory
func (h *NetProbeHistory) GetHistoryID() int { return h.HistoryID }
func (h *NetProbeHistory) SetHistoryID(v int) { h.HistoryID = v }
func (h *NetProbeHistory) GetRttMs() int { return h.RttMs }
func (h *NetProbeHistory) SetRttMs(v int) { h.RttMs = v }
func (h *NetProbeHistory) GetDnsDurationMs() int { return h.DnsDurationMs }
func (h *NetProbeHistory) SetDnsDurationMs(v int) { h.DnsDurationMs = v }
func (h *NetProbeHistory) GetCertValid() bool { return h.CertValid }
func (h *NetProbeHistory) SetCertValid(v bool) { h.CertValid = v }

// NetProbeAlert represents warning thresholds triggered on target nodes.
type NetProbeAlert struct {
	AlertID       int
	RuleName      string
	MetricChecked string
}

// Getters & Setters for NetProbeAlert
func (a *NetProbeAlert) GetAlertID() int { return a.AlertID }
func (a *NetProbeAlert) SetAlertID(v int) { a.AlertID = v }
func (a *NetProbeAlert) GetRuleName() string { return a.RuleName }
func (a *NetProbeAlert) SetRuleName(v string) { a.RuleName = v }
func (a *NetProbeAlert) GetMetricChecked() string { return a.MetricChecked }
func (a *NetProbeAlert) SetMetricChecked(v string) { a.MetricChecked = v }

// NetProbeDevice logs scapy device discovery details.
type NetProbeDevice struct {
	IPAddress    string
	MACAddress   string
	Manufacturer string
	PacketSize   int
	Iface        string
	Confirmed    bool
}

// Getters & Setters for NetProbeDevice
func (d *NetProbeDevice) GetIPAddress() string { return d.IPAddress }
func (d *NetProbeDevice) SetIPAddress(v string) { d.IPAddress = v }
func (d *NetProbeDevice) GetMACAddress() string { return d.MACAddress }
func (d *NetProbeDevice) SetMACAddress(v string) { d.MACAddress = v }
func (d *NetProbeDevice) GetManufacturer() string { return d.Manufacturer }
func (d *NetProbeDevice) SetManufacturer(v string) { d.Manufacturer = v }
func (d *NetProbeDevice) GetPacketSize() int { return d.PacketSize }
func (d *NetProbeDevice) SetPacketSize(v int) { d.PacketSize = v }
func (d *NetProbeDevice) GetIface() string { return d.Iface }
func (d *NetProbeDevice) SetIface(v string) { d.Iface = v }
func (d *NetProbeDevice) GetConfirmed() bool { return d.Confirmed }
func (d *NetProbeDevice) SetConfirmed(v bool) { d.Confirmed = v }

// NetProbeFilter represents filters.
type NetProbeFilter struct {
	FilterID           int
	ManufacturerFilter string
	IPRangeFilter      string
	MinPacketSize      int
	Active             bool
}

// Getters & Setters for NetProbeFilter
func (f *NetProbeFilter) GetFilterID() int { return f.FilterID }
func (f *NetProbeFilter) SetFilterID(v int) { f.FilterID = v }
func (f *NetProbeFilter) GetManufacturerFilter() string { return f.ManufacturerFilter }
func (f *NetProbeFilter) SetManufacturerFilter(v string) { f.ManufacturerFilter = v }
func (f *NetProbeFilter) GetIPRangeFilter() string { return f.IPRangeFilter }
func (f *NetProbeFilter) SetIPRangeFilter(v string) { f.IPRangeFilter = v }
func (f *NetProbeFilter) GetMinPacketSize() int { return f.MinPacketSize }
func (f *NetProbeFilter) SetMinPacketSize(v int) { f.MinPacketSize = v }
func (f *NetProbeFilter) GetActive() bool { return f.Active }
func (f *NetProbeFilter) SetActive(v bool) { f.Active = v }

// NetProbeJob represents the scanner process limits.
type NetProbeJob struct {
	JobID        int
	TargetRange  string
	ScanRateSecs int
	OutputFile   string
	Running      bool
}

// Getters & Setters for NetProbeJob
func (j *NetProbeJob) GetJobID() int { return j.JobID }
func (j *NetProbeJob) SetJobID(v int) { j.JobID = v }
func (j *NetProbeJob) GetTargetRange() string { return j.TargetRange }
func (j *NetProbeJob) SetTargetRange(v string) { j.TargetRange = v }
func (j *NetProbeJob) GetScanRateSecs() int { return j.ScanRateSecs }
func (j *NetProbeJob) SetScanRateSecs(v int) { j.ScanRateSecs = v }
func (j *NetProbeJob) GetOutputFile() string { return j.OutputFile }
func (j *NetProbeJob) SetOutputFile(v string) { j.OutputFile = v }
func (j *NetProbeJob) GetRunning() bool { return j.Running }
func (j *NetProbeJob) SetRunning(v bool) { j.Running = v }
