// Package ui implements admin panel models, wireguard obfuscation, and subscription services.
// Ported from: NetManager-main (lib/l10n/)
// Target path: server/internal/ui/netmanager_locale.go

package ui

import (
	"fmt"
	"time"
)

// NetManagerLocaleConfig defines application translation metrics.
type NetManagerLocaleConfig struct {
	LanguageCode    string            `json:"language_code"`
	CountryCode     string            `json:"country_code"`
	TranslationsMap map[string]string `json:"translations_map"`
	TimeFormat      string            `json:"time_format"`
	NumberFormat    string            `json:"number_format"`
}

// Getters & Setters for NetManagerLocaleConfig
func (cfg *NetManagerLocaleConfig) GetLanguageCode() string { return cfg.LanguageCode }
func (cfg *NetManagerLocaleConfig) SetLanguageCode(v string) { cfg.LanguageCode = v }

// NetManagerDiagnosticReport tracks user network stats.
type NetManagerDiagnosticReport struct {
	ReportID       string    `json:"report_id"`
	Timestamp      time.Time `json:"timestamp"`
	NetworkType    string    `json:"network_type"` // wifi, cellular, ethernet
	ConnectedSince time.Time `json:"connected_since"`
	ErrorLogsCount int       `json:"error_logs_count"`
	PingLatencyMs  int64     `json:"ping_latency_ms"`
}

// Getters & Setters for NetManagerDiagnosticReport
func (r *NetManagerDiagnosticReport) GetReportID() string { return r.ReportID }
func (r *NetManagerDiagnosticReport) SetReportID(v string) { r.ReportID = v }
func (r *NetManagerDiagnosticReport) GetNetworkType() string { return r.NetworkType }
func (r *NetManagerDiagnosticReport) SetNetworkType(v string) { r.NetworkType = v }

// FormatReportSummary returns report identifier.
func (r *NetManagerDiagnosticReport) FormatReportSummary() string {
	return fmt.Sprintf("report-%s-type-%s-latency-%d", r.ReportID, r.NetworkType, r.PingLatencyMs)
}

// Additional getters & setters for NetManagerLocaleConfig
func (cfg *NetManagerLocaleConfig) GetCountryCode() string { return cfg.CountryCode }
func (cfg *NetManagerLocaleConfig) SetCountryCode(v string) { cfg.CountryCode = v }
func (cfg *NetManagerLocaleConfig) GetTranslationsMap() map[string]string { return cfg.TranslationsMap }
func (cfg *NetManagerLocaleConfig) SetTranslationsMap(v map[string]string) { cfg.TranslationsMap = v }
func (cfg *NetManagerLocaleConfig) GetTimeFormat() string { return cfg.TimeFormat }
func (cfg *NetManagerLocaleConfig) SetTimeFormat(v string) { cfg.TimeFormat = v }
func (cfg *NetManagerLocaleConfig) GetNumberFormat() string { return cfg.NumberFormat }
func (cfg *NetManagerLocaleConfig) SetNumberFormat(v string) { cfg.NumberFormat = v }

// Additional getters & setters for NetManagerDiagnosticReport
func (r *NetManagerDiagnosticReport) GetTimestamp() time.Time { return r.Timestamp }
func (r *NetManagerDiagnosticReport) SetTimestamp(v time.Time) { r.Timestamp = v }
func (r *NetManagerDiagnosticReport) GetConnectedSince() time.Time { return r.ConnectedSince }
func (r *NetManagerDiagnosticReport) SetConnectedSince(v time.Time) { r.ConnectedSince = v }
func (r *NetManagerDiagnosticReport) GetErrorLogsCount() int { return r.ErrorLogsCount }
func (r *NetManagerDiagnosticReport) SetErrorLogsCount(v int) { r.ErrorLogsCount = v }
func (r *NetManagerDiagnosticReport) GetPingLatencyMs() int64 { return r.PingLatencyMs }
func (r *NetManagerDiagnosticReport) SetPingLatencyMs(v int64) { r.PingLatencyMs = v }
