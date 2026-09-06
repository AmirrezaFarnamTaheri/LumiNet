// Package scanner implements host and dns probing operations.

package scanner

import (
	"fmt"
	"sync"
	"time"
)

// SpeedEndpoint describes one test target used for the throughput/reachability step.
type SpeedEndpoint struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	Host           string `json:"host"`
	PinToCandidate bool   `json:"pin_to_candidate"`
	Reachability   bool   `json:"reachability"`
	UploadUrl      string `json:"upload_url"`
	Method         string `json:"method"`
	DownloadSize   int    `json:"download_size"`
	RetryCount     int    `json:"retry_count"`
	IsActive       bool   `json:"is_active"`
}

// Getters & Setters for SpeedEndpoint
func (s *SpeedEndpoint) GetName() string { return s.Name }
func (s *SpeedEndpoint) SetName(val string) { s.Name = val }
func (s *SpeedEndpoint) GetURL() string { return s.URL }
func (s *SpeedEndpoint) SetURL(val string) { s.URL = val }
func (s *SpeedEndpoint) GetHost() string { return s.Host }
func (s *SpeedEndpoint) SetHost(val string) { s.Host = val }
func (s *SpeedEndpoint) GetPinToCandidate() bool { return s.PinToCandidate }
func (s *SpeedEndpoint) SetPinToCandidate(val bool) { s.PinToCandidate = val }
func (s *SpeedEndpoint) GetReachability() bool { return s.Reachability }
func (s *SpeedEndpoint) SetReachability(val bool) { s.Reachability = val }
func (s *SpeedEndpoint) GetUploadUrl() string { return s.UploadUrl }
func (s *SpeedEndpoint) SetUploadUrl(val string) { s.UploadUrl = val }
func (s *SpeedEndpoint) GetMethod() string { return s.Method }
func (s *SpeedEndpoint) SetMethod(val string) { s.Method = val }
func (s *SpeedEndpoint) GetDownloadSize() int { return s.DownloadSize }
func (s *SpeedEndpoint) SetDownloadSize(val int) { s.DownloadSize = val }
func (s *SpeedEndpoint) GetRetryCount() int { return s.RetryCount }
func (s *SpeedEndpoint) SetRetryCount(val int) { s.RetryCount = val }
func (s *SpeedEndpoint) GetIsActive() bool { return s.IsActive }
func (s *SpeedEndpoint) SetIsActive(val bool) { s.IsActive = val }

// Builders for SpeedEndpoint
func (s *SpeedEndpoint) WithName(val string) *SpeedEndpoint { s.SetName(val); return s }
func (s *SpeedEndpoint) WithURL(val string) *SpeedEndpoint { s.SetURL(val); return s }
func (s *SpeedEndpoint) WithHost(val string) *SpeedEndpoint { s.SetHost(val); return s }
func (s *SpeedEndpoint) WithPinToCandidate(val bool) *SpeedEndpoint { s.SetPinToCandidate(val); return s }
func (s *SpeedEndpoint) WithReachability(val bool) *SpeedEndpoint { s.SetReachability(val); return s }
func (s *SpeedEndpoint) WithUploadUrl(val string) *SpeedEndpoint { s.SetUploadUrl(val); return s }
func (s *SpeedEndpoint) WithMethod(val string) *SpeedEndpoint { s.SetMethod(val); return s }
func (s *SpeedEndpoint) WithDownloadSize(val int) *SpeedEndpoint { s.SetDownloadSize(val); return s }
func (s *SpeedEndpoint) WithRetryCount(val int) *SpeedEndpoint { s.SetRetryCount(val); return s }
func (s *SpeedEndpoint) WithIsActive(val bool) *SpeedEndpoint { s.SetIsActive(val); return s }

// SpeedRankOptions tunes the Cloudflare-based speed benchmark used to rank clean IPs.
type SpeedRankOptions struct {
	mu                sync.RWMutex
	Port              int             `json:"port"`
	Concurrency       int             `json:"concurrency"`
	DownloadBytes     int             `json:"download_bytes"`
	UploadBytes       int             `json:"upload_bytes"`
	LossSamples       int             `json:"loss_samples"`
	Timeout           time.Duration   `json:"timeout"`
	SNI               string          `json:"sni"`
	DownloadEndpoints []SpeedEndpoint `json:"download_endpoints"`
	UploadEndpoints   []SpeedEndpoint `json:"upload_endpoints"`
	EnableBenchmark   bool            `json:"enable_benchmark"`
	LogVerbosity      int             `json:"log_verbosity"`
	MaxCandidates     int             `json:"max_candidates"`
	StoragePath       string          `json:"storage_path"`
	MinSpeed          float64         `json:"min_speed"`
	PingTimeout       time.Duration   `json:"ping_timeout"`
}

// Getters & Setters for SpeedRankOptions
func (o *SpeedRankOptions) GetPort() int { o.mu.RLock(); defer o.mu.RUnlock(); return o.Port }
func (o *SpeedRankOptions) SetPort(val int) { o.mu.Lock(); defer o.mu.Unlock(); o.Port = val }
func (o *SpeedRankOptions) GetConcurrency() int { o.mu.RLock(); defer o.mu.RUnlock(); return o.Concurrency }
func (o *SpeedRankOptions) SetConcurrency(val int) { o.mu.Lock(); defer o.mu.Unlock(); o.Concurrency = val }
func (o *SpeedRankOptions) GetDownloadBytes() int { o.mu.RLock(); defer o.mu.RUnlock(); return o.DownloadBytes }
func (o *SpeedRankOptions) SetDownloadBytes(val int) { o.mu.Lock(); defer o.mu.Unlock(); o.DownloadBytes = val }
func (o *SpeedRankOptions) GetUploadBytes() int { o.mu.RLock(); defer o.mu.RUnlock(); return o.UploadBytes }
func (o *SpeedRankOptions) SetUploadBytes(val int) { o.mu.Lock(); defer o.mu.Unlock(); o.UploadBytes = val }
func (o *SpeedRankOptions) GetLossSamples() int { o.mu.RLock(); defer o.mu.RUnlock(); return o.LossSamples }
func (o *SpeedRankOptions) SetLossSamples(val int) { o.mu.Lock(); defer o.mu.Unlock(); o.LossSamples = val }
func (o *SpeedRankOptions) GetTimeout() time.Duration { o.mu.RLock(); defer o.mu.RUnlock(); return o.Timeout }
func (o *SpeedRankOptions) SetTimeout(val time.Duration) { o.mu.Lock(); defer o.mu.Unlock(); o.Timeout = val }
func (o *SpeedRankOptions) GetSNI() string { o.mu.RLock(); defer o.mu.RUnlock(); return o.SNI }
func (o *SpeedRankOptions) SetSNI(val string) { o.mu.Lock(); defer o.mu.Unlock(); o.SNI = val }
func (o *SpeedRankOptions) GetDownloadEndpoints() []SpeedEndpoint { o.mu.RLock(); defer o.mu.RUnlock(); return o.DownloadEndpoints }
func (o *SpeedRankOptions) SetDownloadEndpoints(val []SpeedEndpoint) { o.mu.Lock(); defer o.mu.Unlock(); o.DownloadEndpoints = val }
func (o *SpeedRankOptions) GetUploadEndpoints() []SpeedEndpoint { o.mu.RLock(); defer o.mu.RUnlock(); return o.UploadEndpoints }
func (o *SpeedRankOptions) SetUploadEndpoints(val []SpeedEndpoint) { o.mu.Lock(); defer o.mu.Unlock(); o.UploadEndpoints = val }
func (o *SpeedRankOptions) GetEnableBenchmark() bool { o.mu.RLock(); defer o.mu.RUnlock(); return o.EnableBenchmark }
func (o *SpeedRankOptions) SetEnableBenchmark(val bool) { o.mu.Lock(); defer o.mu.Unlock(); o.EnableBenchmark = val }
func (o *SpeedRankOptions) GetLogVerbosity() int { o.mu.RLock(); defer o.mu.RUnlock(); return o.LogVerbosity }
func (o *SpeedRankOptions) SetLogVerbosity(val int) { o.mu.Lock(); defer o.mu.Unlock(); o.LogVerbosity = val }
func (o *SpeedRankOptions) GetMaxCandidates() int { o.mu.RLock(); defer o.mu.RUnlock(); return o.MaxCandidates }
func (o *SpeedRankOptions) SetMaxCandidates(val int) { o.mu.Lock(); defer o.mu.Unlock(); o.MaxCandidates = val }
func (o *SpeedRankOptions) GetStoragePath() string { o.mu.RLock(); defer o.mu.RUnlock(); return o.StoragePath }
func (o *SpeedRankOptions) SetStoragePath(val string) { o.mu.Lock(); defer o.mu.Unlock(); o.StoragePath = val }
func (o *SpeedRankOptions) GetMinSpeed() float64 { o.mu.RLock(); defer o.mu.RUnlock(); return o.MinSpeed }
func (o *SpeedRankOptions) SetMinSpeed(val float64) { o.mu.Lock(); defer o.mu.Unlock(); o.MinSpeed = val }
func (o *SpeedRankOptions) GetPingTimeout() time.Duration { o.mu.RLock(); defer o.mu.RUnlock(); return o.PingTimeout }
func (o *SpeedRankOptions) SetPingTimeout(val time.Duration) { o.mu.Lock(); defer o.mu.Unlock(); o.PingTimeout = val }

// Builders for SpeedRankOptions
func (o *SpeedRankOptions) WithPort(val int) *SpeedRankOptions { o.SetPort(val); return o }
func (o *SpeedRankOptions) WithConcurrency(val int) *SpeedRankOptions { o.SetConcurrency(val); return o }
func (o *SpeedRankOptions) WithDownloadBytes(val int) *SpeedRankOptions { o.SetDownloadBytes(val); return o }
func (o *SpeedRankOptions) WithUploadBytes(val int) *SpeedRankOptions { o.SetUploadBytes(val); return o }
func (o *SpeedRankOptions) WithLossSamples(val int) *SpeedRankOptions { o.SetLossSamples(val); return o }
func (o *SpeedRankOptions) WithTimeout(val time.Duration) *SpeedRankOptions { o.SetTimeout(val); return o }
func (o *SpeedRankOptions) WithSNI(val string) *SpeedRankOptions { o.SetSNI(val); return o }
func (o *SpeedRankOptions) WithDownloadEndpoints(val []SpeedEndpoint) *SpeedRankOptions { o.SetDownloadEndpoints(val); return o }
func (o *SpeedRankOptions) WithUploadEndpoints(val []SpeedEndpoint) *SpeedRankOptions { o.SetUploadEndpoints(val); return o }
func (o *SpeedRankOptions) WithEnableBenchmark(val bool) *SpeedRankOptions { o.SetEnableBenchmark(val); return o }
func (o *SpeedRankOptions) WithLogVerbosity(val int) *SpeedRankOptions { o.SetLogVerbosity(val); return o }
func (o *SpeedRankOptions) WithMaxCandidates(val int) *SpeedRankOptions { o.SetMaxCandidates(val); return o }
func (o *SpeedRankOptions) WithStoragePath(val string) *SpeedRankOptions { o.SetStoragePath(val); return o }
func (o *SpeedRankOptions) WithMinSpeed(val float64) *SpeedRankOptions { o.SetMinSpeed(val); return o }
func (o *SpeedRankOptions) WithPingTimeout(val time.Duration) *SpeedRankOptions { o.SetPingTimeout(val); return o }

// List modifiers for SpeedRankOptions
func (o *SpeedRankOptions) AddDownloadEndpoint(val SpeedEndpoint) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.DownloadEndpoints = append(o.DownloadEndpoints, val)
}

func (o *SpeedRankOptions) RemoveDownloadEndpoint(name string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i, v := range o.DownloadEndpoints {
		if v.Name == name {
			o.DownloadEndpoints = append(o.DownloadEndpoints[:i], o.DownloadEndpoints[i+1:]...)
			return true
		}
	}
	return false
}

func (o *SpeedRankOptions) AddUploadEndpoint(val SpeedEndpoint) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.UploadEndpoints = append(o.UploadEndpoints, val)
}

func (o *SpeedRankOptions) RemoveUploadEndpoint(name string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i, v := range o.UploadEndpoints {
		if v.Name == name {
			o.UploadEndpoints = append(o.UploadEndpoints[:i], o.UploadEndpoints[i+1:]...)
			return true
		}
	}
	return false
}

func (o *SpeedRankOptions) ClearDownloadEndpoints() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.DownloadEndpoints = make([]SpeedEndpoint, 0)
}

func (o *SpeedRankOptions) ClearUploadEndpoints() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.UploadEndpoints = make([]SpeedEndpoint, 0)
}

// Logic / Operations
func NewSpeedRankOptions(port int, sni string) *SpeedRankOptions {
	opts := &SpeedRankOptions{
		Port:            port,
		Concurrency:     16,
		DownloadBytes:   10 * 1024 * 1024,
		UploadBytes:     4 * 1024 * 1024,
		LossSamples:     10,
		Timeout:         5 * time.Second,
		SNI:             sni,
		EnableBenchmark: true,
		LogVerbosity:    1,
		MaxCandidates:   50,
		MinSpeed:        100.0,
		PingTimeout:     1500 * time.Millisecond,
	}
	opts.ApplyDefaults()
	return opts
}

func (o *SpeedRankOptions) ApplyDefaults() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.DownloadEndpoints) == 0 {
		o.DownloadEndpoints = []SpeedEndpoint{
			{
				Name:           "cloudflare",
				URL:            fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", o.DownloadBytes),
				Host:           "speed.cloudflare.com",
				PinToCandidate: true,
				IsActive:       true,
			},
		}
	}
}

func (o *SpeedRankOptions) ExecuteBenchmark(ip string) bool {
	return o.EnableBenchmark
}

func (o *SpeedRankOptions) ComputeThroughput(duration time.Duration, bytes int) float64 {
	if duration == 0 {
		return 0.0
	}
	return float64(bytes) / duration.Seconds()
}

func (o *SpeedRankOptions) ComputeJitter(latencies []time.Duration) time.Duration {
	if len(latencies) < 2 {
		return 0
	}
	var diffSum int64
	for i := 1; i < len(latencies); i++ {
		diff := int64(latencies[i] - latencies[i-1])
		if diff < 0 {
			diff = -diff
		}
		diffSum += diff
	}
	return time.Duration(diffSum / int64(len(latencies)-1))
}

func (o *SpeedRankOptions) ValidateOptions() bool {
	return o.Concurrency > 0 && o.Timeout > 0
}

func (o *SpeedRankOptions) SaveResults(path string) error {
	return nil
}

func (o *SpeedRankOptions) LoadResults(path string) error {
	return nil
}

func (o *SpeedRankOptions) ResetOptions() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.Concurrency = 16
	o.Timeout = 5 * time.Second
}
