// Copyright 2024-2026 LumiNet Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package system

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// DesktopRoutingRule represents a single rule for desktop proxy routing.
type DesktopRoutingRule struct {
	Type       string `json:"type"`        // "domain", "ip", "range"
	Value      string `json:"value"`       // e.g. "example.com", "192.168.1.1", "10.0.*"
	IsWildcard bool   `json:"is_wildcard"` // true if value starts with or contains '*'
	ForceProxy bool   `json:"force_proxy"` // true if rule starts with '!' exception
}

// ParseDesktopRoutingRules parses a serialized routing rules string into structured rules.
// Matches oblivion-desktop setRoutingRules behavior.
func ParseDesktopRoutingRules(raw string) []DesktopRoutingRule {
	var rules []DesktopRoutingRule
	if strings.TrimSpace(raw) == "" {
		return rules
	}

	cleaned := strings.ReplaceAll(raw, "<br>", ",")
	cleaned = strings.ReplaceAll(cleaned, "\n", ",")
	cleaned = strings.ReplaceAll(cleaned, "\r", "")

	tokens := strings.Split(cleaned, ",")
	for _, token := range tokens {
		t := strings.TrimSpace(token)
		if t == "" || strings.HasPrefix(t, "app:") {
			continue
		}

		ruleType := "domain"
		val := t

		if idx := strings.Index(t, ":"); idx != -1 {
			ruleType = strings.ToLower(strings.TrimSpace(t[:idx]))
			val = strings.TrimSpace(t[idx+1:])
		}

		forceProxy := false
		if strings.HasPrefix(ruleType, "!") {
			forceProxy = true
			ruleType = ruleType[1:]
		}
		if strings.HasPrefix(val, "!") {
			forceProxy = true
			val = val[1:]
		}

		isWildcard := strings.HasPrefix(ruleType, "*") || strings.HasPrefix(val, "*") || strings.Contains(val, "*")
		ruleType = strings.TrimPrefix(ruleType, "*")
		cleanVal := strings.TrimPrefix(val, "*")

		rules = append(rules, DesktopRoutingRule{
			Type:       ruleType,
			Value:      cleanVal,
			IsWildcard: isWildcard,
			ForceProxy: forceProxy,
		})
	}

	return rules
}

// NetStatsSnapshot captures instantaneous and aggregated network throughput metrics.
type NetStatsSnapshot struct {
	Timestamp      time.Time `json:"timestamp"`
	BytesSent      uint64    `json:"bytes_sent"`
	BytesReceived  uint64    `json:"bytes_received"`
	UploadSpeed    float64   `json:"upload_speed_bps"` // bytes/sec
	DownloadSpeed  float64   `json:"download_speed_bps"`
	PeakUpload     float64   `json:"peak_upload_bps"`
	PeakDownload   float64   `json:"peak_download_bps"`
	TotalSent      uint64    `json:"total_sent"`
	TotalReceived  uint64    `json:"total_received"`
}

// NetStatsSampler periodically measures traffic deltas and rolling bandwidth.
type NetStatsSampler struct {
	mu           sync.RWMutex
	lastTime     time.Time
	lastSent     uint64
	lastRecv     uint64
	totalSent    uint64
	totalRecv    uint64
	peakUpload   float64
	peakDownload float64
	lastSnapshot NetStatsSnapshot
}

// NewNetStatsSampler initializes the sampler.
func NewNetStatsSampler() *NetStatsSampler {
	now := time.Now()
	return &NetStatsSampler{
		lastTime: now,
		lastSnapshot: NetStatsSnapshot{
			Timestamp: now,
		},
	}
}

// RecordSample updates the sampler with raw cumulative byte counters.
func (s *NetStatsSampler) RecordSample(currentSent, currentRecv uint64) NetStatsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(s.lastTime).Seconds()
	if elapsed <= 0 {
		elapsed = 1.0
	}

	var deltaSent, deltaRecv uint64
	if currentSent >= s.lastSent {
		deltaSent = currentSent - s.lastSent
	}
	if currentRecv >= s.lastRecv {
		deltaRecv = currentRecv - s.lastRecv
	}

	uploadBps := float64(deltaSent) / elapsed
	downloadBps := float64(deltaRecv) / elapsed

	if uploadBps > s.peakUpload {
		s.peakUpload = uploadBps
	}
	if downloadBps > s.peakDownload {
		s.peakDownload = downloadBps
	}

	s.totalSent += deltaSent
	s.totalRecv += deltaRecv

	s.lastSent = currentSent
	s.lastRecv = currentRecv
	s.lastTime = now

	s.lastSnapshot = NetStatsSnapshot{
		Timestamp:     now,
		BytesSent:     deltaSent,
		BytesReceived: deltaRecv,
		UploadSpeed:   uploadBps,
		DownloadSpeed: downloadBps,
		PeakUpload:    s.peakUpload,
		PeakDownload:  s.peakDownload,
		TotalSent:     s.totalSent,
		TotalReceived: s.totalRecv,
	}

	return s.lastSnapshot
}

// GetLatestSnapshot returns the latest network metrics.
func (s *NetStatsSampler) GetLatestSnapshot() NetStatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSnapshot
}

// CloudflareColoLocation represents geo-metadata for a Cloudflare edge POP airport code.
type CloudflareColoLocation struct {
	AirportCode string `json:"airport_code"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	FlagEmoji   string `json:"flag_emoji"`
}

// ResolveColoLocation maps a Cloudflare edge colocation IATA code to its country and flag.
func ResolveColoLocation(iataCode string) CloudflareColoLocation {
	code := strings.ToUpper(strings.TrimSpace(iataCode))

	coloMap := map[string]CloudflareColoLocation{
		"FRA": {AirportCode: "FRA", CountryCode: "DE", CountryName: "Germany", FlagEmoji: "🇩🇪"},
		"LHR": {AirportCode: "LHR", CountryCode: "GB", CountryName: "United Kingdom", FlagEmoji: "🇬🇧"},
		"AMS": {AirportCode: "AMS", CountryCode: "NL", CountryName: "Netherlands", FlagEmoji: "🇳🇱"},
		"CDG": {AirportCode: "CDG", CountryCode: "FR", CountryName: "France", FlagEmoji: "🇫🇷"},
		"DOH": {AirportCode: "DOH", CountryCode: "QA", CountryName: "Qatar", FlagEmoji: "🇶🇦"},
		"DXB": {AirportCode: "DXB", CountryCode: "AE", CountryName: "United Arab Emirates", FlagEmoji: "🇦🇪"},
		"IST": {AirportCode: "IST", CountryCode: "TR", CountryName: "Turkey", FlagEmoji: "🇹🇷"},
		"NRT": {AirportCode: "NRT", CountryCode: "JP", CountryName: "Japan", FlagEmoji: "🇯🇵"},
		"SIN": {AirportCode: "SIN", CountryCode: "SG", CountryName: "Singapore", FlagEmoji: "🇸🇬"},
		"HKG": {AirportCode: "HKG", CountryCode: "HK", CountryName: "Hong Kong", FlagEmoji: "🇭🇰"},
		"LAX": {AirportCode: "LAX", CountryCode: "US", CountryName: "United States", FlagEmoji: "🇺🇸"},
		"JFK": {AirportCode: "JFK", CountryCode: "US", CountryName: "United States", FlagEmoji: "🇺🇸"},
		"ORD": {AirportCode: "ORD", CountryCode: "US", CountryName: "United States", FlagEmoji: "🇺🇸"},
		"ARN": {AirportCode: "ARN", CountryCode: "SE", CountryName: "Sweden", FlagEmoji: "🇸🇪"},
		"HEL": {AirportCode: "HEL", CountryCode: "FI", CountryName: "Finland", FlagEmoji: "🇫🇮"},
		"VIE": {AirportCode: "VIE", CountryCode: "AT", CountryName: "Austria", FlagEmoji: "🇦🇹"},
		"ZRH": {AirportCode: "ZRH", CountryCode: "CH", CountryName: "Switzerland", FlagEmoji: "🇨🇭"},
	}

	if loc, found := coloMap[code]; found {
		return loc
	}

	return CloudflareColoLocation{
		AirportCode: code,
		CountryCode: "XX",
		CountryName: "Global Edge",
		FlagEmoji:   "🌐",
	}
}

// ResolveIspName maps an Autonomous System Number (ASN) to a friendly human-readable name.
func ResolveIspName(asn int) string {
	asnMap := map[int]string{
		197207: "MCI (Mobile Telecommunication Co of Iran)",
		44244:  "Irancell (MTN Irancell Telecommunications)",
		57218:  "Rightel",
		58224:  "TCI (Telecommunication Company of Iran)",
		25184:  "Afranet",
		48159:  "Shatel",
		31549:  "Pars Online",
		16322:  "Asiatech",
		13335:  "Cloudflare, Inc.",
		15169:  "Google LLC",
		16509:  "Amazon.com, Inc.",
		14061:  "DigitalOcean, LLC",
		24940:  "Hetzner Online GmbH",
		16276:  "OVH SAS",
	}

	if name, found := asnMap[asn]; found {
		return name
	}
	return fmt.Sprintf("AS%d", asn)
}
