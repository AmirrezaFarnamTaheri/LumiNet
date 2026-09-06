// Package vpngate provides a bounded parser and read-only directory client for
// the public VPN Gate server catalog. Runtime connection ownership remains in
// runtimecore (SSTP) or explicit profile engines.
package vpngate

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	CatalogURL            = "https://www.vpngate.net/api/iphone/"
	maxCatalogBytes int64 = 8 << 20
	maxServers            = 10000
)

type Server struct {
	HostName     string `json:"hostname"`
	IP           string `json:"ip"`
	Score        int64  `json:"score"`
	PingMS       int    `json:"ping_ms"`
	SpeedBPS     int64  `json:"speed_bps"`
	CountryLong  string `json:"country"`
	CountryShort string `json:"country_code"`
	Sessions     int    `json:"sessions"`
	UptimeMS     int64  `json:"uptime_ms"`
	TotalUsers   int64  `json:"total_users"`
	TotalTraffic int64  `json:"total_traffic_bytes"`
	Operator     string `json:"operator,omitempty"`
	Message      string `json:"message,omitempty"`
	SSTPServer   string `json:"sstp_server"`
	SSTPUsername string `json:"sstp_username"`
	SSTPPassword string `json:"sstp_password"`
}

type Filter struct {
	Country     string
	Limit       int
	MaxPingMS   int
	MinSpeedBPS int64
}

func Fetch(ctx context.Context, client *http.Client, filter Filter) ([]Server, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, CatalogURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch VPN Gate catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("VPN Gate catalog HTTP %d", resp.StatusCode)
	}
	return Parse(io.LimitReader(resp.Body, maxCatalogBytes+1), filter)
}

func Parse(r io.Reader, filter Filter) ([]Server, error) {
	br := bufio.NewReader(io.LimitReader(r, maxCatalogBytes+1))
	all, err := io.ReadAll(br)
	if err != nil {
		return nil, err
	}
	if int64(len(all)) > maxCatalogBytes {
		return nil, fmt.Errorf("VPN Gate catalog exceeds %d bytes", maxCatalogBytes)
	}
	lines := strings.Split(strings.ReplaceAll(string(all), "\r\n", "\n"), "\n")
	var csvLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		csvLines = append(csvLines, line)
	}
	if len(csvLines) < 2 {
		return nil, fmt.Errorf("VPN Gate catalog missing CSV header/data")
	}
	cr := csv.NewReader(strings.NewReader(strings.Join(csvLines, "\n")))
	cr.FieldsPerRecord = -1
	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parse VPN Gate CSV: %w", err)
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("VPN Gate catalog has no servers")
	}
	head := map[string]int{}
	for i, h := range records[0] {
		head[strings.TrimSpace(h)] = i
	}
	required := []string{"HostName", "IP", "Score", "Ping", "Speed", "CountryLong", "CountryShort", "NumVpnSessions", "Uptime", "TotalUsers", "TotalTraffic", "Operator", "Message"}
	for _, key := range required {
		if _, ok := head[key]; !ok {
			return nil, fmt.Errorf("VPN Gate catalog missing column %s", key)
		}
	}
	get := func(row []string, key string) string {
		i := head[key]
		if i < 0 || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}
	parseI64 := func(v string) int64 { n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64); return n }
	parseInt := func(v string) int { n, _ := strconv.Atoi(strings.TrimSpace(v)); return n }
	countryNeedle := strings.ToLower(strings.TrimSpace(filter.Country))
	out := make([]Server, 0, min(len(records)-1, maxServers))
	for _, row := range records[1:] {
		if len(out) >= maxServers {
			break
		}
		host := get(row, "HostName")
		ip := get(row, "IP")
		if host == "" || ip == "" {
			continue
		}
		countryLong := get(row, "CountryLong")
		countryShort := get(row, "CountryShort")
		if countryNeedle != "" && strings.ToLower(countryLong) != countryNeedle && strings.ToLower(countryShort) != countryNeedle {
			continue
		}
		ping := parseInt(get(row, "Ping"))
		speed := parseI64(get(row, "Speed"))
		if filter.MaxPingMS > 0 && (ping <= 0 || ping > filter.MaxPingMS) {
			continue
		}
		if filter.MinSpeedBPS > 0 && speed < filter.MinSpeedBPS {
			continue
		}
		out = append(out, Server{HostName: host, IP: ip, Score: parseI64(get(row, "Score")), PingMS: ping, SpeedBPS: speed, CountryLong: countryLong, CountryShort: countryShort, Sessions: parseInt(get(row, "NumVpnSessions")), UptimeMS: parseI64(get(row, "Uptime")), TotalUsers: parseI64(get(row, "TotalUsers")), TotalTraffic: parseI64(get(row, "TotalTraffic")), Operator: get(row, "Operator"), Message: get(row, "Message"), SSTPServer: host + ".opengw.net", SSTPUsername: "vpn", SSTPPassword: "vpn"})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].SpeedBPS != out[j].SpeedBPS {
			return out[i].SpeedBPS > out[j].SpeedBPS
		}
		pi, pj := out[i].PingMS, out[j].PingMS
		if pi <= 0 {
			pi = 1 << 30
		}
		if pj <= 0 {
			pj = 1 << 30
		}
		if pi != pj {
			return pi < pj
		}
		return out[i].HostName < out[j].HostName
	})
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
