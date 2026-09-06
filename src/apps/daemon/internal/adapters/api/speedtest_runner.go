package api

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSpeedtestBytes          = 1024 * 1024
	maxSpeedtestBytes              = 100 * 1024 * 1024
	defaultSpeedtestTimeoutSeconds = 15
	maxSpeedtestTimeoutSeconds     = 60
	defaultSpeedtestLatencySamples = 5
	maxSpeedtestLatencySamples     = 20
	maxSpeedtestRedirects          = 3
	speedtestProbeTimeout          = 2 * time.Second
)

// SpeedtestRequest specifies inputs for the speedtest.
type SpeedtestRequest struct {
	URL            string `json:"url,omitempty"`
	Bytes          int    `json:"bytes,omitempty"`
	Proxy          string `json:"proxy,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
	LatencySamples int    `json:"latency_samples,omitempty"`
}

// SpeedtestResponse contains the metrics computed during the speedtest.
type SpeedtestResponse struct {
	Success                  bool    `json:"success"`
	DownloadSpeedMbps        float64 `json:"download_speed_mbps"`
	DownloadTimeSeconds      float64 `json:"download_time_seconds"`
	TotalTimeSeconds         float64 `json:"total_time_seconds"`
	TotalTestTimeSeconds     float64 `json:"total_test_time_seconds"`
	ServerTimingSeconds      float64 `json:"server_timing_seconds"`
	LatencySamples           int     `json:"latency_samples"`
	LatencySuccessfulSamples int     `json:"latency_successful_samples"`
	PingMilliseconds         float64 `json:"ping_ms"`
	LatencyMilliseconds      float64 `json:"latency_ms"`
	JitterMilliseconds       float64 `json:"jitter_ms"`
	PacketLossPercent        float64 `json:"packet_loss_percent"`
	QualityStable            bool    `json:"quality_stable"`
	Error                    string  `json:"error,omitempty"`
}

func parseServerTiming(header string) float64 {
	if header == "" {
		return 0
	}
	parts := strings.Split(header, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "dur=") {
			valStr := strings.TrimPrefix(part, "dur=")
			if val, err := strconv.ParseFloat(valStr, 64); err == nil {
				return val / 1000.0 // convert ms to seconds
			}
		}
	}
	if idx := strings.Index(header, "="); idx != -1 {
		valStr := strings.TrimSpace(header[idx+1:])
		if val, err := strconv.ParseFloat(valStr, 64); err == nil {
			return val / 1000.0
		}
	}
	return 0
}

func normalizeSpeedtestRequest(req *SpeedtestRequest) error {
	if req.URL == "" {
		req.URL = "https://speed.cloudflare.com/__down"
	}
	parsed, err := url.Parse(req.URL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("url must be an absolute HTTP(S) URL")
	}
	if parsed.User != nil {
		return fmt.Errorf("url credentials are not allowed")
	}

	if req.Bytes <= 0 {
		req.Bytes = defaultSpeedtestBytes
	}
	if req.Bytes > maxSpeedtestBytes {
		return fmt.Errorf("bytes must not exceed %d", maxSpeedtestBytes)
	}

	if req.TimeoutSeconds <= 0 {
		req.TimeoutSeconds = defaultSpeedtestTimeoutSeconds
	}
	if req.TimeoutSeconds > maxSpeedtestTimeoutSeconds {
		return fmt.Errorf("timeout_seconds must not exceed %d", maxSpeedtestTimeoutSeconds)
	}

	if req.LatencySamples < 0 {
		return fmt.Errorf("latency_samples must not be negative")
	}
	if req.LatencySamples == 0 {
		req.LatencySamples = defaultSpeedtestLatencySamples
	}
	if req.LatencySamples > maxSpeedtestLatencySamples {
		return fmt.Errorf("latency_samples must not exceed %d", maxSpeedtestLatencySamples)
	}
	return nil
}

func parseSpeedtestProxy(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	proxyURL, err := url.Parse(raw)
	if err != nil || proxyURL.Host == "" {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	switch proxyURL.Scheme {
	case "http", "https", "socks5", "socks5h":
		return proxyURL, nil
	default:
		return nil, fmt.Errorf("proxy URL must use http, https, socks5, or socks5h")
	}
}

func newSpeedtestHTTPRequest(ctx context.Context, rawURL string, bytes int, latencyProbe bool) (*http.Request, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}

	if strings.EqualFold(httpReq.URL.Hostname(), "speed.cloudflare.com") {
		q := httpReq.URL.Query()
		if latencyProbe {
			q.Set("bytes", "0")
		} else {
			q.Set("bytes", strconv.Itoa(bytes))
		}
		httpReq.URL.RawQuery = q.Encode()
	} else if latencyProbe {
		httpReq.Header.Set("Range", "bytes=0-0")
	} else {
		httpReq.Header.Set("Range", fmt.Sprintf("bytes=0-%d", bytes-1))
	}
	httpReq.Header.Set("User-Agent", "LumiNet/Speedtest")
	httpReq.Header.Set("Accept-Encoding", "identity")
	return httpReq, nil
}

func measureSpeedtestLatency(ctx context.Context, client *http.Client, rawURL string, requestedSamples int) ([]time.Duration, int) {
	latencies := make([]time.Duration, 0, requestedSamples)
	attempts := 0
	for i := 0; i < requestedSamples; i++ {
		if ctx.Err() != nil {
			break
		}
		attempts++
		probeCtx, cancel := context.WithTimeout(ctx, speedtestProbeTimeout)
		httpReq, err := newSpeedtestHTTPRequest(probeCtx, rawURL, 0, true)
		if err != nil {
			cancel()
			continue
		}

		start := time.Now()
		resp, err := client.Do(httpReq)
		if err == nil {
			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent {
				_, _ = io.CopyN(io.Discard, resp.Body, 1)
				latencies = append(latencies, time.Since(start))
			}
			_ = resp.Body.Close()
		}
		cancel()
	}
	return latencies, attempts
}

func speedtestErrorResponse(summary speedtestLatencySummary, started time.Time, message string) SpeedtestResponse {
	return SpeedtestResponse{
		Success:                  false,
		TotalTestTimeSeconds:     time.Since(started).Seconds(),
		LatencySamples:           summary.Attempts,
		LatencySuccessfulSamples: summary.SuccessfulSamples,
		PingMilliseconds:         summary.PingMilliseconds,
		LatencyMilliseconds:      summary.LatencyMilliseconds,
		JitterMilliseconds:       summary.JitterMilliseconds,
		PacketLossPercent:        summary.PacketLossPercent,
		Error:                    message,
	}
}

func runSpeedtest(parent context.Context, req SpeedtestRequest) (SpeedtestResponse, int) {
	if err := normalizeSpeedtestRequest(&req); err != nil {
		return SpeedtestResponse{Success: false, Error: err.Error()}, http.StatusBadRequest
	}
	proxyURL, err := parseSpeedtestProxy(req.Proxy)
	if err != nil {
		return SpeedtestResponse{Success: false, Error: err.Error()}, http.StatusBadRequest
	}

	testStart := time.Now()
	ctx, cancel := context.WithTimeout(parent, time.Duration(req.TimeoutSeconds)*time.Second)
	defer cancel()

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxSpeedtestRedirects {
				return fmt.Errorf("speedtest redirect limit exceeded (%d)", maxSpeedtestRedirects)
			}
			if req.URL.User != nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
				return fmt.Errorf("speedtest redirect target must be credential-free HTTP(S)")
			}
			return nil
		},
	}

	latencies, latencyAttempts := measureSpeedtestLatency(ctx, client, req.URL, req.LatencySamples)
	latencySummary := summarizeSpeedtestLatency(latencies, latencyAttempts)

	httpReq, err := newSpeedtestHTTPRequest(ctx, req.URL, req.Bytes, false)
	if err != nil {
		return speedtestErrorResponse(latencySummary, testStart, fmt.Sprintf("failed to create http request: %v", err)), http.StatusInternalServerError
	}

	startTime := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return speedtestErrorResponse(latencySummary, testStart, fmt.Sprintf("http request failed: %v", err)), http.StatusBadGateway
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return speedtestErrorResponse(latencySummary, testStart, fmt.Sprintf("unexpected response status: %s", resp.Status)), http.StatusBadGateway
	}

	// Do not trust Range support or Content-Length from an arbitrary test server.
	// Read at most one byte beyond the caller-approved budget so an origin that
	// ignores Range cannot turn diagnostics into an unbounded download.
	if resp.ContentLength > int64(req.Bytes) {
		return speedtestErrorResponse(latencySummary, testStart, fmt.Sprintf("response exceeds requested byte budget (%d > %d)", resp.ContentLength, req.Bytes)), http.StatusBadGateway
	}
	totalRead, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, int64(req.Bytes)+1))
	if readErr != nil {
		return speedtestErrorResponse(latencySummary, testStart, fmt.Sprintf("error reading response body: %v", readErr)), http.StatusBadGateway
	}
	if totalRead > int64(req.Bytes) {
		return speedtestErrorResponse(latencySummary, testStart, fmt.Sprintf("response exceeded requested byte budget (%d)", req.Bytes)), http.StatusBadGateway
	}

	totalTime := time.Since(startTime).Seconds()
	serverTimingSeconds := parseServerTiming(resp.Header.Get("Server-Timing"))
	downloadTime := totalTime - serverTimingSeconds
	if downloadTime <= 0 {
		downloadTime = totalTime
		if downloadTime <= 0 {
			downloadTime = 0.001
		}
	}
	downloadSpeedMbps := (float64(totalRead) * 8.0) / (downloadTime * 1000000.0)

	return SpeedtestResponse{
		Success:                  true,
		DownloadSpeedMbps:        downloadSpeedMbps,
		DownloadTimeSeconds:      downloadTime,
		TotalTimeSeconds:         totalTime,
		TotalTestTimeSeconds:     time.Since(testStart).Seconds(),
		ServerTimingSeconds:      serverTimingSeconds,
		LatencySamples:           latencySummary.Attempts,
		LatencySuccessfulSamples: latencySummary.SuccessfulSamples,
		PingMilliseconds:         latencySummary.PingMilliseconds,
		LatencyMilliseconds:      latencySummary.LatencyMilliseconds,
		JitterMilliseconds:       latencySummary.JitterMilliseconds,
		PacketLossPercent:        latencySummary.PacketLossPercent,
		QualityStable:            speedtestQualityStable(latencySummary, downloadSpeedMbps),
	}, http.StatusOK
}
