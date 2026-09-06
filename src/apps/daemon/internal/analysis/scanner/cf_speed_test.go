
package scanner

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// SpeedTestResult aggregates the measurements of the Cloudflare speed check.
type SpeedTestResult struct {
	IP           string
	DownloadKbps float64
	UploadKbps   float64
	Latency      time.Duration
}

// CfSpeedTest manages downloading and uploading test bytes to measure real speed.
type CfSpeedTest struct {
	IP string
}

// NewCfSpeedTest creates a speed test manager for a specific Cloudflare IP.
func NewCfSpeedTest(ip string) *CfSpeedTest {
	return &CfSpeedTest{IP: ip}
}

// Run executes the download/upload speed check.
func (t *CfSpeedTest) Run(ctx context.Context) (*SpeedTestResult, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				// Force connecting to the target speed test IP
				return d.DialContext(ctx, "tcp", fmt.Sprintf("%s:443", t.IP))
			},
		},
	}

	latency, err := t.measureLatency(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("speed_test: failed latency check: %w", err)
	}

	dlSpeed, err := t.measureDownload(ctx, client)
	if err != nil {
		dlSpeed = 0
	}

	ulSpeed, err := t.measureUpload(ctx, client)
	if err != nil {
		ulSpeed = 0
	}

	return &SpeedTestResult{
		IP:           t.IP,
		DownloadKbps: dlSpeed,
		UploadKbps:   ulSpeed,
		Latency:      latency,
	}, nil
}

func (t *CfSpeedTest) measureLatency(ctx context.Context, client *http.Client) (time.Duration, error) {
	req, _ := http.NewRequestWithContext(ctx, "HEAD", "https://speed.cloudflare.com/__down", nil)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return time.Since(start), nil
}

func (t *CfSpeedTest) measureDownload(ctx context.Context, client *http.Client) (float64, error) {
	// Download 1MB file
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://speed.cloudflare.com/__down?bytes=1048576", nil)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	written, err := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start).Seconds()
	if err != nil || elapsed <= 0 {
		return 0, err
	}

	// Speed in Kbps
	return (float64(written*8) / 1000.0) / elapsed, nil
}

func (t *CfSpeedTest) measureUpload(ctx context.Context, client *http.Client) (float64, error) {
	// Upload 256KB random bytes
	payload := make([]byte, 262144)
	_, _ = rand.Read(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://speed.cloudflare.com/__up", bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.ContentLength = int64(len(payload))

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		elapsed = 0.1
	}

	return (float64(len(payload)*8) / 1000.0) / elapsed, nil
}

