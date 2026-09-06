package system

import (
	"testing"
	"time"
)

func TestTrafficMeterSmoother(t *testing.T) {
	m := NewTrafficMeterSmoother()
	m.Start(1000, 2000)

	// Step 1: 1 second, +102400 rx, +51200 tx
	s1 := m.SampleNow(1000+102400, 2000+51200, 1*time.Second)
	if s1.ReceivedBytes != 102400 || s1.SentBytes != 51200 {
		t.Fatalf("unexpected totals: %+v", s1)
	}
	if s1.DownloadBytesPerSec != 102400 || s1.UploadBytesPerSec != 51200 {
		t.Fatalf("unexpected rates: %+v", s1)
	}

	// Step 2: 1 second, +102400 rx, 0 tx
	s2 := m.SampleNow(1000+204800, 2000+51200, 1*time.Second)
	if s2.DownloadBytesPerSec != 102400 {
		t.Fatalf("expected download rate to remain 102400, got %d", s2.DownloadBytesPerSec)
	}
	if s2.UploadBytesPerSec != 20480 {
		t.Fatalf("expected smoothed upload rate 20480, got %d", s2.UploadBytesPerSec)
	}
}

func TestFormatBytesAndRate(t *testing.T) {
	if FormatBytes(500) != "500 B" {
		t.Fatalf("unexpected: %s", FormatBytes(500))
	}
	if FormatBytes(1536) != "1.5 KB" {
		t.Fatalf("unexpected: %s", FormatBytes(1536))
	}
	if FormatBytes(10*1024*1024) != "10 MB" {
		t.Fatalf("unexpected: %s", FormatBytes(10*1024*1024))
	}
	if FormatRate(10*1024*1024) != "10 MB/s" {
		t.Fatalf("unexpected: %s", FormatRate(10*1024*1024))
	}
}

func TestSplitTunnelPolicy(t *testing.T) {
	p := SplitTunnelPolicy{
		Mode:     SplitModeOnly,
		Packages: []string{"com.example.browser", "com.luminet.vpn"},
	}

	eff := p.EffectivePackages("com.luminet.vpn")
	if len(eff) != 1 || eff[0] != "com.example.browser" {
		t.Fatalf("expected self exclusion, got %v", eff)
	}

	if p.ValidationError("com.luminet.vpn") != "" {
		t.Fatalf("expected no validation error, got %s", p.ValidationError("com.luminet.vpn"))
	}

	pEmpty := SplitTunnelPolicy{
		Mode:     SplitModeOnly,
		Packages: []string{"com.luminet.vpn"},
	}
	if pEmpty.ValidationError("com.luminet.vpn") == "" {
		t.Fatalf("expected validation error for empty only list")
	}
}
