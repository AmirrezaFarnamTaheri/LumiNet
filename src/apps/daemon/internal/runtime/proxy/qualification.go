package proxy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/networking/proxyconfig"
)

// QualificationRequest is the external seam for an ephemeral proxy-quality session.
// Core process selection, tester construction, progress polling, and lifecycle stay internal.
type QualificationRequest struct {
	Proxies       []*proxyconfig.ProxyConfig
	Core          string
	CorePath      string
	TestURLs      []string
	Timeout       int
	Concurrency   int
	SpeedTest     bool
	GeoIP         bool
	DNSResolver   string
	StabilityRuns int
}

// QualificationProgress receives stable snapshots while a qualification session runs.
type QualificationProgress func(TestProgress)

func normalizeQualificationRequest(req QualificationRequest) (QualificationRequest, error) {
	if len(req.TestURLs) == 0 {
		req.TestURLs = []string{"http://cp.cloudflare.com/"}
	}
	if req.Timeout <= 0 {
		req.Timeout = 10
	}
	if req.Concurrency <= 0 {
		req.Concurrency = 8
	}
	if req.StabilityRuns <= 0 {
		req.StabilityRuns = 1
	}
	if len(req.Proxies) == 0 {
		return req, fmt.Errorf("proxy qualification requires at least one proxy")
	}
	if _, err := qualificationCoreType(req.Core); err != nil {
		return req, err
	}
	return req, nil
}

func qualificationCoreType(value string) (CoreType, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "auto":
		return CoreTypeAuto, nil
	case "xray":
		return CoreTypeXray, nil
	case "singbox", "sing-box":
		return CoreTypeSingBox, nil
	default:
		return "", fmt.Errorf("unsupported proxy core %q", value)
	}
}

// Qualify runs one bounded proxy qualification session. Callers submit intent and
// observe progress/results; concrete Xray/sing-box process mechanics remain internal.
func Qualify(ctx context.Context, request QualificationRequest, onProgress QualificationProgress) ([]*TestResult, error) {
	req, err := normalizeQualificationRequest(request)
	if err != nil {
		return nil, err
	}
	coreType, err := qualificationCoreType(req.Core)
	if err != nil {
		return nil, err
	}

	coreManager := NewCoreManager(coreType, req.CorePath)
	tester := NewProxyTester(TestConfig{
		TestURLs:         append([]string(nil), req.TestURLs...),
		Timeout:          req.Timeout,
		Concurrency:      req.Concurrency,
		SpeedTestEnabled: req.SpeedTest,
		GeoIPEnabled:     req.GeoIP,
		StabilityRuns:    req.StabilityRuns,
		DnsResolver:      req.DNSResolver,
	}, coreManager)

	done := make(chan struct{})
	if onProgress != nil {
		go func() {
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-done:
					return
				case <-ticker.C:
					if p := tester.Progress(); p != nil {
						onProgress(*p)
					}
				}
			}
		}()
	}

	err = tester.Start(ctx, req.Proxies)
	close(done)
	if onProgress != nil {
		if p := tester.Progress(); p != nil {
			onProgress(*p)
		}
	}
	if err != nil {
		return nil, err
	}
	return tester.Results(), nil
}
