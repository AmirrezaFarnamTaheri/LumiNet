package relayclient

import (
	"errors"
	"net"
	"sort"
	"time"
)

// quotaResetTZ is the Apps Script quota reset timezone (Pacific Time).
// Falls back to fixed -08:00 if timezone data is unavailable.
var quotaResetTZ = func() *time.Location {
	if loc, err := time.LoadLocation("America/Los_Angeles"); err == nil {
		return loc
	}
	return time.FixedZone("PST", -8*3600)
}()

// NextQuotaReset returns the next midnight in the Apps Script quota timezone strictly after now.
// Used to reset daily invocation counters across deployment IDs.
func NextQuotaReset(now time.Time) time.Time {
	inTZ := now.In(quotaResetTZ)
	midnight := time.Date(inTZ.Year(), inTZ.Month(), inTZ.Day()+1, 0, 0, 0, 0, quotaResetTZ)
	return midnight
}

// IsLocalNetworkOffline checks if an error corresponds to an offline local interface,
// DNS timeout, or temporary network failure, rather than remote censorship.
func IsLocalNetworkOffline(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsTimeout || dnsErr.IsTemporary || dnsErr.IsNotFound {
			return true
		}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return true
		}
		// String matching for common OS socket errors
		s := opErr.Error()
		if s != "" && (opErr.Op == "dial" || opErr.Op == "read") {
			return true
		}
	}
	return false
}

// FrontedProbeResult represents a latency test probe against a fronted host.
type FrontedProbeResult struct {
	Index   int
	Host    string
	Samples []time.Duration
	Err     error
}

// SelectFrontedClientIndexes selects the highest quality fronted host indexes,
// dropping failed probes and endpoints with latency > 2.5x the best sample.
func SelectFrontedClientIndexes(results []FrontedProbeResult) []int {
	type scoredHost struct {
		index   int
		avgRTT  time.Duration
	}

	var valid []scoredHost
	for _, res := range results {
		if res.Err != nil || len(res.Samples) == 0 {
			continue
		}
		var sum time.Duration
		for _, s := range res.Samples {
			sum += s
		}
		avg := sum / time.Duration(len(res.Samples))
		valid = append(valid, scoredHost{index: res.Index, avgRTT: avg})
	}

	if len(valid) == 0 {
		return nil
	}

	// Sort by average latency ascending
	sort.Slice(valid, func(i, j int) bool {
		return valid[i].avgRTT < valid[j].avgRTT
	})

	best := valid[0].avgRTT
	threshold := best * 5 / 2 // 2.5x best

	var selected []int
	for _, v := range valid {
		if v.avgRTT <= threshold {
			selected = append(selected, v.index)
		}
	}
	return selected
}
