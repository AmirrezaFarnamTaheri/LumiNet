package presets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Citizenlab updater defaults,
// analysis/citizenlab_test_lists_updater.py: test lists live in the
// citizenlab/test-lists repository, one list per country code plus a global.
const (
	CitizenlabBaseURL   = "https://raw.githubusercontent.com/citizenlab/test-lists/master/lists/"
	CitizenlabGlobalURL = CitizenlabBaseURL + "global.txt"

	citizenlabFetchTimeout = 30 * time.Second
	maxTestListEntries     = 100_000
)

// TestListFetcher retrieves URL lists. Abstracted for tests.
type TestListFetcher interface {
	Fetch(ctx context.Context, url string) ([]string, error)
}

// HTTPTestListFetcher fetches newline-separated URL lists over HTTP(S).
type HTTPTestListFetcher struct {
	Client *http.Client
}

// Fetch implements TestListFetcher.
func (f *HTTPTestListFetcher) Fetch(ctx context.Context, url string) ([]string, error) {
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: citizenlabFetchTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("citizenlab request %s: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("citizenlab fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("citizenlab fetch %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("citizenlab read %s: %w", url, err)
	}
	lines := strings.Split(string(body), "\n")
	list := make([]string, 0, len(lines))
	for _, line := range lines {
		entry := strings.TrimSpace(line)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		list = append(list, entry)
		if len(list) >= maxTestListEntries {
			break
		}
	}
	return list, nil
}

// CountryListURL returns the citizenlab list for a two-letter country code.
func CountryListURL(cc string) string {
	return CitizenlabBaseURL + strings.ToUpper(cc) + ".txt"
}

// RefreshResult summarises one scheduled refresh pass.
type RefreshResult struct {
	CountryCode string `json:"country_code"`
	Entries     int    `json:"entries"`
	DurationMS  int64  `json:"duration_ms"`
	Err         string `json:"error,omitempty"`
}

// RefreshCitizenlabLists fetches the global list plus any requested country
// lists. Failures per-country are recorded in the result and do not abort the
// remaining fetches — a partial refresh beats none.
func RefreshCitizenlabLists(ctx context.Context, fetcher TestListFetcher, countries []string) []RefreshResult {
	if fetcher == nil {
		fetcher = &HTTPTestListFetcher{}
	}
	targets := make([]string, 0, len(countries)+1)
	targets = append(targets, "global")
	for _, cc := range countries {
		targets = append(targets, strings.ToUpper(cc))
	}
	results := make([]RefreshResult, 0, len(targets))
	for _, cc := range targets {
		started := time.Now()
		url := CitizenlabGlobalURL
		if cc != "global" {
			url = CountryListURL(cc)
		}
		entries, err := fetcher.Fetch(ctx, url)
		result := RefreshResult{CountryCode: cc, Entries: len(entries)}
		if err != nil && ctx.Err() == nil {
			result.Err = err.Error()
		}
		result.DurationMS = time.Since(started).Milliseconds()
		results = append(results, result)
	}
	return results
}

// MarshalResults renders refresh results as JSON evidence for jobs history.
func MarshalResults(results []RefreshResult) ([]byte, error) {
	return json.MarshalIndent(results, "", "  ")
}
