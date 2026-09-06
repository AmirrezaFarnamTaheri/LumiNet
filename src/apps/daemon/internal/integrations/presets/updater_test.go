package presets

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRefreshCitizenlabListsGlobalAndCountries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/global.txt"):
			_, _ = w.Write([]byte("https://global.one\n# comment\n\nhttps://global.two\n"))
		case strings.HasSuffix(r.URL.Path, "/IR.txt"):
			_, _ = w.Write([]byte("https://ir.example\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	fetcher := &URLPrefixFetcher{Prefix: server.URL}
	results := RefreshCitizenlabLists(context.Background(), fetcher, []string{"ir"})
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	if results[0].CountryCode != "global" || results[0].Entries != 2 || results[0].Err != "" {
		t.Fatalf("global result wrong: %+v", results[0])
	}
	if results[1].CountryCode != "IR" || results[1].Entries != 1 {
		t.Fatalf("country result wrong: %+v", results[1])
	}
}

func TestRefreshContinuesPastFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/XX.txt") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("https://ok.example\n"))
	}))
	defer server.Close()
	fetcher := &URLPrefixFetcher{Prefix: server.URL}

	results := RefreshCitizenlabLists(context.Background(), fetcher, []string{"xx"})
	if len(results) != 2 { // global + xx
		t.Fatalf("results = %d", len(results))
	}
	hasErr := false
	for _, r := range results {
		if r.Err != "" {
			hasErr = true
		} else if r.Entries == 0 && r.CountryCode == "global" {
			t.Fatalf("global unexpectedly empty: %+v", r)
		}
	}
	if !hasErr {
		t.Fatal("expected one failing country entry")
	}
}

// URLPrefixFetcher redirects absolute citizenlab URLs at a test server.
type URLPrefixFetcher struct{ Prefix string }

func (f *URLPrefixFetcher) Fetch(ctx context.Context, url string) ([]string, error) {
	trimmed := strings.TrimPrefix(url, CitizenlabBaseURL)
	rewritten := f.Prefix + "/" + trimmed
	client := &http.Client{}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rewritten, nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body := new(strings.Builder)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			break
		}
	}
	lines := []string{}
	for _, l := range strings.Split(body.String(), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines, nil
}
