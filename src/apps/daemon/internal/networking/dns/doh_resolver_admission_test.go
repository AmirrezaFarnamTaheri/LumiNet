package dns

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type dohRoundTripFunc func(*http.Request) (*http.Response, error)

func (f dohRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func testDNSAResponseForQuery(t *testing.T, query []byte) []byte {
	t.Helper()
	if len(query) < 16 {
		t.Fatalf("query too short: %d", len(query))
	}
	resp := []byte{
		query[0], query[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	}
	resp = append(resp, query[12:]...)
	resp = append(resp,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
		203, 0, 113, 9,
	)
	return resp
}

func newBlockingDOHResolver(t *testing.T, slots int, started chan<- struct{}, release <-chan struct{}, active *atomic.Int32) *FailoverDOHResolver {
	t.Helper()
	r := NewFailoverDOHResolver(time.Minute)
	r.providers = []DoHProvider{{Name: "unit", URL: "https://unit.invalid/dns-query", Weight: 1}}
	r.geoIP = nil
	r.lookupSlots = make(chan struct{}, slots)
	r.client = &http.Client{
		Timeout: time.Second,
		Transport: dohRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			query, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			active.Add(1)
			defer active.Add(-1)
			select {
			case started <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytesReader(testDNSAResponseForQuery(t, query))),
				Header:     make(http.Header),
			}, nil
		}),
	}
	return r
}

type byteReader struct {
	b []byte
	i int
}

func bytesReader(b []byte) *byteReader { return &byteReader{b: b} }
func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func TestFailoverDOHSharedLookupSurvivesFirstWaiterCancellation(t *testing.T) {
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var active atomic.Int32
	r := newBlockingDOHResolver(t, 2, started, release, &active)

	ctx1, cancel1 := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, err := r.LookupHost(ctx1, "shared.example")
		first <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("shared lookup did not start")
	}

	second := make(chan error, 1)
	go func() {
		ips, err := r.LookupHost(context.Background(), "shared.example")
		if err == nil && (len(ips) != 1 || ips[0] != "203.0.113.9") {
			err = errors.New("unexpected DNS result")
		}
		second <- err
	}()

	// Give the second waiter time to join the existing singleflight call.
	time.Sleep(20 * time.Millisecond)
	cancel1()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first waiter error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first waiter did not observe cancellation")
	}

	close(release)
	select {
	case err := <-second:
		if err != nil {
			t.Fatalf("second waiter failed after first canceled: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second waiter did not complete")
	}
}

func TestFailoverDOHRejectsUniqueLookupWhenAdmissionIsFull(t *testing.T) {
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	var active atomic.Int32
	r := newBlockingDOHResolver(t, 2, started, release, &active)

	results := make(chan error, 2)
	for _, host := range []string{"one.example", "two.example"} {
		host := host
		go func() {
			_, err := r.LookupHost(context.Background(), host)
			results <- err
		}()
	}

	// Each admitted lookup races two upstream requests, so four blocked requests
	// proves both admission slots are occupied.
	for i := 0; i < 4; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d blocked upstream requests started", i)
		}
	}

	_, err := r.LookupHost(context.Background(), "three.example")
	if !errors.Is(err, errDOHLookupCapacity) {
		t.Fatalf("third unique lookup error = %v, want %v", err, errDOHLookupCapacity)
	}
	if got := active.Load(); got > 4 {
		t.Fatalf("active upstream requests = %d, want <= 4", got)
	}

	close(release)
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("admitted lookup failed: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("admitted lookup did not complete")
		}
	}
}

func TestValidateDNSResponseIdentityRejectsTransactionAndQuestionMismatch(t *testing.T) {
	query := buildDNSQuery("example.com")
	response := testDNSAResponseForQuery(t, query)
	if err := validateDNSResponseIdentity(query, response); err != nil {
		t.Fatalf("matching response rejected: %v", err)
	}

	wrongID := append([]byte(nil), response...)
	wrongID[1] ^= 0x01
	if err := validateDNSResponseIdentity(query, wrongID); err == nil {
		t.Fatal("transaction-ID mismatch was accepted")
	}

	wrongQuestion := append([]byte(nil), response...)
	wrongQuestion[13] = 'z'
	if err := validateDNSResponseIdentity(query, wrongQuestion); err == nil {
		t.Fatal("question mismatch was accepted")
	}
}
