// Package decoy owns optional background HTTP noise generation.
package decoy

import (
	"context"
	"crypto/rand"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/remoteaction"
)

// Manager generates bounded background HTTP noise traffic.
type Manager struct {
	targets         []string
	volumePerMinute int
	httpClient      *http.Client

	mu        sync.Mutex
	running   bool
	cancel    context.CancelFunc
	loopWG    sync.WaitGroup
	requestWG sync.WaitGroup
}

// New creates a decoy traffic manager with conservative defaults.
func New(targets []string, volumePerMinute int) *Manager {
	if len(targets) == 0 {
		targets = []string{"https://www.google.com", "https://www.wikipedia.org"}
	}
	if volumePerMinute <= 0 {
		volumePerMinute = 120
	}
	return &Manager{
		targets:         append([]string(nil), targets...),
		volumePerMinute: volumePerMinute,
		httpClient:      &http.Client{Timeout: 5 * time.Second},
	}
}

// Start begins the background loop under the caller-owned lifetime.
func (m *Manager) Start(parent context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	m.running = true
	m.loopWG.Add(1)
	go m.loop(ctx)
}

// Stop cancels the loop and joins both scheduling and in-flight requests.
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	cancel := m.cancel
	m.cancel = nil
	m.running = false
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	m.loopWG.Wait()
	m.requestWG.Wait()
}

func (m *Manager) loop(ctx context.Context) {
	defer m.loopWG.Done()
	avgInterval := float64(15*60) / float64(m.volumePerMinute)
	if avgInterval < 1 {
		avgInterval = 1
	}

	for {
		delay := m.exponentialDelay(1 / avgInterval)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}

		target := m.pickRandomTarget()
		sizeKB := 1 + m.randomRange(29)
		payload := strings.Repeat("a", int(sizeKB*1024))
		m.requestWG.Add(1)
		go func() {
			defer m.requestWG.Done()
			m.sendDecoy(ctx, target, payload)
		}()
	}
}

func (m *Manager) pickRandomTarget() string {
	return m.targets[m.randomRange(int64(len(m.targets)))]
}

func (m *Manager) randomRange(max int64) int64 {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}

func (m *Manager) exponentialDelay(rate float64) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	u := 0.5
	if err == nil {
		u = float64(n.Int64()) / 1_000_000
	}
	if u == 0 {
		u = 0.00001
	}
	return time.Duration((-math.Log(u) / rate) * float64(time.Second))
}

func (m *Manager) sendDecoy(ctx context.Context, target, payload string) {
	policy := remoteaction.DefaultPolicy("decoy.http.emit", remoteaction.SingleAttempt)
	outcome, err := remoteaction.Do(ctx, m.httpClient, policy, func(ctx context.Context, _ int) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("X-Decoy-Traffic", "true")
		if parsed, err := url.Parse(target); err == nil {
			req.Header.Set("Host", parsed.Host)
		}
		return req, nil
	}, nil)
	if err != nil {
		return
	}
	resp := outcome.Response
	if resp == nil {
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
}
