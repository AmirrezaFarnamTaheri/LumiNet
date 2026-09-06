// Package certs implements certificate store and ACME utilities.
// Ported from: certmagic-master (filestorage.go, storage.go)
// Target path: server/internal/certs/certmagic_store.go

package certs

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"
)

// CertMagicStorage defines standard key-value storage used by CertMagic.
type CertMagicStorage interface {
	Exists(ctx context.Context, key string) bool
	Store(ctx context.Context, key string, value []byte) error
	Load(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string, recursive bool) ([]string, error)
	Lock(ctx context.Context, key string) error
	Unlock(ctx context.Context, key string) error
}

// CertMagicFileStorage implements CertMagicStorage on the local disk.
type CertMagicFileStorage struct {
	mu      sync.Mutex
	dirPath string
	locks   map[string]*fileLock
}

type fileLock struct {
	cancel context.CancelFunc
	done   chan struct{}
}

var (
	lockStaleDuration     = 5 * time.Minute
	lockHeartbeatInterval = 30 * time.Second
)

// ErrLockTimeout is returned when a certificate lock cannot be acquired.
var ErrLockTimeout = errors.New("certmagic: lock acquisition timed out")

// NewCertMagicFileStorage creates a CertMagicFileStorage directory.
func NewCertMagicFileStorage(dirPath string) *CertMagicFileStorage {
	return &CertMagicFileStorage{dirPath: dirPath, locks: make(map[string]*fileLock)}
}

func (s *CertMagicFileStorage) path(key string) (string, error) {
	if key == "" || strings.ContainsRune(key, '\x00') || filepath.IsAbs(key) || filepath.VolumeName(key) != "" {
		return "", fmt.Errorf("certmagic storage: invalid key %q", key)
	}
	parts := strings.Split(strings.ReplaceAll(key, "\\", "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("certmagic storage: invalid key %q", key)
		}
	}
	root := filepath.Clean(s.dirPath)
	resolved := filepath.Join(append([]string{root}, parts...)...)
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("certmagic storage: key escapes root %q", key)
	}
	return resolved, nil
}

func (s *CertMagicFileStorage) ensureNoSymlink(path string) error {
	root := filepath.Clean(s.dirPath)
	for candidate := root; ; {
		info, err := os.Lstat(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				break
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("certmagic storage: symlink path is not allowed: %q", candidate)
		}
		if candidate == path {
			break
		}
		rel, err := filepath.Rel(candidate, path)
		if err != nil || rel == "." {
			break
		}
		part := strings.Split(rel, string(filepath.Separator))[0]
		candidate = filepath.Join(candidate, part)
	}
	return nil
}

// Exists checks if the key exists.
func (s *CertMagicFileStorage) Exists(ctx context.Context, key string) bool {
	if ctx.Err() != nil {
		return false
	}
	p, err := s.path(key)
	if err != nil {
		return false
	}
	if err := s.ensureNoSymlink(p); err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = os.Stat(p)
	return err == nil
}

// Store writes value to key path.
func (s *CertMagicFileStorage) Store(ctx context.Context, key string, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := s.path(key)
	if err != nil {
		return err
	}
	if err := s.ensureNoSymlink(p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".certmagic-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(value); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, p)
}

// Load reads value from key path.
func (s *CertMagicFileStorage) Load(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := s.path(key)
	if err != nil {
		return nil, err
	}
	if err := s.ensureNoSymlink(p); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.ReadFile(p)
}

// Delete removes key path.
func (s *CertMagicFileStorage) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := s.path(key)
	if err != nil {
		return err
	}
	if err := s.ensureNoSymlink(p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// DeletePrefix removes a key and every descendant beneath it. It keeps path
// validation and symlink protection inside the canonical file-store boundary.
func (s *CertMagicFileStorage) DeletePrefix(ctx context.Context, prefix string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := s.path(prefix)
	if err != nil {
		return err
	}
	if err := s.ensureNoSymlink(p); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.RemoveAll(p); err != nil {
		return err
	}
	return nil
}

// Stat returns metadata for a validated storage key.
func (s *CertMagicFileStorage) Stat(ctx context.Context, key string) (os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p, err := s.path(key)
	if err != nil {
		return nil, err
	}
	if err := s.ensureNoSymlink(p); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.Stat(p)
}

// List scans files by prefix.
func (s *CertMagicFileStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root := s.dirPath
	if prefix != "" {
		var err error
		root, err = s.path(prefix)
		if err != nil {
			return nil, err
		}
	}
	if err := s.ensureNoSymlink(root); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var keys []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if !recursive && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(s.dirPath, p)
		if err == nil {
			keys = append(keys, filepath.ToSlash(rel))
		}
		return nil
	})
	if os.IsNotExist(err) {
		return nil, nil
	}
	return keys, err
}

// Lock acquires a named file lock. Lock files contain a heartbeat timestamp so
// a process can safely reclaim a lock left behind by a terminated owner.
func (s *CertMagicFileStorage) Lock(ctx context.Context, key string) error {
	p, err := s.path(key + ".lock")
	if err != nil {
		return err
	}
	if err := s.ensureNoSymlink(p); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	deadline := time.Now().Add(lockStaleDuration * 2)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return ErrLockTimeout
		}
		if data, err := os.ReadFile(p); err == nil {
			var heartbeat time.Time
			if heartbeat.UnmarshalText(data) == nil && time.Since(heartbeat) >= lockStaleDuration {
				_ = os.Remove(p)
			}
		}
		s.mu.Lock()
		file, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			timestamp, _ := time.Now().MarshalText()
			_, writeErr := file.Write(timestamp)
			closeErr := file.Close()
			if writeErr != nil || closeErr != nil {
				_ = os.Remove(p)
				s.mu.Unlock()
				if writeErr != nil {
					return writeErr
				}
				return closeErr
			}
			heartbeatCtx, cancel := context.WithCancel(ctx)
			entry := &fileLock{cancel: cancel, done: make(chan struct{})}
			s.locks[key] = entry
			s.mu.Unlock()
			go s.heartbeat(heartbeatCtx, p, entry)
			return nil
		}
		s.mu.Unlock()

		// Wait or check context
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (s *CertMagicFileStorage) heartbeat(ctx context.Context, lockPath string, entry *fileLock) {
	defer close(entry.done)
	ticker := time.NewTicker(lockHeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			timestamp, _ := time.Now().MarshalText()
			_ = os.WriteFile(lockPath, timestamp, 0o600)
		}
	}
}

// Unlock deletes lock file.
func (s *CertMagicFileStorage) Unlock(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := s.path(key + ".lock")
	if err != nil {
		return err
	}
	if err := s.ensureNoSymlink(p); err != nil {
		return err
	}
	s.mu.Lock()
	entry, ok := s.locks[key]
	if ok {
		delete(s.locks, key)
	}
	s.mu.Unlock()
	if ok {
		entry.cancel()
		<-entry.done
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// SafeCertStoreReader implements a thread-safe helper for copying file streams.
func SafeCertStoreReader(r io.Reader, w io.Writer) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		nr, rerr := r.Read(buf)
		if nr > 0 {
			nw, werr := w.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if werr != nil {
				return written, werr
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return written, rerr
		}
	}
	return written, nil
}

// FormatDomainStorageKey standardizes key generation.
func FormatDomainStorageKey(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}

// LockStorageKey creates lock key.
func LockStorageKey(domain string) string {
	return fmt.Sprintf("locks/%s", FormatDomainStorageKey(domain))
}

// RingBufferRateLimiter uses a ring buffer to enforce rate limits
// consisting of a maximum number of events within a single sliding window.
type RingBufferRateLimiter struct {
	window  time.Duration
	ring    []time.Time
	cursor  int
	mu      sync.Mutex
	started chan struct{}
	stopped chan struct{}
	ticket  chan struct{}
}

// NewRateLimiter returns a rate limiter that allows up to maxEvents in a sliding window.
func NewRateLimiter(maxEvents int, window time.Duration) *RingBufferRateLimiter {
	if maxEvents < 0 {
		panic("maxEvents cannot be less than zero")
	}
	if maxEvents == 0 && window != 0 {
		panic("NewRateLimiter: invalid configuration: maxEvents = 0 and window != 0 would not allow any events")
	}
	rbrl := &RingBufferRateLimiter{
		window:  window,
		ring:    make([]time.Time, maxEvents),
		started: make(chan struct{}),
		stopped: make(chan struct{}),
		ticket:  make(chan struct{}),
	}
	go rbrl.loop()
	<-rbrl.started
	return rbrl
}

// Stop cleans up the rate limiter goroutines.
func (r *RingBufferRateLimiter) Stop() {
	close(r.stopped)
}

func (r *RingBufferRateLimiter) loop() {
	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, 2048)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("panic: ring buffer rate limiter: %v\n%s", err, buf)
		}
	}()

	for {
		select {
		case <-r.stopped:
			return
		default:
		}

		if len(r.ring) == 0 {
			if r.window == 0 {
				r.permit()
				continue
			}
			panic("invalid configuration: maxEvents = 0 and window != 0 does not allow any events")
		}

		r.mu.Lock()
		then := r.ring[r.cursor].Add(r.window)
		r.mu.Unlock()
		waitDuration := time.Until(then)
		waitTimer := time.NewTimer(waitDuration)
		select {
		case <-waitTimer.C:
			r.permit()
		case <-r.stopped:
			waitTimer.Stop()
			return
		}
	}
}

// Allow returns true if the event is allowed to happen immediately.
func (r *RingBufferRateLimiter) Allow() bool {
	select {
	case <-r.ticket:
		return true
	default:
		return false
	}
}

// Wait blocks until the event is allowed or context is cancelled.
func (r *RingBufferRateLimiter) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.ticket:
		return nil
	}
}

// MaxEvents returns the maximum number of allowed events in the window.
func (r *RingBufferRateLimiter) MaxEvents() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ring)
}

// SetMaxEvents updates the max event limit.
func (r *RingBufferRateLimiter) SetMaxEvents(maxEvents int) {
	newRing := make([]time.Time, maxEvents)
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.window != 0 && maxEvents == 0 {
		panic("SetMaxEvents: invalid configuration: maxEvents = 0 and window != 0 would not allow any events")
	}

	if maxEvents == len(r.ring) {
		return
	}

	sizeDiff := len(r.ring) - maxEvents
	for i := 0; i < sizeDiff; i++ {
		r.advance()
	}

	if len(r.ring) > 0 {
		startCursor := r.cursor
		for i := 0; i < len(newRing); i++ {
			newRing[i] = r.ring[r.cursor]
			r.advance()
			if r.cursor == startCursor {
				break
			}
		}
	}

	r.ring = newRing
	r.cursor = 0
}

// Window returns the sliding window duration.
func (r *RingBufferRateLimiter) Window() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.window
}

// SetWindow updates the sliding window duration.
func (r *RingBufferRateLimiter) SetWindow(window time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if window != 0 && len(r.ring) == 0 {
		panic("SetWindow: invalid configuration: maxEvents = 0 and window != 0 would not allow any events")
	}
	r.window = window
}

func (r *RingBufferRateLimiter) permit() {
	for {
		select {
		case r.started <- struct{}{}:
			continue
		case <-r.stopped:
			return
		case r.ticket <- struct{}{}:
			r.mu.Lock()
			defer r.mu.Unlock()
			if len(r.ring) > 0 {
				r.ring[r.cursor] = time.Now()
				r.advance()
			}
			return
		}
	}
}

func (r *RingBufferRateLimiter) advance() {
	r.cursor++
	if r.cursor >= len(r.ring) {
		r.cursor = 0
	}
}

// OCSPConfig configures OCSP stapling operations.
type OCSPConfig struct {
	DisableStapling    bool              `json:"disable_stapling"`
	ResponderOverrides map[string]string `json:"responder_overrides,omitempty"`
	HTTPProxy          string            `json:"http_proxy,omitempty"`
}

// GetOCSPForCert queries OCSP status for PEM bundle.
// Maps to upstream getOCSPForCert() in ocsp.go.
func GetOCSPForCert(cfg OCSPConfig, bundle []byte) ([]byte, *ocsp.Response, error) {
	certificates, err := parseCertsFromPEMBundle(bundle)
	if err != nil {
		return nil, nil, err
	}
	if len(certificates) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in bundle")
	}

	issuedCert := certificates[0]
	if len(issuedCert.OCSPServer) == 0 {
		return nil, nil, errors.New("no OCSP server specified in certificate")
	}

	respURL := issuedCert.OCSPServer[0]
	if len(cfg.ResponderOverrides) > 0 {
		if override, ok := cfg.ResponderOverrides[respURL]; ok {
			respURL = override
		}
	}
	if respURL == "" {
		return nil, nil, fmt.Errorf("override disables querying OCSP responder: %v", issuedCert.OCSPServer[0])
	}

	httpClient := http.DefaultClient
	if cfg.HTTPProxy != "" {
		if proxyURL, err := url.Parse(cfg.HTTPProxy); err == nil {
			httpClient = &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(proxyURL),
				},
				Timeout: 30 * time.Second,
			}
		}
	}

	// get issuer certificate if needed
	if len(certificates) == 1 {
		if len(issuedCert.IssuingCertificateURL) == 0 {
			return nil, nil, fmt.Errorf("no URL to issuing certificate")
		}

		resp, err := httpClient.Get(issuedCert.IssuingCertificateURL[0])
		if err != nil {
			return nil, nil, fmt.Errorf("getting issuer certificate: %v", err)
		}
		defer resp.Body.Close()

		issuerBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			return nil, nil, fmt.Errorf("reading issuer certificate: %v", err)
		}

		issuerCert, err := x509.ParseCertificate(issuerBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing issuer certificate: %v", err)
		}
		certificates = append(certificates, issuerCert)
	}

	issuerCert := certificates[1]
	ocspReq, err := ocsp.CreateRequest(issuedCert, issuerCert, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("creating OCSP request: %v", err)
	}

	req, err := httpClient.Post(respURL, "application/ocsp-request", bytes.NewReader(ocspReq))
	if err != nil {
		return nil, nil, fmt.Errorf("making OCSP request: %v", err)
	}
	defer req.Body.Close()

	ocspResBytes, err := io.ReadAll(io.LimitReader(req.Body, 1024*1024))
	if err != nil {
		return nil, nil, fmt.Errorf("reading OCSP response: %v", err)
	}

	ocspRes, err := ocsp.ParseResponse(ocspResBytes, issuerCert)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing OCSP response: %v", err)
	}

	if err := ValidateOCSPResponder(ocspRes, issuerCert); err != nil {
		return nil, nil, fmt.Errorf("OCSP responder authorization check failed: %v", err)
	}

	return ocspResBytes, ocspRes, nil
}

// FreshOCSP returns true if OCSP response is still valid.
// Maps to upstream freshOCSP().
func FreshOCSP(resp *ocsp.Response) bool {
	nextUpdate := resp.NextUpdate
	if resp.Certificate != nil && resp.Certificate.NotAfter.Before(nextUpdate) {
		nextUpdate = resp.Certificate.NotAfter
	}
	refreshTime := resp.ThisUpdate.Add(nextUpdate.Sub(resp.ThisUpdate) / 2)
	return time.Now().Before(refreshTime)
}

// ValidateOCSPResponder enforces key usage checks.
// Maps to upstream validateOCSPResponder().
func ValidateOCSPResponder(ocspResp *ocsp.Response, issuerCert *x509.Certificate) error {
	respCert := ocspResp.Certificate
	if respCert == nil || respCert.Equal(issuerCert) {
		return nil
	}
	for _, eku := range respCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			return nil
		}
	}
	return fmt.Errorf("OCSP responder certificate (subject: %s) is not the issuer and does not carry id-kp-OCSPSigning", respCert.Subject)
}

func parseCertsFromPEMBundle(bundle []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	var block *pem.Block
	rest := bundle
	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		}
	}
	return certificates, nil
}
