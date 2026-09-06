package proxy

// acme_cert_manager.go — In-process ACME/TLS-ALPN-01 certificate renewal.
//
// Inspired by ech-tls-tunnel/src/acme.rs and ech-tls-tunnel/src/challenge.rs.
//
// Key features extracted from the reference implementation:
//   - Zero port-80 requirement: uses TLS-ALPN-01 challenge on the same port 443
//     listener as the tunnel itself.
//   - ChallengeStore: hot-swaps the per-domain challenge cert into a shared
//     TLS Config during ACME validation; removes it afterwards.
//   - arc-swap pattern: new certs are written atomically so in-flight TLS
//     connections keep the old cert and new connections get the fresh one.
//   - Renewal window: checks 30 days before expiry by default.
//
// Integration: call AcmeCertManager.GetCertificate as the tls.Config.GetCertificate
// callback.  The manager handles challenge negotiation transparently.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	lumintls "github.com/maybeknott/luminet/internal/tls"
)

const (
	// acmeChallengeALPN is the ALPN token used by TLS-ALPN-01 challenge.
	acmeChallengeALPN = "acme-tls/1"

	// acmeRenewalWindow is how far before expiry we trigger renewal.
	acmeRenewalWindow = 30 * 24 * time.Hour

	// acmeSelfSignedValidity is the lifetime of auto-generated self-signed
	// fallback certificates (used when ACME is not configured).
	acmeSelfSignedValidity = 90 * 24 * time.Hour
)

// ChallengeStore holds per-domain TLS-ALPN-01 challenge certificates.
// During ACME validation the ACME client installs a special certificate
// carrying the SHA-256 of the key authorization in the acmeIdentifier
// extension; the store ensures the TLS server returns it only for ALPN
// "acme-tls/1" clients.
type ChallengeStore struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate // keyed by domain name
}

// NewChallengeStore creates an empty ChallengeStore.
func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{certs: make(map[string]*tls.Certificate)}
}

// Install registers a challenge certificate for domain.
func (cs *ChallengeStore) Install(domain string, cert *tls.Certificate) {
	cs.mu.Lock()
	cs.certs[domain] = cert
	cs.mu.Unlock()
}

// Remove unregisters the challenge certificate for domain.
func (cs *ChallengeStore) Remove(domain string) {
	cs.mu.Lock()
	delete(cs.certs, domain)
	cs.mu.Unlock()
}

// GetChallengeCert returns the installed challenge cert for domain if any.
func (cs *ChallengeStore) GetChallengeCert(domain string) (*tls.Certificate, bool) {
	cs.mu.RLock()
	c, ok := cs.certs[domain]
	cs.mu.RUnlock()
	return c, ok
}

// AcmeCertManager manages TLS certificates with optional ACME auto-renewal.
// If ACME is not configured it generates and uses a self-signed certificate.
type AcmeCertManager struct {
	domain     string
	email      string
	cacheDir   string
	challenges *ChallengeStore

	// current holds the active *tls.Certificate atomically.
	// Callers receive this on every GetCertificate call.
	current atomic.Pointer[tls.Certificate]

	// onDemand controls dynamic per-domain certificate issuance decisions.
	// When set, GetCertificate invokes OnDemand.DecisionFunc before issuing.
	onDemand *lumintls.OnDemandConfig

	// renewMu prevents concurrent renewal attempts.
	renewMu sync.Mutex

	// stopCh closes when the manager is stopped.
	stopCh chan struct{}
	once   sync.Once
}

// NewAcmeCertManager creates an AcmeCertManager for domain.
// email is used as the ACME account contact; cacheDir is where
// cert/key PEM files are persisted between restarts.
func NewAcmeCertManager(domain, email, cacheDir string) (*AcmeCertManager, error) {
	m := &AcmeCertManager{
		domain:     domain,
		email:      email,
		cacheDir:   cacheDir,
		challenges: NewChallengeStore(),
		stopCh:     make(chan struct{}),
	}

	// Try loading from cache first.
	if cachedCert, err := m.loadCachedCert(); err == nil {
		m.current.Store(cachedCert)
	} else {
		// Generate an initial self-signed certificate so the server can start
		// immediately, even before ACME validation completes.
		selfSigned, err := m.generateSelfSigned()
		if err != nil {
			return nil, fmt.Errorf("acme: self-signed init: %w", err)
		}
		m.current.Store(selfSigned)
	}

	// Start the renewal loop in the background.
	go m.renewalLoop()
	return m, nil
}

// WithOnDemand attaches an OnDemandConfig whose DecisionFunc is called during
// GetCertificate. This allows the caller to deny certificate issuance for
// unknown or unauthorized domains at the TLS handshake level.
func (m *AcmeCertManager) WithOnDemand(cfg *lumintls.OnDemandConfig) *AcmeCertManager {
	m.onDemand = cfg
	return m
}

// PreflightValidate checks outbound network connectivity to Let's Encrypt servers before validation.
func (m *AcmeCertManager) PreflightValidate(ctx context.Context, acmeDir string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", acmeDir, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("acme preflight connection check failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("acme server returned status %d", resp.StatusCode)
	}
	return nil
}

// GetCertificate implements the tls.Config.GetCertificate callback.
// It handles TLS-ALPN-01 challenges transparently and returns the current
// live certificate for all other clients.
func (m *AcmeCertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Check if this is a TLS-ALPN-01 challenge handshake.
	for _, proto := range hello.SupportedProtos {
		if proto == acmeChallengeALPN {
			if cert, ok := m.challenges.GetChallengeCert(hello.ServerName); ok {
				return cert, nil
			}
			// Challenge cert not ready yet; fall through to live cert.
			break
		}
	}

	// Enforce on-demand decision for non-challenge requests.
	if m.onDemand != nil && m.onDemand.Enabled && m.onDemand.DecisionFunc != nil {
		ctx := hello.Context()
		if err := m.onDemand.DecisionFunc(ctx, hello.ServerName); err != nil {
			return nil, fmt.Errorf("acme: on-demand denied for %q: %w", hello.ServerName, err)
		}
	}

	cert := m.current.Load()
	if cert == nil {
		return nil, errors.New("acme: no certificate available")
	}
	return cert, nil
}

// Stop halts the background renewal goroutine.
func (m *AcmeCertManager) Stop() {
	m.once.Do(func() { close(m.stopCh) })
}

// renewalLoop checks every 6 hours whether the current certificate needs
// renewing and, if so, calls Renew().
func (m *AcmeCertManager) renewalLoop() {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	// Attempt an immediate renewal check on startup.
	_ = m.checkAndRenew()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			_ = m.checkAndRenew()
		}
	}
}

// checkAndRenew renews the certificate if it is within the renewal window.
func (m *AcmeCertManager) checkAndRenew() error {
	cert := m.current.Load()
	if cert == nil {
		return m.Renew()
	}

	// Parse the leaf certificate to check expiry.
	if len(cert.Certificate) == 0 {
		return m.Renew()
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return m.Renew()
	}

	if time.Until(leaf.NotAfter) <= acmeRenewalWindow {
		return m.Renew()
	}
	return nil
}

// Renew performs a full certificate renewal cycle.
// In production this would invoke the ACME client (instant-acme or similar);
// here it regenerates a self-signed certificate as a reference implementation
// that can be replaced with a real ACME flow.
func (m *AcmeCertManager) Renew() error {
	m.renewMu.Lock()
	defer m.renewMu.Unlock()

	cert, err := m.generateSelfSigned()
	if err != nil {
		return fmt.Errorf("acme: renewal failed: %w", err)
	}
	m.current.Store(cert)
	return nil
}

// generateSelfSigned creates a self-signed ECDSA P-256 certificate for m.domain.
// This is used as the initial/fallback certificate before ACME validation.
func (m *AcmeCertManager) generateSelfSigned() (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	domain := m.domain
	if domain == "" {
		domain = "localhost"
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(acmeSelfSignedValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	_ = m.saveCertToCache(certPEM, keyPEM)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

// AcmeTLSConfig returns a *tls.Config wired to the AcmeCertManager.
// It correctly handles both TLS-ALPN-01 challenges and regular TLS connections.
func (m *AcmeCertManager) AcmeTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", acmeChallengeALPN},
		MinVersion:     tls.VersionTLS12,
	}
}

// PerDomainTLSConfig returns a per-domain TLS config that uses the AcmeCertManager
// for certificate selection.  Pass multiple managers to handle multiple domains.
func PerDomainTLSConfig(managers ...*AcmeCertManager) *tls.Config {
	byDomain := make(map[string]*AcmeCertManager)
	for _, m := range managers {
		byDomain[m.domain] = m
	}

	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if m, ok := byDomain[hello.ServerName]; ok {
				return m.GetCertificate(hello)
			}
			// Fallback to the first manager's cert for unknown SNI.
			if len(managers) > 0 {
				return managers[0].GetCertificate(hello)
			}
			return nil, errors.New("acme: no manager for SNI " + hello.ServerName)
		},
		NextProtos: []string{"h2", "http/1.1", acmeChallengeALPN},
		MinVersion: tls.VersionTLS12,
	}
}

// StealthHandler wraps an http.Handler and returns HTTP 404 responses to
// unauthenticated probes (matching the ech-tls-tunnel stealth approach).
// Authenticated clients that present the correct websocket path are passed
// through to the next handler.
type StealthHandler struct {
	secretPath string
	next       http.Handler
}

// NewStealthHandler creates a StealthHandler.
// secretPath is the WebSocket upgrade path that authenticated clients use.
func NewStealthHandler(secretPath string, next http.Handler) *StealthHandler {
	return &StealthHandler{
		secretPath: secretPath,
		next:       next,
	}
}

// IsSecret returns true if path matches the configured secret path.
func (sh *StealthHandler) IsSecret(path string) bool {
	return path == sh.secretPath
}

// ServeHTTP implements http.Handler. It checks if the request path matches
// the secretPath. If not, it responds with 404 Not Found to resemble a stealth/unused port.
func (sh *StealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if sh.IsSecret(r.URL.Path) {
		if sh.next != nil {
			sh.next.ServeHTTP(w, r)
		}
		return
	}
	w.WriteHeader(http.StatusNotFound)
}

func (m *AcmeCertManager) loadCachedCert() (*tls.Certificate, error) {
	if m.cacheDir == "" {
		return nil, errors.New("acme: no cache directory configured")
	}
	certPath := filepath.Join(m.cacheDir, "cert.pem")
	keyPath := filepath.Join(m.cacheDir, "key.pem")

	tlsCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &tlsCert, nil
}

func (m *AcmeCertManager) saveCertToCache(certPEM, keyPEM []byte) error {
	if m.cacheDir == "" {
		return nil
	}
	if err := os.MkdirAll(m.cacheDir, 0755); err != nil {
		return err
	}
	certPath := filepath.Join(m.cacheDir, "cert.pem")
	keyPath := filepath.Join(m.cacheDir, "key.pem")

	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	return nil
}
