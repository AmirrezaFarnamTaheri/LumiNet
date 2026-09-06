// Ported from: go-mitmproxy-main / mitm-proxy-main
// Target path: server/internal/proxy/mitm_decryptor.go

package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

// MitmDecryptor manages CA and dynamic certificate generation for HTTPS decryption.
type MitmDecryptor struct {
	mu     sync.Mutex
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	certs  map[string]*tls.Certificate
}

// NewMitmDecryptor creates a decryptor using a pre-loaded Root CA certificate and key.
func NewMitmDecryptor(caCert *x509.Certificate, caKey *rsa.PrivateKey) *MitmDecryptor {
	return &MitmDecryptor{
		caCert: caCert,
		caKey:  caKey,
		certs:  make(map[string]*tls.Certificate),
	}
}

// GetCertificate returns a dynamically generated certificate for the given domain.
// Generates and signs it using the CA key. Uses caching.
func (d *MitmDecryptor) GetCertificate(domain string) (*tls.Certificate, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if cert, ok := d.certs[domain]; ok {
		return cert, nil
	}

	// Generate a new private key for the domain certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("mitm_decryptor: generate key: %w", err)
	}

	// Craft certificate template
	serial, _ := rand.Int(rand.Reader, big.NewInt(100000000))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{"LumiNet Decryption Proxy"},
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add IP SANs if it's an IP address, DNS SANs if domain
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain}
	}

	// Sign the domain certificate using our Root CA key
	derBytes, err := x509.CreateCertificate(rand.Reader, template, d.caCert, &privKey.PublicKey, d.caKey)
	if err != nil {
		return nil, fmt.Errorf("mitm_decryptor: create certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privKey,
	}

	d.certs[domain] = tlsCert
	return tlsCert, nil
}

// TLSConfig returns a tls.Config set up to use dynamic SNI certificate generation.
func (d *MitmDecryptor) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			domain := info.ServerName
			if domain == "" {
				// Fallback to local ip if SNI is empty (e.g. direct IP connection)
				host, _, _ := net.SplitHostPort(info.Conn.LocalAddr().String())
				domain = host
			}
			return d.GetCertificate(domain)
		},
	}
}
