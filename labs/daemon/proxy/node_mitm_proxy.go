// Package proxy implements outbound protocols and obfuscation mechanisms.
// Ported from: node-http-mitm-proxy-master
// Target path: server/internal/proxy/node_mitm_proxy.go

package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"
)

// NodeMitmProxy CA manager (from ca.ts).
type NodeMitmProxy struct {
	mu                 sync.RWMutex
	caCert             *x509.Certificate
	caPrivateKey       *rsa.PrivateKey
	organization       string
	organizationalUnit string
	commonName         string
	validityYears      int
	keyLength          int
}

// NewNodeMitmProxy initializes a new NodeMitmProxy.
func NewNodeMitmProxy() *NodeMitmProxy {
	return &NodeMitmProxy{
		organization:       "Node MITM Proxy CA",
		organizationalUnit: "CA",
		commonName:         "NodeMITMProxyCA",
		validityYears:      10,
		keyLength:          2048,
	}
}

// GenerateRootCA creates a new self-signed root CA certificate using standard attributes (from ca.ts).
func (n *NodeMitmProxy) GenerateRootCA() error {
	n.mu.RLock()
	keyLen := n.keyLength
	cName := n.commonName
	org := n.organization
	orgUnit := n.organizationalUnit
	vYears := n.validityYears
	n.mu.RUnlock()

	privKey, err := rsa.GenerateKey(rand.Reader, keyLen)
	if err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         cName,
			Country:            []string{"Internet"},
			Province:           []string{"Internet"},
			Locality:           []string{"Internet"},
			Organization:       []string{org},
			OrganizationalUnit: []string{orgUnit},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(vYears, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return err
	}

	n.mu.Lock()
	n.caCert = cert
	n.caPrivateKey = privKey
	n.mu.Unlock()

	return nil
}

// GenerateServerCertificate creates a leaf certificate for the target domain signed by root CA (from ca.ts).
func (n *NodeMitmProxy) GenerateServerCertificate(domain string) (*x509.Certificate, *rsa.PrivateKey, error) {
	n.mu.RLock()
	caCert := n.caCert
	caKey := n.caPrivateKey
	n.mu.RUnlock()

	if caCert == nil || caKey == nil {
		// Generate root CA on the fly if missing
		if err := n.GenerateRootCA(); err != nil {
			return nil, nil, err
		}
		n.mu.RLock()
		caCert = n.caCert
		caKey = n.caPrivateKey
		n.mu.RUnlock()
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         domain,
			Country:            []string{"Internet"},
			Province:           []string{"Internet"},
			Locality:           []string{"Internet"},
			Organization:       []string{"Node MITM Proxy CA"},
			OrganizationalUnit: []string{"Node MITM Proxy Server Certificate"},
		},
		DNSNames:    []string{domain},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, privKey, nil
}

// ModifyRequestHeaders applies custom header injection to proxy requests (from examples/modifyRequest.ts).
func (n *NodeMitmProxy) ModifyRequestHeaders(headers map[string]string) map[string]string {
	n.mu.Lock()
	defer n.mu.Unlock()
	modified := make(map[string]string)
	for k, v := range headers {
		modified[k] = v
	}
	modified["X-Mitm-Proxy"] = "NodeMitmProxy/1.0"
	return modified
}

// ModifyResponseHeaders applies custom header injection to proxy responses (from examples/modifyResponse.ts).
func (n *NodeMitmProxy) ModifyResponseHeaders(headers map[string]string) map[string]string {
	n.mu.Lock()
	defer n.mu.Unlock()
	modified := make(map[string]string)
	for k, v := range headers {
		modified[k] = v
	}
	modified["X-Mitm-Processed"] = "true"
	return modified
}

// SetOrganization overrides the root CA organization.
func (n *NodeMitmProxy) SetOrganization(org string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.organization = org
}

// GetOrganization retrieves the root CA organization.
func (n *NodeMitmProxy) GetOrganization() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.organization
}

// SetOrganizationalUnit overrides the root CA organizational unit.
func (n *NodeMitmProxy) SetOrganizationalUnit(unit string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.organizationalUnit = unit
}

// GetOrganizationalUnit retrieves the root CA organizational unit.
func (n *NodeMitmProxy) GetOrganizationalUnit() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.organizationalUnit
}

// SetCommonName overrides the root CA common name.
func (n *NodeMitmProxy) SetCommonName(name string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.commonName = name
}

// GetCommonName retrieves the root CA common name.
func (n *NodeMitmProxy) GetCommonName() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.commonName
}

// SetValidityYears overrides root CA validity period.
func (n *NodeMitmProxy) SetValidityYears(years int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.validityYears = years
}

// GetValidityYears retrieves root CA validity period.
func (n *NodeMitmProxy) GetValidityYears() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.validityYears
}

// SetKeyLength overrides RSA private key size.
func (n *NodeMitmProxy) SetKeyLength(length int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.keyLength = length
}

// GetKeyLength retrieves RSA private key size.
func (n *NodeMitmProxy) GetKeyLength() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.keyLength
}
