package scanner

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestExtractTLSPeerInfo_EnrichesCertificateEvidence(t *testing.T) {
	leaf := &x509.Certificate{
		Raw:                []byte{1, 2, 3, 4},
		Subject:            pkix.Name{CommonName: "example.test"},
		Issuer:             pkix.Name{CommonName: "Example Test CA"},
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &rsa.PublicKey{},
	}
	intermediate := &x509.Certificate{Raw: []byte{5, 6, 7}}
	info := ExtractTLSPeerInfo(tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
		PeerCertificates:   []*x509.Certificate{leaf, intermediate},
	}, "example.test", "192.0.2.1:443")

	if info.ChainLength != 2 || info.ChainBytes != 7 {
		t.Fatalf("chain evidence = len %d bytes %d", info.ChainLength, info.ChainBytes)
	}
	if info.Subject != "CN=example.test" || info.Issuer != "CN=Example Test CA" {
		t.Fatalf("unexpected subject/issuer: %q / %q", info.Subject, info.Issuer)
	}
	if info.SignatureAlgorithm != "SHA256-RSA" || info.PublicKeyAlgorithm != "RSA" {
		t.Fatalf("unexpected algorithms: %q / %q", info.SignatureAlgorithm, info.PublicKeyAlgorithm)
	}
}
