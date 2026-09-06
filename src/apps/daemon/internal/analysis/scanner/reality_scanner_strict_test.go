package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func testRealityTLS(t *testing.T, dnsName string) (string, *x509.CertPool, func()) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "LumiNet test root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: dnsName}, DNSNames: []string{dnsName}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: leafKey}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{leafPEM}})
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				<-stop
			}(conn)
		}
	}()
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return listener.Addr().String(), pool, func() { close(stop); _ = listener.Close() }
}

func TestRealityScannerRequiresTrustedMatchingCertificate(t *testing.T) {
	addr, roots, stop := testRealityTLS(t, "good.test")
	defer stop()
	scanner := &RealityScanner{Timeout: time.Second, RootCAs: roots}
	got, err := scanner.Scan(context.Background(), addr, "good.test")
	if err != nil {
		t.Fatal(err)
	}
	if !got.HandshakeOK {
		t.Fatalf("trusted matching cert rejected: %+v", got)
	}
	if got.CertSubject == "" {
		t.Fatalf("missing cert subject: %+v", got)
	}
}

func TestRealityScannerRejectsHostnameMismatch(t *testing.T) {
	addr, roots, stop := testRealityTLS(t, "good.test")
	defer stop()
	scanner := &RealityScanner{Timeout: time.Second, RootCAs: roots}
	got, err := scanner.Scan(context.Background(), addr, "wrong.test")
	if err != nil {
		t.Fatal(err)
	}
	if got.HandshakeOK || got.Error == "" {
		t.Fatalf("hostname mismatch accepted: %+v", got)
	}
}

func TestRealityScannerRejectsUntrustedCertificate(t *testing.T) {
	addr, _, stop := testRealityTLS(t, "good.test")
	defer stop()
	scanner := &RealityScanner{Timeout: time.Second, RootCAs: x509.NewCertPool()}
	got, err := scanner.Scan(context.Background(), addr, "good.test")
	if err != nil {
		t.Fatal(err)
	}
	if got.HandshakeOK || got.Error == "" {
		t.Fatalf("untrusted certificate accepted: %+v", got)
	}
}

func TestRealityScannerHandshakeHonorsContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(time.Second)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	got, err := (&RealityScanner{Timeout: time.Second}).Scan(ctx, listener.Addr().String(), "good.test")
	if err != nil {
		t.Fatal(err)
	}
	if got.HandshakeOK || got.Error == "" {
		t.Fatalf("stalled peer accepted: %+v", got)
	}
	if time.Since(started) > 300*time.Millisecond {
		t.Fatalf("context cancellation not honored: %s", time.Since(started))
	}
	if len(got.Error) > maxRealityScanErrorLen {
		t.Fatalf("unbounded error length=%d", len(got.Error))
	}
}
