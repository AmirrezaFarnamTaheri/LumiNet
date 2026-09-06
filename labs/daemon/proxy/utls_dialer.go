package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// UTLSDialer handles outbound TLS handshakes with randomized JA3/JA4 fingerprint profile rotation.
type UTLSDialer struct {
	Timeout time.Duration
}

// NewUTLSDialer instantiates a UTLSDialer.
func NewUTLSDialer() *UTLSDialer {
	return &UTLSDialer{Timeout: 5 * time.Second}
}

// DialUTLS connects to a remote server using specified ClientHello fingerprint profile (chrome, firefox, ios, cloak).
func (d *UTLSDialer) DialUTLS(network, addr, profile string, config *tls.Config) (net.Conn, error) {
	rawConn, err := net.DialTimeout(network, addr, d.Timeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	uConfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: config != nil && config.InsecureSkipVerify,
	}

	var clientHelloID utls.ClientHelloID
	switch profile {
	case "firefox":
		clientHelloID = utls.HelloFirefox_Auto
	case "ios":
		clientHelloID = utls.HelloIOS_Auto
	case "cloak":
		clientHelloID = utls.HelloRandomizedALPN
	default:
		clientHelloID = utls.HelloChrome_Auto
	}

	uConn := utls.UClient(rawConn, uConfig, clientHelloID)
	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake failed: %w", err)
	}

	return uConn, nil
}
