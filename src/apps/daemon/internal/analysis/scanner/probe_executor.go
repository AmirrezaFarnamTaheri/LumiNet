// Endpoint probing is internal scanner implementation; callers use scanner results, not a probe seam.
package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Protocol identifies the transport measured by an observation.
type probeProtocol string

const (
	probeProtocolTCP probeProtocol = "tcp"
	probeProtocolTLS probeProtocol = "tls"
)

// VerificationMode controls certificate verification during a TLS measurement.
type probeVerificationMode string

const (
	probeVerificationStrict          probeVerificationMode = "strict"
	probeVerificationObservationOnly probeVerificationMode = "observation_only"
	probeVerificationNotApplicable   probeVerificationMode = "not_applicable"
)

// Endpoint is a protocol-neutral network destination.
type probeEndpoint struct {
	Host       string
	Port       uint16
	ServerName string
}

// Address returns Endpoint in host:port form.
func (e probeEndpoint) address() (string, error) {
	host := strings.TrimSpace(e.Host)
	if host == "" {
		return "", errors.New("probe endpoint host is required")
	}
	if e.Port == 0 {
		return "", errors.New("probe endpoint port is required")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(e.Port))), nil
}

// Request describes one endpoint measurement.
type probeRequest struct {
	Endpoint     probeEndpoint
	Protocol     probeProtocol
	Verification probeVerificationMode
	Timeout      time.Duration
}

// Observation records one protocol measurement and its verification semantics.
type ProbeObservation struct {
	Endpoint       probeEndpoint
	Protocol       probeProtocol
	Verification   probeVerificationMode
	Succeeded      bool
	ConnectLatency time.Duration
	TLSLatency     time.Duration
	TLSVersion     uint16
	Error          string
}

// Executor performs a protocol measurement. Native adapters must implement the
// same interface so cancellation and result semantics remain identical.
type probeExecutor interface {
	probe(context.Context, probeRequest) ProbeObservation
}

// GoExecutor performs measurements with the Go network stack.
type goProbeExecutor struct{}

// Probe measures TCP connectivity or a TLS handshake.
func (goProbeExecutor) probe(ctx context.Context, request probeRequest) ProbeObservation {
	observation := ProbeObservation{
		Endpoint:     request.Endpoint,
		Protocol:     request.Protocol,
		Verification: request.Verification,
	}
	if request.Protocol != probeProtocolTCP && request.Protocol != probeProtocolTLS {
		observation.Error = fmt.Sprintf("unsupported probe protocol %q", request.Protocol)
		return observation
	}
	if request.Protocol == probeProtocolTCP && request.Verification == "" {
		observation.Verification = probeVerificationNotApplicable
	}
	if request.Protocol == probeProtocolTLS && request.Verification == "" {
		observation.Verification = probeVerificationStrict
	}
	address, err := request.Endpoint.address()
	if err != nil {
		observation.Error = err.Error()
		return observation
	}
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	connectStarted := time.Now()
	connection, err := dialer.DialContext(ctx, "tcp", address)
	observation.ConnectLatency = time.Since(connectStarted)
	if err != nil {
		observation.Error = err.Error()
		return observation
	}
	defer connection.Close()
	if request.Protocol == probeProtocolTCP {
		observation.Succeeded = true
		return observation
	}

	serverName := request.Endpoint.ServerName
	if serverName == "" {
		serverName = request.Endpoint.Host
	}
	tlsConfig := &tls.Config{ServerName: serverName}
	if observation.Verification == probeVerificationObservationOnly {
		tlsConfig.InsecureSkipVerify = true
	}
	tlsConnection := tls.Client(connection, tlsConfig)
	tlsStarted := time.Now()
	err = tlsConnection.HandshakeContext(ctx)
	observation.TLSLatency = time.Since(tlsStarted)
	if err != nil {
		observation.Error = err.Error()
		return observation
	}
	observation.Succeeded = true
	observation.TLSVersion = tlsConnection.ConnectionState().Version
	return observation
}
