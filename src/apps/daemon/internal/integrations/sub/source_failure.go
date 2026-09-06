package sub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
)

// Stable subscription-source failure kinds. These are diagnostic evidence only:
// they must never relax TLS verification or alter source authority.
const (
	SourceFailureCertificateVerification = "certificate_verification"
	SourceFailurePathInterference        = "path_interference_suspected"
	SourceFailureTimeout                 = "timeout"
	SourceFailureCanceled                = "canceled"
	SourceFailureNetwork                 = "network_failure"
)

func classifySourceFailure(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		if errors.Is(err, context.Canceled) {
			return SourceFailureCanceled
		}
		return SourceFailureTimeout
	}

	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostnameError) || errors.As(err, &invalidCertificate) {
		return SourceFailureCertificateVerification
	}

	var recordHeader tls.RecordHeaderError
	if errors.As(err, &recordHeader) {
		return SourceFailurePathInterference
	}

	message := strings.ToLower(err.Error())
	if strings.Contains(message, "server gave http response to https client") ||
		strings.Contains(message, "first record does not look like a tls handshake") ||
		strings.Contains(message, "tls: oversized record") {
		return SourceFailurePathInterference
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return SourceFailureTimeout
	}
	return SourceFailureNetwork
}
