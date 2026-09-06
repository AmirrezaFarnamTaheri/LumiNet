package sub

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return false }

func TestClassifySourceFailureKinds(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"certificate authority", x509.UnknownAuthorityError{}, SourceFailureCertificateVerification},
		{"hostname mismatch", x509.HostnameError{}, SourceFailureCertificateVerification},
		{"invalid certificate", x509.CertificateInvalidError{}, SourceFailureCertificateVerification},
		{"record header", tls.RecordHeaderError{}, SourceFailurePathInterference},
		{"http on https", errors.New("http: server gave HTTP response to HTTPS client"), SourceFailurePathInterference},
		{"timeout", timeoutErr{}, SourceFailureTimeout},
		{"canceled", context.Canceled, SourceFailureCanceled},
		{"network", &net.DNSError{Err: "temporary resolver failure", Name: "example.test"}, SourceFailureNetwork},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifySourceFailure(tc.err); got != tc.want {
				t.Fatalf("classifySourceFailure(%T)=%q want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestSourceFailureKindPropagatesAndClears(t *testing.T) {
	s := NewProfileService()
	profile := s.Create(ManagedProfile{ID: "p1", Name: "p1", URL: "https://example.test/sub"})
	at := time.Now().UTC()
	s.recordSourceFailure(profile.ID, profile.URL, profile.URL, x509.UnknownAuthorityError{}, at)
	failed, ok := s.Get(profile.ID)
	if !ok {
		t.Fatal("profile missing")
	}
	if got := failed.SourceHealth.FailureKind; got != SourceFailureCertificateVerification {
		t.Fatalf("aggregate failure kind=%q", got)
	}
	if got := failed.SourceHealthByURL[profile.URL].FailureKind; got != SourceFailureCertificateVerification {
		t.Fatalf("per-source failure kind=%q", got)
	}

	refreshed, applied := s.ApplyRefresh(profile.ID, profile.URL, ProfileRefresh{LastUpdated: at.Add(time.Second), NodeCount: 1})
	if !applied {
		t.Fatal("refresh not applied")
	}
	if refreshed.SourceHealth.FailureKind != "" || refreshed.SourceHealthByURL[profile.URL].FailureKind != "" {
		t.Fatalf("successful refresh retained failure kind: %+v", refreshed.SourceHealth)
	}

	s.recordSourceFailure(profile.ID, profile.URL, profile.URL, tls.RecordHeaderError{}, at.Add(2*time.Second))
	modified, applied := s.applyNotModified(profile.ID, profile.URL, profile.URL, nil, at.Add(3*time.Second))
	if !applied {
		t.Fatal("304 not applied")
	}
	if modified.SourceHealth.FailureKind != "" || modified.SourceHealthByURL[profile.URL].FailureKind != "" {
		t.Fatalf("304 retained failure kind: %+v", modified.SourceHealth)
	}
}
