package auth

import (
	"strings"
	"testing"
	"time"
)

func testSecret() []byte { return []byte("super-secret-luminet-test-key-32x") }

func testClaims(exp int64) CustomClaims {
	return CustomClaims{
		Subject:        "test-user",
		Issuer:         "luminet/test",
		Audience:       "luminet-api",
		ExpiresAt:      exp,
		IssuedAt:       time.Now().Unix() - 1,
		Domain:         "vpn.luminet.app",
		Project:        "luminet-core",
		ServiceAccount: "backend-svc",
	}
}

func testClient() *OIDCClient {
	return NewOIDCClient(OIDCConfig{
		Issuer:     "luminet/test",
		HMACSecret: testSecret(),
	})
}

func TestMintAndVerify_Valid(t *testing.T) {
	claims := testClaims(time.Now().Unix() + 3600)
	token, err := MintHMACToken(claims, testSecret())
	if err != nil {
		t.Fatalf("MintHMACToken: %v", err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("expected 3-part JWT, got %q", token)
	}

	client := testClient()
	got, err := client.VerifyToken(token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if got.Subject != claims.Subject {
		t.Errorf("Subject: got %q, want %q", got.Subject, claims.Subject)
	}
	if got.Domain != claims.Domain {
		t.Errorf("Domain: got %q, want %q", got.Domain, claims.Domain)
	}
	if got.Project != claims.Project {
		t.Errorf("Project: got %q, want %q", got.Project, claims.Project)
	}
	if got.ServiceAccount != claims.ServiceAccount {
		t.Errorf("ServiceAccount: got %q, want %q", got.ServiceAccount, claims.ServiceAccount)
	}
}

func TestVerify_Expired(t *testing.T) {
	claims := testClaims(time.Now().Unix() - 3600) // expired 1 hour ago
	token, err := MintHMACToken(claims, testSecret())
	if err != nil {
		t.Fatalf("MintHMACToken: %v", err)
	}

	client := testClient()
	_, err = client.VerifyToken(token)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected 'expired' in error, got: %v", err)
	}
}

func TestVerify_WrongSecret(t *testing.T) {
	claims := testClaims(time.Now().Unix() + 3600)
	token, err := MintHMACToken(claims, []byte("wrong-secret"))
	if err != nil {
		t.Fatalf("MintHMACToken: %v", err)
	}

	client := testClient()
	_, err = client.VerifyToken(token)
	if err == nil {
		t.Fatal("expected signature verification failure, got nil")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("expected 'signature' in error, got: %v", err)
	}
}

func TestVerify_Malformed(t *testing.T) {
	client := testClient()
	cases := []string{
		"",
		"notajwt",
		"only.two",
		"a.b.c.d",
	}
	for _, tc := range cases {
		_, err := client.VerifyToken(tc)
		if err == nil {
			t.Errorf("expected error for malformed token %q", tc)
		}
	}
}

func TestVerify_IssuerMismatch(t *testing.T) {
	claims := testClaims(time.Now().Unix() + 3600)
	claims.Issuer = "some-other-issuer"
	token, err := MintHMACToken(claims, testSecret())
	if err != nil {
		t.Fatalf("MintHMACToken: %v", err)
	}

	client := testClient() // expects issuer "luminet/test"
	_, err = client.VerifyToken(token)
	if err == nil {
		t.Fatal("expected issuer mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("expected 'issuer' in error, got: %v", err)
	}
}

func TestMintToken_FieldRoundtrip(t *testing.T) {
	claims := CustomClaims{
		Subject:        "svc-account@luminet.app",
		Issuer:         "luminet/test",
		ExpiresAt:      time.Now().Unix() + 7200,
		IssuedAt:       time.Now().Unix(),
		Domain:         "internal.corp",
		Project:        "ops",
		ServiceAccount: "ops-runner",
	}
	token, err := MintHMACToken(claims, testSecret())
	if err != nil {
		t.Fatal(err)
	}
	client := testClient()
	got, err := client.VerifyToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if got.ServiceAccount != "ops-runner" {
		t.Errorf("ServiceAccount mismatch: %q", got.ServiceAccount)
	}
	if got.Domain != "internal.corp" {
		t.Errorf("Domain mismatch: %q", got.Domain)
	}
}
