package updateadmission

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signedEnvelope(t *testing.T, mutate func(*Manifest)) (*Verifier, Envelope, time.Time) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	manifest := Manifest{
		SchemaVersion: 1, Product: "luminet", ReleaseID: "release-42",
		Version: "4.0.0", FromVersion: "3.0.0", RollbackVersion: "3.0.0",
		ArtifactURL:    "https://releases.example/luminet-4.tar.gz",
		ArtifactSHA256: strings.Repeat("ab", 32), ArtifactSize: 1024,
		PublishedAt: now.Add(-time.Minute), ExpiresAt: now.Add(24 * time.Hour),
	}
	if mutate != nil {
		mutate(&manifest)
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, payload)
	verifier, err := NewVerifier(map[string]string{"primary": base64.StdEncoding.EncodeToString(public)})
	if err != nil {
		t.Fatal(err)
	}
	return verifier, Envelope{KeyID: "primary", Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(signature)}, now
}

func TestVerifyProducesNonAuthoritativePlan(t *testing.T) {
	verifier, envelope, now := signedEnvelope(t, nil)
	plan, err := verifier.Verify(now, "3.0.0", envelope)
	if err != nil {
		t.Fatal(err)
	}
	if plan.ApplyAuthorized || plan.Version != "4.0.0" || plan.RollbackVersion != "3.0.0" {
		t.Fatalf("plan=%+v", plan)
	}
}

func TestVerifyRejectsTamperUnknownKeyAndVersionMismatch(t *testing.T) {
	verifier, envelope, now := signedEnvelope(t, nil)
	tampered := envelope
	payload, _ := base64.StdEncoding.DecodeString(tampered.Payload)
	payload[len(payload)-2] ^= 1
	tampered.Payload = base64.StdEncoding.EncodeToString(payload)
	if _, err := verifier.Verify(now, "3.0.0", tampered); err == nil {
		t.Fatal("tampered payload accepted")
	}
	unknown := envelope
	unknown.KeyID = "other"
	if _, err := verifier.Verify(now, "3.0.0", unknown); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := verifier.Verify(now, "2.9.0", envelope); err == nil {
		t.Fatal("wrong current version accepted")
	}
}

func TestVerifyRejectsUnsafeManifestShapes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"http artifact", func(m *Manifest) { m.ArtifactURL = "http://example.test/a" }},
		{"userinfo", func(m *Manifest) { m.ArtifactURL = "https://user:pass@example.test/a" }},
		{"expired", func(m *Manifest) { m.ExpiresAt = m.PublishedAt.Add(time.Second) }},
		{"bad digest", func(m *Manifest) { m.ArtifactSHA256 = "xyz" }},
		{"no rollback", func(m *Manifest) { m.RollbackVersion = "" }},
		{"oversize", func(m *Manifest) { m.ArtifactSize = maxArtifactBytes + 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, envelope, now := signedEnvelope(t, tt.mutate)
			if tt.name == "expired" {
				now = now.Add(2 * time.Hour)
			}
			if _, err := verifier.Verify(now, "3.0.0", envelope); err == nil {
				t.Fatal("unsafe manifest accepted")
			}
		})
	}
}

func TestNewVerifierRejectsNormalizedDuplicateKeyIDs(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	encoded := base64.StdEncoding.EncodeToString(public)
	if _, err := NewVerifier(map[string]string{"primary": encoded, " primary ": encoded}); err == nil {
		t.Fatal("normalized duplicate key ids accepted")
	}
}

func TestVerifyRejectsTrailingSignedJSONValue(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	verifier, err := NewVerifier(map[string]string{"primary": base64.StdEncoding.EncodeToString(public)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 11, 8, 0, 0, 0, time.UTC)
	manifest := Manifest{SchemaVersion: 1, Product: "luminet", ReleaseID: "release-42", Version: "4.0.0", FromVersion: "3.0.0", RollbackVersion: "3.0.0", ArtifactURL: "https://releases.example/luminet-4.tar.gz", ArtifactSHA256: strings.Repeat("ab", 32), ArtifactSize: 1024, PublishedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	payload, _ := json.Marshal(manifest)
	payload = append(payload, []byte(` {"extra":true}`)...)
	signature := ed25519.Sign(private, payload)
	envelope := Envelope{KeyID: "primary", Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(signature)}
	if _, err := verifier.Verify(now, "3.0.0", envelope); err == nil {
		t.Fatal("trailing signed JSON value accepted")
	}
}
