package updateadmission

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func schemaV2Envelope(t *testing.T, sequence uint64, rollout float64) (*Verifier, Envelope, time.Time) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(77 + i)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	manifest := Manifest{
		SchemaVersion: ManifestSchemaVersion, Product: "luminet", ReleaseID: "release-229", Version: "229.0.0", FromVersion: "228.0.0", RollbackVersion: "228.0.0",
		ArtifactURL: "https://releases.example/luminet-229.tar.gz", ArtifactSHA256: strings.Repeat("cd", 32), ArtifactSize: 4096,
		PublishedAt: now.Add(-time.Minute), ExpiresAt: now.Add(24 * time.Hour), MetadataSequence: sequence, Rollout: &rollout,
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(private, payload)
	verifier, err := NewVerifier(map[string]string{"release-v2": base64.StdEncoding.EncodeToString(public)})
	if err != nil {
		t.Fatal(err)
	}
	return verifier, Envelope{KeyID: "release-v2", Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(sig)}, now
}

func TestSchemaV2UpdateMetadataHighWater(t *testing.T) {
	verifier, envelope, now := schemaV2Envelope(t, 12, 0.5)
	if _, err := verifier.VerifyWithMinimumSequence(now, "228.0.0", 13, envelope); err == nil {
		t.Fatal("stale signed metadata accepted below high-water mark")
	}
	plan, err := verifier.VerifyWithMinimumSequence(now, "228.0.0", 12, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SchemaVersion != ManifestSchemaVersion || plan.MetadataSequence != 12 || !plan.ReplayProtected || plan.Rollout == nil || *plan.Rollout != 0.5 {
		t.Fatalf("schema-v2 plan lost replay/rollout truth: %+v", plan)
	}
}

func TestSchemaV2RequiresSequenceAndBoundedRollout(t *testing.T) {
	verifier, envelope, now := schemaV2Envelope(t, 0, 0.5)
	if _, err := verifier.Verify(now, "228.0.0", envelope); err == nil {
		t.Fatal("schema-v2 manifest without sequence accepted")
	}
	verifier, envelope, now = schemaV2Envelope(t, 1, 1.5)
	if _, err := verifier.Verify(now, "228.0.0", envelope); err == nil {
		t.Fatal("schema-v2 manifest with invalid rollout accepted")
	}
}

func TestLegacySchemaRemainsReadableButDoesNotClaimReplayProtection(t *testing.T) {
	verifier, envelope, now := signedEnvelope(t, nil)
	plan, err := verifier.VerifyWithMinimumSequence(now, "3.0.0", 99, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if plan.SchemaVersion != LegacyManifestSchemaVersion || plan.ReplayProtected || plan.MetadataSequence != 0 {
		t.Fatalf("legacy schema replay truth incorrect: %+v", plan)
	}
}
