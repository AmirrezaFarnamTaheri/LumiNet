// Package updateadmission verifies signed release intents and can stage an exact
// hash-verified artifact without authorizing installation or execution. It is the
// trust boundary between remote release discovery and promotion/rollback authority.
package updateadmission

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"strings"
	"time"
)

const (
	LegacyManifestSchemaVersion = 1
	ManifestSchemaVersion       = 2
	maxPayloadBytes             = 32 << 10
	maxArtifactBytes            = int64(8 << 30)
	maxValidityWindow           = 30 * 24 * time.Hour
	maxFutureClockSkew          = 10 * time.Minute
)

type Envelope struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type Manifest struct {
	SchemaVersion    int       `json:"schema_version"`
	Product          string    `json:"product"`
	ReleaseID        string    `json:"release_id"`
	Version          string    `json:"version"`
	FromVersion      string    `json:"from_version"`
	RollbackVersion  string    `json:"rollback_version"`
	ArtifactURL      string    `json:"artifact_url"`
	ArtifactSHA256   string    `json:"artifact_sha256"`
	ArtifactSize     int64     `json:"artifact_size"`
	PublishedAt      time.Time `json:"published_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	MetadataSequence uint64    `json:"metadata_sequence,omitempty"`
	Rollout          *float64  `json:"rollout,omitempty"`
}

type Plan struct {
	SchemaVersion    int       `json:"schema_version"`
	KeyID            string    `json:"key_id"`
	ReleaseID        string    `json:"release_id"`
	Version          string    `json:"version"`
	FromVersion      string    `json:"from_version"`
	RollbackVersion  string    `json:"rollback_version"`
	ArtifactURL      string    `json:"artifact_url"`
	ArtifactSHA256   string    `json:"artifact_sha256"`
	ArtifactSize     int64     `json:"artifact_size"`
	PublishedAt      time.Time `json:"published_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	VerifiedAt       time.Time `json:"verified_at"`
	MetadataSequence uint64    `json:"metadata_sequence,omitempty"`
	Rollout          *float64  `json:"rollout,omitempty"`
	ReplayProtected  bool      `json:"replay_protected"`
	ApplyAuthorized  bool      `json:"apply_authorized"`
}

type Verifier struct {
	keys map[string]ed25519.PublicKey
}

func NewVerifier(encodedKeys map[string]string) (*Verifier, error) {
	if len(encodedKeys) == 0 {
		return nil, errors.New("no update trust roots configured")
	}
	keys := make(map[string]ed25519.PublicKey, len(encodedKeys))
	for rawID, encoded := range encodedKeys {
		id := strings.TrimSpace(rawID)
		if id == "" {
			return nil, errors.New("update trust root has empty key id")
		}
		if _, exists := keys[id]; exists {
			return nil, fmt.Errorf("duplicate update trust root key id %q after normalization", id)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil {
			return nil, fmt.Errorf("update trust root %q is not valid base64: %w", id, err)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("update trust root %q has %d bytes, want %d", id, len(decoded), ed25519.PublicKeySize)
		}
		keys[id] = append(ed25519.PublicKey(nil), decoded...)
	}
	return &Verifier{keys: keys}, nil
}

func (v *Verifier) Verify(now time.Time, currentVersion string, envelope Envelope) (Plan, error) {
	return v.VerifyWithMinimumSequence(now, currentVersion, 0, envelope)
}

// VerifyWithMinimumSequence verifies the signed envelope and, for schema-v2
// manifests, rejects metadata older than the caller-owned persisted high-water
// mark. It never advances that mark itself.
func (v *Verifier) VerifyWithMinimumSequence(now time.Time, currentVersion string, minimumSequence uint64, envelope Envelope) (Plan, error) {
	if v == nil || len(v.keys) == 0 {
		return Plan{}, errors.New("update verifier has no trust roots")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	keyID := strings.TrimSpace(envelope.KeyID)
	key, ok := v.keys[keyID]
	if !ok {
		return Plan{}, fmt.Errorf("update signing key %q is not trusted", keyID)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.Payload))
	if err != nil {
		return Plan{}, fmt.Errorf("decode update manifest payload: %w", err)
	}
	if len(payload) == 0 || len(payload) > maxPayloadBytes {
		return Plan{}, fmt.Errorf("update manifest payload size %d outside 1..%d", len(payload), maxPayloadBytes)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(envelope.Signature))
	if err != nil {
		return Plan{}, fmt.Errorf("decode update manifest signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, payload, signature) {
		return Plan{}, errors.New("update manifest signature verification failed")
	}

	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	var manifest Manifest
	if err := dec.Decode(&manifest); err != nil {
		return Plan{}, fmt.Errorf("decode signed update manifest: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return Plan{}, errors.New("signed update manifest contains trailing JSON values")
	}
	if err := validateManifest(now, strings.TrimSpace(currentVersion), manifest); err != nil {
		return Plan{}, err
	}
	if manifest.SchemaVersion >= ManifestSchemaVersion && minimumSequence > 0 && manifest.MetadataSequence < minimumSequence {
		return Plan{}, fmt.Errorf("update metadata sequence %d is below persisted high-water mark %d", manifest.MetadataSequence, minimumSequence)
	}
	return Plan{
		SchemaVersion: manifest.SchemaVersion, KeyID: keyID, ReleaseID: manifest.ReleaseID, Version: manifest.Version,
		FromVersion: manifest.FromVersion, RollbackVersion: manifest.RollbackVersion,
		ArtifactURL: manifest.ArtifactURL, ArtifactSHA256: strings.ToLower(manifest.ArtifactSHA256),
		ArtifactSize: manifest.ArtifactSize, PublishedAt: manifest.PublishedAt.UTC(),
		ExpiresAt: manifest.ExpiresAt.UTC(), VerifiedAt: now,
		MetadataSequence: manifest.MetadataSequence, Rollout: manifest.Rollout, ReplayProtected: manifest.SchemaVersion >= ManifestSchemaVersion && minimumSequence > 0,
		ApplyAuthorized: false,
	}, nil
}

func validateManifest(now time.Time, currentVersion string, m Manifest) error {
	if m.SchemaVersion != LegacyManifestSchemaVersion && m.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("unsupported update manifest schema %d", m.SchemaVersion)
	}
	if m.SchemaVersion == ManifestSchemaVersion {
		if m.MetadataSequence == 0 {
			return errors.New("schema-v2 update manifest requires non-zero metadata_sequence")
		}
		if m.Rollout == nil || math.IsNaN(*m.Rollout) || math.IsInf(*m.Rollout, 0) || *m.Rollout < 0 || *m.Rollout > 1 {
			return errors.New("schema-v2 update manifest rollout must be finite and within 0..1")
		}
	}
	if strings.TrimSpace(m.Product) != "luminet" {
		return fmt.Errorf("update manifest product %q is not luminet", m.Product)
	}
	if strings.TrimSpace(m.ReleaseID) == "" || strings.TrimSpace(m.Version) == "" || strings.TrimSpace(m.FromVersion) == "" {
		return errors.New("update manifest release_id/version/from_version are required")
	}
	if currentVersion == "" {
		return errors.New("current version is required for update admission")
	}
	if m.FromVersion != currentVersion {
		return fmt.Errorf("update manifest expects current version %q, have %q", m.FromVersion, currentVersion)
	}
	if m.Version == currentVersion {
		return errors.New("update manifest does not change version")
	}
	if m.RollbackVersion != currentVersion {
		return fmt.Errorf("update rollback version %q must equal current version %q", m.RollbackVersion, currentVersion)
	}
	if m.ArtifactSize <= 0 || m.ArtifactSize > maxArtifactBytes {
		return fmt.Errorf("update artifact size %d outside 1..%d", m.ArtifactSize, maxArtifactBytes)
	}
	digest := strings.TrimSpace(m.ArtifactSHA256)
	if len(digest) != 64 {
		return errors.New("update artifact sha256 must contain 64 hexadecimal characters")
	}
	decodedDigest, err := hex.DecodeString(digest)
	if err != nil || len(decodedDigest) != 32 {
		return errors.New("update artifact sha256 is invalid")
	}
	artifact, err := url.Parse(strings.TrimSpace(m.ArtifactURL))
	if err != nil || artifact.Scheme != "https" || artifact.Host == "" || artifact.User != nil || artifact.Fragment != "" {
		return errors.New("update artifact URL must be absolute HTTPS without userinfo or fragment")
	}
	published := m.PublishedAt.UTC()
	expires := m.ExpiresAt.UTC()
	if published.IsZero() || expires.IsZero() || !expires.After(published) {
		return errors.New("update manifest validity window is invalid")
	}
	if published.After(now.Add(maxFutureClockSkew)) {
		return errors.New("update manifest publication time is too far in the future")
	}
	if !expires.After(now) {
		return errors.New("update manifest has expired")
	}
	if expires.Sub(published) > maxValidityWindow {
		return fmt.Errorf("update manifest validity exceeds %s", maxValidityWindow)
	}
	return nil
}
