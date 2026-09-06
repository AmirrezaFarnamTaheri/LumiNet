package crypto

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/secrets"
)

const (
	TPMEnvelopeVersion = 2
	DefaultTPMProfile  = "pcr7-sha256-password-v1"
)

var ErrUnsupportedTPMEnvelope = errors.New("unsupported TPM envelope")

type TPMPolicy struct {
	PCR      int    `json:"pcr"`
	Hash     string `json:"hash"`
	AuthMode string `json:"auth_mode"`
}

func DefaultTPMPolicy() TPMPolicy {
	return TPMPolicy{PCR: pcrNum, Hash: "sha256", AuthMode: "password"}
}

func (p TPMPolicy) Validate() error {
	if p.PCR < 0 || p.Hash == "" || p.AuthMode == "" {
		return errors.New("complete TPM policy context is required")
	}
	return nil
}

// TPMSealer isolates TPM I/O so migration ordering is testable without a physical TPM.
type TPMSealer interface {
	Seal(key, authorization []byte) (public, private []byte, err error)
	Unseal(public, private, authorization []byte) ([]byte, error)
}

// SystemTPMSealer is the production adapter for the local TPM implementation.
// It is intentionally thin so the migration sequence remains independently testable.
type SystemTPMSealer struct{}

func (SystemTPMSealer) Seal(key, authorization []byte) ([]byte, []byte, error) {
	return SealKeyToTPMWithAuthorization(key, authorization)
}

func (SystemTPMSealer) Unseal(public, private, authorization []byte) ([]byte, error) {
	return UnsealKeyFromTPMWithAuthorization(public, private, authorization)
}

// TPMEnvelope stores only ciphertext blobs and a reference to the authorization secret.
// Authorization bytes are never serialized with the envelope.
type TPMEnvelope struct {
	Version       int               `json:"version"`
	RecordID      string            `json:"record_id"`
	Authorization secrets.SecretRef `json:"authorization"`
	Profile       string            `json:"profile"`
	Policy        TPMPolicy         `json:"policy"`
	Public        []byte            `json:"public"`
	Private       []byte            `json:"private"`
}

func (e TPMEnvelope) Validate() error {
	if e.Version != TPMEnvelopeVersion {
		return fmt.Errorf("%w: %d", ErrUnsupportedTPMEnvelope, e.Version)
	}
	if e.Authorization.Provider == "" || e.Authorization.Ref == "" {
		return errors.New("TPM envelope authorization reference is required")
	}
	if e.RecordID == "" {
		return errors.New("TPM envelope record identity is required")
	}
	if e.Profile == "" {
		return errors.New("TPM envelope profile is required")
	}
	if err := e.Policy.Validate(); err != nil {
		return err
	}
	if len(e.Public) == 0 || len(e.Private) == 0 {
		return errors.New("TPM envelope blobs are required")
	}
	return nil
}

func newTPMRecordID() (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", fmt.Errorf("generate TPM record identity: %w", err)
	}
	return hex.EncodeToString(id), nil
}

func boundTPMAuthorization(root []byte, envelope TPMEnvelope) ([]byte, error) {
	binding, err := json.Marshal(struct {
		Version       int               `json:"version"`
		RecordID      string            `json:"record_id"`
		Authorization secrets.SecretRef `json:"authorization"`
		Profile       string            `json:"profile"`
		Policy        TPMPolicy         `json:"policy"`
	}{
		Version:       envelope.Version,
		RecordID:      envelope.RecordID,
		Authorization: envelope.Authorization,
		Profile:       envelope.Profile,
		Policy:        envelope.Policy,
	})
	if err != nil {
		return nil, fmt.Errorf("encode TPM authorization binding: %w", err)
	}
	mac := hmac.New(sha256.New, root)
	_, _ = mac.Write(binding)
	return mac.Sum(nil), nil
}

func zeroBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

// SealTPMEnvelope writes a fresh authorization secret before sealing. The caller must
// verify and atomically activate the returned envelope before retiring its predecessor.
func SealTPMEnvelope(ctx context.Context, key []byte, store secrets.Store, ref secrets.SecretRef, sealer TPMSealer) (TPMEnvelope, error) {
	if len(key) != 32 {
		return TPMEnvelope{}, errors.New("key must be exactly 32 bytes")
	}
	if sealer == nil {
		return TPMEnvelope{}, errors.New("TPM sealer is required")
	}
	if err := secrets.ValidateStoreRef(store, ref, false); err != nil {
		return TPMEnvelope{}, err
	}
	recordID, err := newTPMRecordID()
	if err != nil {
		return TPMEnvelope{}, err
	}
	ref.Ref = strings.TrimRight(ref.Ref, "/") + "/" + recordID
	if _, err := store.Get(ctx, ref.Ref); err == nil {
		return TPMEnvelope{}, errors.New("TPM authorization reference already exists")
	} else {
		var notFound secrets.ErrNotFound
		if !errors.As(err, &notFound) {
			return TPMEnvelope{}, fmt.Errorf("check TPM authorization reference: %w", err)
		}
	}
	rootAuthorization := make([]byte, 32)
	if _, err := rand.Read(rootAuthorization); err != nil {
		return TPMEnvelope{}, fmt.Errorf("generate TPM authorization: %w", err)
	}
	defer zeroBytes(rootAuthorization)
	if err := store.Put(ctx, ref.Ref, rootAuthorization); err != nil {
		return TPMEnvelope{}, fmt.Errorf("store TPM authorization: %w", err)
	}
	envelope := TPMEnvelope{
		Version:       TPMEnvelopeVersion,
		RecordID:      recordID,
		Authorization: ref,
		Profile:       DefaultTPMProfile,
		Policy:        DefaultTPMPolicy(),
	}
	authorization, err := boundTPMAuthorization(rootAuthorization, envelope)
	if err != nil {
		_ = store.Delete(ctx, ref.Ref)
		return TPMEnvelope{}, err
	}
	public, private, err := sealer.Seal(key, authorization)
	if err != nil {
		_ = store.Delete(ctx, ref.Ref)
		return TPMEnvelope{}, fmt.Errorf("seal TPM envelope: %w", err)
	}
	envelope.Public = public
	envelope.Private = private
	if err := envelope.Validate(); err != nil {
		return TPMEnvelope{}, err
	}
	return envelope, nil
}

func UnsealTPMEnvelope(ctx context.Context, envelope TPMEnvelope, store secrets.Store, sealer TPMSealer) ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	if sealer == nil {
		return nil, errors.New("TPM sealer is required")
	}
	if err := secrets.ValidateStoreRef(store, envelope.Authorization, false); err != nil {
		return nil, err
	}
	rootAuthorization, err := store.Get(ctx, envelope.Authorization.Ref)
	if err != nil {
		return nil, fmt.Errorf("load TPM authorization: %w", err)
	}
	defer zeroBytes(rootAuthorization)
	authorization, err := boundTPMAuthorization(rootAuthorization, envelope)
	if err != nil {
		return nil, err
	}
	key, err := sealer.Unseal(envelope.Public, envelope.Private, authorization)
	if err != nil {
		return nil, fmt.Errorf("unseal TPM envelope: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("TPM envelope returned invalid key length %d", len(key))
	}
	return key, nil
}

// MigrateLegacyTPM performs the recover → replacement write → verified reopen sequence.
// persist must atomically activate the replacement while retaining the legacy record.
func MigrateLegacyTPM(ctx context.Context, legacyPublic, legacyPrivate, legacyAuthorization []byte, store secrets.Store, ref secrets.SecretRef, sealer TPMSealer, persist func(TPMEnvelope) error) (TPMEnvelope, error) {
	if persist == nil {
		return TPMEnvelope{}, errors.New("TPM migration persistence callback is required")
	}
	key, err := sealer.Unseal(legacyPublic, legacyPrivate, legacyAuthorization)
	if err != nil {
		return TPMEnvelope{}, fmt.Errorf("recover legacy TPM key: %w", err)
	}
	defer zeroBytes(key)
	replacement, err := SealTPMEnvelope(ctx, key, store, ref, sealer)
	if err != nil {
		return TPMEnvelope{}, err
	}
	verified, err := UnsealTPMEnvelope(ctx, replacement, store, sealer)
	if err != nil {
		_ = store.Delete(ctx, replacement.Authorization.Ref)
		return TPMEnvelope{}, fmt.Errorf("verify replacement TPM envelope: %w", err)
	}
	defer zeroBytes(verified)
	if !bytes.Equal(verified, key) {
		_ = store.Delete(ctx, replacement.Authorization.Ref)
		return TPMEnvelope{}, errors.New("replacement TPM envelope did not recover the legacy key")
	}
	if err := persist(replacement); err != nil {
		_ = store.Delete(ctx, replacement.Authorization.Ref)
		return TPMEnvelope{}, fmt.Errorf("activate replacement TPM envelope: %w", err)
	}
	return replacement, nil
}

// MigrateLegacyTPMToRepository is the opt-in production lifecycle. It refuses
// non-native stores, verifies the replacement before activation, and asks the
// repository to retain the legacy blobs for the configured recovery window.
func MigrateLegacyTPMToRepository(ctx context.Context, legacyPublic, legacyPrivate, legacyAuthorization []byte, store secrets.Store, ref secrets.SecretRef, sealer TPMSealer, repository *TPMEnvelopeRepository, cutoff *time.Time) (TPMEnvelope, error) {
	if repository == nil {
		return TPMEnvelope{}, errors.New("TPM envelope repository is required")
	}
	if cutoff == nil || !cutoff.After(time.Now().UTC()) {
		return TPMEnvelope{}, ErrLegacyCutoff
	}
	if err := secrets.ValidateStoreRef(store, ref, true); err != nil {
		return TPMEnvelope{}, fmt.Errorf("TPM migration provider: %w", err)
	}
	legacy := &LegacyTPMBlobs{Public: legacyPublic, Private: legacyPrivate}
	var replacement TPMEnvelope
	err := repository.withLifecycleLock(func() error {
		var err error
		replacement, err = MigrateLegacyTPM(ctx, legacyPublic, legacyPrivate, legacyAuthorization, store, ref, sealer, func(envelope TPMEnvelope) error {
			return repository.activateLocked(envelope, legacy, cutoff, time.Now().UTC())
		})
		return err
	})
	return replacement, err
}

// UnsealActiveTPMEnvelope resolves and opens only the atomically activated
// envelope. Legacy recovery is intentionally a separate, explicit operation.
func UnsealActiveTPMEnvelope(ctx context.Context, repository *TPMEnvelopeRepository, store secrets.Store, sealer TPMSealer) ([]byte, error) {
	if repository == nil {
		return nil, errors.New("TPM envelope repository is required")
	}
	record, err := repository.Load()
	if err != nil {
		return nil, fmt.Errorf("load active TPM envelope: %w", err)
	}
	if err := secrets.ValidateStoreRef(store, record.Active.Authorization, true); err != nil {
		return nil, fmt.Errorf("TPM active provider: %w", err)
	}
	return UnsealTPMEnvelope(ctx, record.Active, store, sealer)
}
