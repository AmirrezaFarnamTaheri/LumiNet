package crypto

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/secrets"
)

type memorySecretStore struct{ values map[string][]byte }

func (s *memorySecretStore) Put(_ context.Context, ref string, value []byte) error {
	s.values[ref] = append([]byte(nil), value...)
	return nil
}
func (s *memorySecretStore) Get(_ context.Context, ref string) ([]byte, error) {
	v, ok := s.values[ref]
	if !ok {
		return nil, secrets.ErrNotFound{Ref: ref}
	}
	return append([]byte(nil), v...), nil
}
func (s *memorySecretStore) Delete(_ context.Context, ref string) error {
	delete(s.values, ref)
	return nil
}
func (s *memorySecretStore) List(context.Context) ([]string, error) { return nil, nil }
func (*memorySecretStore) ProviderName() string                     { return "test" }
func (*memorySecretStore) Native() bool                             { return false }

type nativeMemorySecretStore struct{ *memorySecretStore }

func (*nativeMemorySecretStore) ProviderName() string { return "test-native" }
func (*nativeMemorySecretStore) Native() bool         { return true }

type fakeTPM struct {
	legacy, sealed       []byte
	failSeal, failUnseal bool
}

func (f *fakeTPM) Seal(key, authorization []byte) ([]byte, []byte, error) {
	if f.failSeal {
		return nil, nil, errors.New("seal failed")
	}
	f.sealed = append(append([]byte(nil), key...), authorization...)
	return []byte("public"), append([]byte("sealed:"), authorization...), nil
}
func (f *fakeTPM) Unseal(public, private, authorization []byte) ([]byte, error) {
	if f.failUnseal || (string(public) != "legacy" && string(private) != "sealed:"+string(authorization)) || (string(public) == "legacy" && string(private) != string(authorization)) {
		return nil, errors.New("unseal failed")
	}
	if string(public) == "legacy" {
		return append([]byte(nil), f.legacy...), nil
	}
	return append([]byte(nil), f.sealed[:32]...), nil
}

func TestTPMEnvelopeDoesNotSerializeAuthorization(t *testing.T) {
	ctx := context.Background()
	store := &nativeMemorySecretStore{&memorySecretStore{values: map[string][]byte{}}}
	sealer := &fakeTPM{}
	key := make([]byte, 32)
	key[0] = 7
	envelope, err := SealTPMEnvelope(ctx, key, store, secrets.SecretRef{Provider: "test-native", Ref: "tpm/auth"}, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if string(envelope.Private) == string(store.values[envelope.Authorization.Ref]) {
		t.Fatal("authorization was serialized into the private blob")
	}
	got, err := UnsealTPMEnvelope(ctx, envelope, store, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) {
		t.Fatal("unsealed key mismatch")
	}
}

func TestTPMEnvelopeBindsProviderReferenceRecordProfileAndPolicy(t *testing.T) {
	ctx := context.Background()
	store := &nativeMemorySecretStore{&memorySecretStore{values: map[string][]byte{}}}
	key := bytes.Repeat([]byte{0x42}, 32)
	sealer := &fakeTPM{}
	envelope, err := SealTPMEnvelope(ctx, key, store, secrets.SecretRef{Provider: store.ProviderName(), Ref: "tpm/auth"}, sealer)
	if err != nil {
		t.Fatal(err)
	}
	rootAuthorization := append([]byte(nil), store.values[envelope.Authorization.Ref]...)

	tests := map[string]func(*TPMEnvelope){
		"provider": func(e *TPMEnvelope) { e.Authorization.Provider = "other-native" },
		"reference": func(e *TPMEnvelope) {
			e.Authorization.Ref = "tpm/substituted"
			store.values[e.Authorization.Ref] = append([]byte(nil), rootAuthorization...)
		},
		"record":  func(e *TPMEnvelope) { e.RecordID = "different-record" },
		"profile": func(e *TPMEnvelope) { e.Profile = "different-profile" },
		"policy":  func(e *TPMEnvelope) { e.Policy.PCR = 11 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := envelope
			mutate(&changed)
			if _, err := UnsealTPMEnvelope(ctx, changed, store, sealer); err == nil {
				t.Fatal("substituted envelope unexpectedly unsealed")
			}
		})
	}
}

func TestMigrateLegacyTPMVerifiesBeforeActivation(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	key[31] = 9
	store := &memorySecretStore{values: map[string][]byte{}}
	sealer := &fakeTPM{legacy: key}
	activated := false
	_, err := MigrateLegacyTPM(ctx, []byte("legacy"), []byte("old-auth"), []byte("old-auth"), store, secrets.SecretRef{Provider: "test", Ref: "tpm/new"}, sealer, func(TPMEnvelope) error { activated = true; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !activated {
		t.Fatal("replacement was not activated")
	}
}

func TestMigrateLegacyTPMDoesNotActivateOnVerificationFailure(t *testing.T) {
	ctx := context.Background()
	store := &memorySecretStore{values: map[string][]byte{}}
	sealer := &fakeTPM{legacy: make([]byte, 32), failUnseal: true}
	activated := false
	_, err := MigrateLegacyTPM(ctx, []byte("legacy"), []byte("old-auth"), []byte("old-auth"), store, secrets.SecretRef{Provider: "test", Ref: "tpm/new"}, sealer, func(TPMEnvelope) error { activated = true; return nil })
	if err == nil {
		t.Fatal("expected verification failure")
	}
	if activated {
		t.Fatal("activated replacement after verification failure")
	}
}

func TestMigrateLegacyTPMCleansStagedAuthorizationOnActivationFailure(t *testing.T) {
	ctx := context.Background()
	store := &memorySecretStore{values: map[string][]byte{}}
	key := bytes.Repeat([]byte{0x5a}, 32)
	sealer := &fakeTPM{legacy: key}
	_, err := MigrateLegacyTPM(ctx, []byte("legacy"), []byte("old-auth"), []byte("old-auth"), store, secrets.SecretRef{Provider: store.ProviderName(), Ref: "tpm/staged"}, sealer, func(TPMEnvelope) error {
		return errors.New("simulated activation interruption")
	})
	if err == nil {
		t.Fatal("expected activation failure")
	}
	if len(store.values) != 0 {
		t.Fatal("staged authorization remained after activation failure")
	}
}

func TestMigrateLegacyTPMToRepositoryRequiresNativeStore(t *testing.T) {
	store := &memorySecretStore{values: map[string][]byte{}}
	cutoff := time.Now().UTC().Add(time.Hour)
	_, err := MigrateLegacyTPMToRepository(context.Background(), []byte("legacy"), []byte("old-auth"), []byte("old-auth"), store, secrets.SecretRef{Provider: "test", Ref: "tpm/new"}, &fakeTPM{legacy: make([]byte, 32)}, NewTPMEnvelopeRepository(filepath.Join(t.TempDir(), "record.json")), &cutoff)
	if err == nil {
		t.Fatal("expected native-store requirement")
	}
}

func TestMigrateLegacyTPMToRepositoryActivatesVerifiedEnvelope(t *testing.T) {
	store := &nativeMemorySecretStore{&memorySecretStore{values: map[string][]byte{}}}
	key := make([]byte, 32)
	key[0] = 4
	repo := NewTPMEnvelopeRepository(filepath.Join(t.TempDir(), "record.json"))
	cutoff := time.Now().UTC().Add(time.Hour)
	_, err := MigrateLegacyTPMToRepository(context.Background(), []byte("legacy"), []byte("old-auth"), []byte("old-auth"), store, secrets.SecretRef{Provider: "test-native", Ref: "tpm/new"}, &fakeTPM{legacy: key}, repo, &cutoff)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnsealActiveTPMEnvelope(context.Background(), repo, store, &fakeTPM{sealed: append([]byte(nil), key...)})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(key) {
		t.Fatal("active envelope key mismatch")
	}
}

func TestMigrateLegacyTPMToRepositoryRequiresFutureCutoff(t *testing.T) {
	store := &nativeMemorySecretStore{&memorySecretStore{values: map[string][]byte{}}}
	expired := time.Now().UTC().Add(-time.Minute)
	_, err := MigrateLegacyTPMToRepository(context.Background(), []byte("legacy"), []byte("old-auth"), []byte("old-auth"), store, secrets.SecretRef{Provider: store.ProviderName(), Ref: "tpm/new"}, &fakeTPM{legacy: make([]byte, 32)}, NewTPMEnvelopeRepository(filepath.Join(t.TempDir(), "record.json")), &expired)
	if !errors.Is(err, ErrLegacyCutoff) {
		t.Fatalf("error = %v, want ErrLegacyCutoff", err)
	}
	if len(store.values) != 0 {
		t.Fatal("expired cutoff mutated the secret store")
	}
}

func TestUnsealActiveTPMEnvelopeRejectsProviderOutage(t *testing.T) {
	store := &nativeMemorySecretStore{&memorySecretStore{values: map[string][]byte{}}}
	key := bytes.Repeat([]byte{0x6b}, 32)
	cutoff := time.Now().UTC().Add(time.Hour)
	repo := NewTPMEnvelopeRepository(filepath.Join(t.TempDir(), "record.json"))
	if _, err := MigrateLegacyTPMToRepository(context.Background(), []byte("legacy"), []byte("old-auth"), []byte("old-auth"), store, secrets.SecretRef{Provider: store.ProviderName(), Ref: "tpm/new"}, &fakeTPM{legacy: key}, repo, &cutoff); err != nil {
		t.Fatal(err)
	}
	record, err := repo.Load()
	if err != nil {
		t.Fatal(err)
	}
	delete(store.values, record.Active.Authorization.Ref)
	if _, err := UnsealActiveTPMEnvelope(context.Background(), repo, store, &fakeTPM{}); err == nil {
		t.Fatal("provider outage unexpectedly unsealed active envelope")
	}
}

func TestConcurrentLegacyMigrationsSerializeBeforeSecretMutation(t *testing.T) {
	store := &nativeMemorySecretStore{&memorySecretStore{values: map[string][]byte{}}}
	key := bytes.Repeat([]byte{0x7c}, 32)
	cutoff := time.Now().UTC().Add(time.Hour)
	path := filepath.Join(t.TempDir(), "record.json")
	ref := secrets.SecretRef{Provider: store.ProviderName(), Ref: "tpm/shared"}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := MigrateLegacyTPMToRepository(context.Background(), []byte("legacy"), []byte("old-auth"), []byte("old-auth"), store, ref, &fakeTPM{legacy: key}, NewTPMEnvelopeRepository(path), &cutoff)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successful migrations = %d, want 1", successes)
	}
	record, err := NewTPMEnvelopeRepository(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(store.values[record.Active.Authorization.Ref]) == 0 {
		t.Fatal("winning active authorization was removed")
	}
}

func TestMigrationRetryAfterCrashWindowUsesUniqueAuthorizationRef(t *testing.T) {
	store := &nativeMemorySecretStore{&memorySecretStore{values: map[string][]byte{}}}
	key := bytes.Repeat([]byte{0x31}, 32)
	baseRef := secrets.SecretRef{Provider: store.ProviderName(), Ref: "tpm/retry"}

	staged, err := SealTPMEnvelope(context.Background(), key, store, baseRef, &fakeTPM{})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate process loss after Store.Put and sealing, but before repository
	// activation. The staged authorization remains durable and unreachable.
	cutoff := time.Now().UTC().Add(time.Hour)
	repo := NewTPMEnvelopeRepository(filepath.Join(t.TempDir(), "record.json"))
	active, err := MigrateLegacyTPMToRepository(context.Background(), []byte("legacy"), []byte("old-auth"), []byte("old-auth"), store, baseRef, &fakeTPM{legacy: key}, repo, &cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if active.Authorization.Ref == staged.Authorization.Ref {
		t.Fatal("retry reused crash-staged authorization reference")
	}
	if len(store.values[staged.Authorization.Ref]) == 0 || len(store.values[active.Authorization.Ref]) == 0 {
		t.Fatal("retry lost staged or active authorization")
	}
}
