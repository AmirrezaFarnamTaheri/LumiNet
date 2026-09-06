package crypto

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maybeknott/luminet/internal/foundation/secrets"
)

func testEnvelope(ref string) TPMEnvelope {
	return TPMEnvelope{
		Version:       TPMEnvelopeVersion,
		RecordID:      "record-1",
		Authorization: secrets.SecretRef{Provider: "test", Ref: ref},
		Profile:       DefaultTPMProfile,
		Policy:        DefaultTPMPolicy(),
		Public:        []byte("public"),
		Private:       []byte("private"),
	}
}

func TestTPMEnvelopeRepositoryActivatesAtomicallyAndRetainsLegacy(t *testing.T) {
	repo := NewTPMEnvelopeRepository(filepath.Join(t.TempDir(), "tpm-envelope.json"))
	cutoff := time.Now().UTC().Add(24 * time.Hour)
	legacy := &LegacyTPMBlobs{Public: []byte("old-public"), Private: []byte("old-private")}
	if err := repo.Activate(testEnvelope("first"), legacy, &cutoff); err != nil {
		t.Fatal(err)
	}
	if err := repo.Activate(testEnvelope("second"), &LegacyTPMBlobs{Public: []byte("replacement")}, nil); err != nil {
		t.Fatal(err)
	}
	record, err := repo.Load()
	if err != nil {
		t.Fatal(err)
	}
	if record.Active.Authorization.Ref != "second" {
		t.Fatalf("active ref = %q, want second", record.Active.Authorization.Ref)
	}
	if string(record.Legacy.Public) != "old-public" || record.LegacyCutoff == nil {
		t.Fatal("legacy recovery material or cutoff was not retained")
	}
}

func TestTPMEnvelopeRepositoryRejectsInvalidActivation(t *testing.T) {
	repo := NewTPMEnvelopeRepository(filepath.Join(t.TempDir(), "tpm-envelope.json"))
	if err := repo.Activate(TPMEnvelope{}, nil, nil); err == nil {
		t.Fatal("expected invalid envelope rejection")
	}
}

func TestTPMEnvelopeRepositoryRequiresPathBeforeMutation(t *testing.T) {
	repo := NewTPMEnvelopeRepository("")
	if _, err := repo.Load(); err == nil {
		t.Fatal("expected empty repository path rejection")
	}
	if err := repo.Activate(testEnvelope("first"), nil, nil); err == nil {
		t.Fatal("expected empty repository path rejection")
	}
}

func TestTPMEnvelopeRepositoryRejectsLegacyWithoutFutureCutoff(t *testing.T) {
	repo := NewTPMEnvelopeRepository(filepath.Join(t.TempDir(), "tpm-envelope.json"))
	legacy := &LegacyTPMBlobs{Public: []byte("old-public"), Private: []byte("old-private")}
	if err := repo.Activate(testEnvelope("first"), legacy, nil); !errors.Is(err, ErrLegacyCutoff) {
		t.Fatalf("error = %v, want ErrLegacyCutoff", err)
	}
	expired := time.Now().UTC().Add(-time.Second)
	if err := repo.Activate(testEnvelope("first"), legacy, &expired); !errors.Is(err, ErrLegacyCutoff) {
		t.Fatalf("error = %v, want ErrLegacyCutoff", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(repo.path), filepath.Base(repo.path))); !os.IsNotExist(err) {
		t.Fatalf("rejected activation created record: %v", err)
	}
}

func TestTPMEnvelopeRepositoryLegacyReadHonorsCutoff(t *testing.T) {
	repo := NewTPMEnvelopeRepository(filepath.Join(t.TempDir(), "tpm-envelope.json"))
	cutoff := time.Now().UTC().Add(time.Hour)
	legacy := &LegacyTPMBlobs{Public: []byte("old-public"), Private: []byte("old-private")}
	if err := repo.Activate(testEnvelope("first"), legacy, &cutoff); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.LoadLegacy(cutoff.Add(-time.Second)); err != nil {
		t.Fatalf("legacy read before cutoff: %v", err)
	}
	if _, err := repo.LoadLegacy(cutoff); !errors.Is(err, ErrLegacyCutoff) {
		t.Fatalf("error = %v, want ErrLegacyCutoff", err)
	}
}

func TestTPMEnvelopeRepositoryExportsRollbackOnlyBeforeCutoff(t *testing.T) {
	repo := NewTPMEnvelopeRepository(filepath.Join(t.TempDir(), "tpm-envelope.json"))
	cutoff := time.Now().UTC().Add(time.Hour)
	legacy := &LegacyTPMBlobs{Public: []byte("old-public"), Private: []byte("old-private")}
	if err := repo.Activate(testEnvelope("first"), legacy, &cutoff); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(t.TempDir(), "rollback")
	if err := repo.ExportLegacyRollback(cutoff.Add(-time.Second), outputDir); err != nil {
		t.Fatal(err)
	}
	public, err := os.ReadFile(filepath.Join(outputDir, "crypto.pub"))
	if err != nil {
		t.Fatal(err)
	}
	private, err := os.ReadFile(filepath.Join(outputDir, "crypto.priv"))
	if err != nil {
		t.Fatal(err)
	}
	if string(public) != "old-public" || string(private) != "old-private" {
		t.Fatal("rollback export did not preserve retained legacy blobs")
	}
	if _, err := os.Stat(filepath.Join(outputDir, "manifest.json")); err != nil {
		t.Fatalf("rollback manifest: %v", err)
	}
	if err := repo.ExportLegacyRollback(cutoff, filepath.Join(t.TempDir(), "expired")); !errors.Is(err, ErrLegacyCutoff) {
		t.Fatalf("error = %v, want ErrLegacyCutoff", err)
	}
}

func TestTPMEnvelopeRepositoryRollbackIsAtomicWithConcurrentCutoff(t *testing.T) {
	repo := NewTPMEnvelopeRepository(filepath.Join(t.TempDir(), "tpm-envelope.json"))
	cutoff := time.Now().UTC().Add(time.Hour)
	legacy := &LegacyTPMBlobs{Public: make([]byte, 2<<20), Private: make([]byte, 2<<20)}
	legacy.Public[0] = 1
	legacy.Private[0] = 2
	if err := repo.Activate(testEnvelope("first"), legacy, &cutoff); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(t.TempDir(), "rollback")
	exportResult := make(chan error, 1)
	cutoffResult := make(chan error, 1)
	go func() {
		exportResult <- NewTPMEnvelopeRepository(repo.path).ExportLegacyRollback(time.Now().UTC(), outputDir)
	}()
	go func() {
		cutoffResult <- NewTPMEnvelopeRepository(repo.path).SetLegacyCutoff(time.Now().UTC().Add(-time.Second))
	}()

	exportErr := <-exportResult
	if cutoffErr := <-cutoffResult; cutoffErr != nil {
		t.Fatalf("cutoff update: %v", cutoffErr)
	}
	if exportErr != nil {
		if !errors.Is(exportErr, ErrLegacyCutoff) {
			t.Fatalf("rollback export: %v", exportErr)
		}
		if _, err := os.Stat(outputDir); !os.IsNotExist(err) {
			t.Fatalf("cutoff-rejected export published output: %v", err)
		}
		return
	}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if got := strings.Join(names, ","); got != "crypto.priv,crypto.pub,manifest.json" {
		t.Fatalf("published partial rollback bundle: %s", got)
	}
}

func TestTPMEnvelopeRepositoryRollbackRechecksWallClockBeforePublish(t *testing.T) {
	parent := t.TempDir()
	repo := NewTPMEnvelopeRepository(filepath.Join(parent, "tpm-envelope.json"))
	cutoff := time.Now().UTC().Add(2 * time.Second)
	legacy := &LegacyTPMBlobs{Public: []byte("old-public"), Private: []byte("old-private")}
	if err := repo.Activate(testEnvelope("first"), legacy, &cutoff); err != nil {
		t.Fatal(err)
	}
	hookCalled := false
	repo.beforeRollbackPublish = func() {
		hookCalled = true
		if delay := time.Until(cutoff.Add(50 * time.Millisecond)); delay > 0 {
			time.Sleep(delay)
		}
	}
	outputDir := filepath.Join(parent, "rollback")
	if err := repo.ExportLegacyRollback(time.Now().UTC(), outputDir); !errors.Is(err, ErrLegacyCutoff) {
		t.Fatalf("error = %v, want ErrLegacyCutoff", err)
	}
	if !hookCalled {
		t.Fatal("rollback expired before reaching the pre-publish wall-clock check")
	}
	if _, err := os.Stat(outputDir); !os.IsNotExist(err) {
		t.Fatalf("expired rollback was published: %v", err)
	}
	staging, err := filepath.Glob(filepath.Join(parent, ".rollback.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(staging) != 0 {
		t.Fatalf("expired rollback staging was not removed: %v", staging)
	}
}

func TestTPMEnvelopeRecordRejectsMetadataRebinding(t *testing.T) {
	cutoff := time.Now().UTC().Add(time.Hour)
	envelope := testEnvelope("first")
	record := TPMEnvelopeRecord{
		Version:      TPMEnvelopeRecordVersion,
		RecordID:     envelope.RecordID,
		Profile:      envelope.Profile,
		Policy:       envelope.Policy,
		Active:       envelope,
		Legacy:       &LegacyTPMBlobs{Public: []byte("old-public"), Private: []byte("old-private")},
		ActivatedAt:  time.Now().UTC(),
		LegacyCutoff: &cutoff,
	}
	record.Profile = "substituted"
	if err := record.Validate(); err == nil {
		t.Fatal("record/profile rebinding was accepted")
	}
}

func TestTPMEnvelopeRepositorySerializesAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tpm-envelope.json")
	cutoff := time.Now().UTC().Add(time.Hour)
	legacy := &LegacyTPMBlobs{Public: []byte("old-public"), Private: []byte("old-private")}
	if err := NewTPMEnvelopeRepository(path).Activate(testEnvelope("initial"), legacy, &cutoff); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- NewTPMEnvelopeRepository(path).Activate(testEnvelope("next"), nil, nil)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	record, err := NewTPMEnvelopeRepository(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if record.Active.RecordID != "record-1" || record.Legacy == nil {
		t.Fatalf("corrupt concurrent record: %+v", record)
	}
	if matches, err := filepath.Glob(path + ".tmp-*"); err != nil || len(matches) != 0 {
		t.Fatalf("temporary files remain: %v, %v", matches, err)
	}
}
