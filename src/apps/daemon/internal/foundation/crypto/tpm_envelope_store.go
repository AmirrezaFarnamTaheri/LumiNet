package crypto

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const TPMEnvelopeRecordVersion = 2

var ErrLegacyCutoff = errors.New("legacy TPM compatibility cutoff is absent or expired")

// LegacyTPMBlobs are retained only for a controlled migration window. They
// allow an older binary or a recovery tool to read a pre-envelope object.
type LegacyTPMBlobs struct {
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
}

type TPMEnvelopeRecord struct {
	Version      int             `json:"version"`
	RecordID     string          `json:"record_id"`
	Profile      string          `json:"profile"`
	Policy       TPMPolicy       `json:"policy"`
	Active       TPMEnvelope     `json:"active"`
	Legacy       *LegacyTPMBlobs `json:"legacy,omitempty"`
	ActivatedAt  time.Time       `json:"activated_at"`
	LegacyCutoff *time.Time      `json:"legacy_cutoff,omitempty"`
}

func (r TPMEnvelopeRecord) Validate() error {
	if r.Version != TPMEnvelopeRecordVersion {
		return fmt.Errorf("unsupported TPM envelope record version %d", r.Version)
	}
	if err := r.Active.Validate(); err != nil {
		return fmt.Errorf("invalid active TPM envelope: %w", err)
	}
	if r.RecordID == "" || r.RecordID != r.Active.RecordID {
		return errors.New("TPM record identity does not match active envelope")
	}
	if r.Profile == "" || r.Profile != r.Active.Profile {
		return errors.New("TPM profile does not match active envelope")
	}
	if r.Policy != r.Active.Policy {
		return errors.New("TPM policy does not match active envelope")
	}
	if r.ActivatedAt.IsZero() {
		return errors.New("TPM envelope activation time is required")
	}
	if r.Legacy != nil {
		if len(r.Legacy.Public) == 0 || len(r.Legacy.Private) == 0 {
			return errors.New("legacy TPM blobs are incomplete")
		}
		if r.LegacyCutoff == nil {
			return ErrLegacyCutoff
		}
	}
	return nil
}

// TPMEnvelopeRepository owns atomic record replacement. It does not delete
// legacy blobs; legacy retirement is a separate, explicitly approved action.
type TPMEnvelopeRepository struct {
	mu                    sync.Mutex
	path                  string
	beforeRollbackPublish func()
}

func NewTPMEnvelopeRepository(path string) *TPMEnvelopeRepository {
	return &TPMEnvelopeRepository{path: path}
}

func (r *TPMEnvelopeRepository) Load() (TPMEnvelopeRecord, error) {
	if r.path == "" {
		return TPMEnvelopeRecord{}, errors.New("TPM envelope repository path is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var record TPMEnvelopeRecord
	err := withTPMRepositoryLock(r.path+".lock", func() error {
		var err error
		record, err = r.loadLocked()
		return err
	})
	return record, err
}

func (r *TPMEnvelopeRepository) loadLocked() (TPMEnvelopeRecord, error) {
	raw, err := os.ReadFile(r.path)
	if err != nil {
		return TPMEnvelopeRecord{}, err
	}
	var record TPMEnvelopeRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return TPMEnvelopeRecord{}, fmt.Errorf("parse TPM envelope record: %w", err)
	}
	if err := record.Validate(); err != nil {
		return TPMEnvelopeRecord{}, err
	}
	return record, nil
}

// Activate atomically switches the active envelope. legacy is written only on
// first migration and is never overwritten by later activations.
func (r *TPMEnvelopeRepository) Activate(active TPMEnvelope, legacy *LegacyTPMBlobs, cutoff *time.Time) error {
	if err := active.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC()
	return r.withLifecycleLock(func() error {
		return r.activateLocked(active, legacy, cutoff, now)
	})
}

func (r *TPMEnvelopeRepository) withLifecycleLock(fn func() error) error {
	if r.path == "" {
		return errors.New("TPM envelope repository path is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return withTPMRepositoryLock(r.path+".lock", fn)
}

func (r *TPMEnvelopeRepository) activateLocked(active TPMEnvelope, legacy *LegacyTPMBlobs, cutoff *time.Time, now time.Time) error {
	var retainedLegacy *LegacyTPMBlobs
	if current, err := r.loadLocked(); err == nil {
		if current.RecordID != active.RecordID {
			return errors.New("cannot replace TPM record with a different identity")
		}
		retainedLegacy = current.Legacy
		if cutoff == nil {
			cutoff = current.LegacyCutoff
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if retainedLegacy == nil && legacy != nil {
		if cutoff == nil || !cutoff.After(now) {
			return ErrLegacyCutoff
		}
		retainedLegacy = &LegacyTPMBlobs{Public: append([]byte(nil), legacy.Public...), Private: append([]byte(nil), legacy.Private...)}
	}
	record := TPMEnvelopeRecord{
		Version:      TPMEnvelopeRecordVersion,
		RecordID:     active.RecordID,
		Profile:      active.Profile,
		Policy:       active.Policy,
		Active:       active,
		Legacy:       retainedLegacy,
		ActivatedAt:  now,
		LegacyCutoff: cutoff,
	}
	if err := record.Validate(); err != nil {
		return err
	}
	return r.writeLocked(record)
}

func (r *TPMEnvelopeRepository) writeLocked(record TPMEnvelopeRecord) error {
	if err := os.MkdirAll(filepath.Dir(r.path), 0700); err != nil {
		return fmt.Errorf("create TPM envelope directory: %w", err)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode TPM envelope record: %w", err)
	}
	return writeTPMFileAtomically(r.path, raw)
}

func writeTPMFileAtomically(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary TPM file: %w", err)
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("secure temporary TPM file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary TPM file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary TPM file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary TPM file: %w", err)
	}
	closed = true
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("activate TPM file: %w", err)
	}
	if err := syncTPMDirectory(dir); err != nil {
		return fmt.Errorf("sync TPM directory: %w", err)
	}
	return nil
}

// LoadLegacy is the isolated compatibility reader. At or after the cutoff it
// refuses legacy material even though the retained blobs remain auditable.
func (r *TPMEnvelopeRepository) LoadLegacy(now time.Time) (LegacyTPMBlobs, error) {
	record, err := r.Load()
	if err != nil {
		return LegacyTPMBlobs{}, err
	}
	if record.Legacy == nil || record.LegacyCutoff == nil || !now.UTC().Before(record.LegacyCutoff.UTC()) {
		return LegacyTPMBlobs{}, ErrLegacyCutoff
	}
	return LegacyTPMBlobs{
		Public:  append([]byte(nil), record.Legacy.Public...),
		Private: append([]byte(nil), record.Legacy.Private...),
	}, nil
}

// SetLegacyCutoff may only preserve or shorten an existing compatibility
// window. Extending a production cutoff requires a new migration decision.
func (r *TPMEnvelopeRepository) SetLegacyCutoff(cutoff time.Time) error {
	return r.withLifecycleLock(func() error {
		record, err := r.loadLocked()
		if err != nil {
			return err
		}
		if record.Legacy == nil || record.LegacyCutoff == nil {
			return ErrLegacyCutoff
		}
		cutoff = cutoff.UTC()
		if cutoff.After(record.LegacyCutoff.UTC()) {
			return errors.New("legacy TPM cutoff cannot be extended")
		}
		record.LegacyCutoff = &cutoff
		return r.writeLocked(record)
	})
}

// ExportLegacyRollback atomically publishes a complete rollback bundle. It
// holds the lifecycle lock through staging, evaluates cutoff authorization
// again immediately before publication, then performs the directory rename as
// the next operation. Observers see either no directory or the complete pair.
func (r *TPMEnvelopeRepository) ExportLegacyRollback(now time.Time, outputDir string) error {
	if outputDir == "" {
		return errors.New("legacy rollback output directory is required")
	}
	return r.withLifecycleLock(func() error {
		record, err := r.loadLocked()
		if err != nil {
			return err
		}
		if record.Legacy == nil || record.LegacyCutoff == nil || !now.UTC().Before(record.LegacyCutoff.UTC()) {
			return ErrLegacyCutoff
		}
		return writeTPMRollbackBundle(outputDir, record, r.beforeRollbackPublish)
	})
}

func writeTPMRollbackBundle(outputDir string, record TPMEnvelopeRecord, beforePublish func()) error {
	if _, err := os.Lstat(outputDir); err == nil {
		return errors.New("legacy rollback output directory already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect legacy rollback output: %w", err)
	}
	parent := filepath.Dir(outputDir)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return fmt.Errorf("create legacy rollback parent: %w", err)
	}
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(outputDir)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create legacy rollback staging directory: %w", err)
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0700); err != nil {
		return fmt.Errorf("secure legacy rollback staging directory: %w", err)
	}
	publicPath := filepath.Join(staging, "crypto.pub")
	privatePath := filepath.Join(staging, "crypto.priv")
	if err := writeTPMFileAtomically(publicPath, record.Legacy.Public); err != nil {
		return fmt.Errorf("stage legacy public blob: %w", err)
	}
	if err := writeTPMFileAtomically(privatePath, record.Legacy.Private); err != nil {
		return fmt.Errorf("stage legacy private blob: %w", err)
	}
	manifest, err := json.Marshal(struct {
		Version       int       `json:"version"`
		RecordID      string    `json:"record_id"`
		LegacyCutoff  time.Time `json:"legacy_cutoff"`
		PublicSHA256  string    `json:"public_sha256"`
		PrivateSHA256 string    `json:"private_sha256"`
	}{
		Version:       1,
		RecordID:      record.RecordID,
		LegacyCutoff:  record.LegacyCutoff.UTC(),
		PublicSHA256:  fmt.Sprintf("%x", sha256.Sum256(record.Legacy.Public)),
		PrivateSHA256: fmt.Sprintf("%x", sha256.Sum256(record.Legacy.Private)),
	})
	if err != nil {
		return fmt.Errorf("encode legacy rollback manifest: %w", err)
	}
	if err := writeTPMFileAtomically(filepath.Join(staging, "manifest.json"), manifest); err != nil {
		return fmt.Errorf("stage legacy rollback manifest: %w", err)
	}
	if err := syncTPMDirectory(staging); err != nil {
		return fmt.Errorf("sync legacy rollback staging directory: %w", err)
	}
	if beforePublish != nil {
		beforePublish()
	}
	if !time.Now().UTC().Before(record.LegacyCutoff.UTC()) {
		return ErrLegacyCutoff
	}
	if err := os.Rename(staging, outputDir); err != nil {
		return fmt.Errorf("publish legacy rollback bundle: %w", err)
	}
	if err := syncTPMDirectory(parent); err != nil {
		return fmt.Errorf("sync legacy rollback parent: %w", err)
	}
	return nil
}
