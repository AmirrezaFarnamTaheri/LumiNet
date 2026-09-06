//go:build windows

package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DPAPIStore stores each value under the current Windows user using DPAPI.
// Files contain ciphertext only; DPAPI binds decryption to the user profile.
type DPAPIStore struct {
	mu  sync.Mutex
	dir string
}

func newPlatformStore() (NativeStore, error) {
	dir, err := secretsDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("secrets/dpapi: create directory: %w", err)
	}
	return &DPAPIStore{dir: dir}, nil
}

func (s *DPAPIStore) ProviderName() string { return "dpapi" }
func (s *DPAPIStore) Native() bool         { return true }

func (s *DPAPIStore) Put(_ context.Context, ref string, value []byte) error {
	if len(value) == 0 {
		return fmt.Errorf("secrets/dpapi: empty value for %q", ref)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ciphertext, err := dpapiProtect(value)
	if err != nil {
		return err
	}
	path := s.refPath(ref)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, ciphertext, 0600); err != nil {
		return fmt.Errorf("secrets/dpapi: write %q: %w", ref, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("secrets/dpapi: activate %q: %w", ref, err)
	}
	return nil
}

func (s *DPAPIStore) Get(_ context.Context, ref string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ciphertext, err := os.ReadFile(s.refPath(ref))
	if os.IsNotExist(err) {
		return nil, ErrNotFound{Ref: ref}
	}
	if err != nil {
		return nil, fmt.Errorf("secrets/dpapi: read %q: %w", ref, err)
	}
	return dpapiUnprotect(ciphertext)
}

func (s *DPAPIStore) Delete(_ context.Context, ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.refPath(ref)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("secrets/dpapi: delete %q: %w", ref, err)
	}
	return nil
}

func (s *DPAPIStore) List(context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("secrets/dpapi: list: %w", err)
	}
	refs := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".dpapi") {
			refs = append(refs, strings.TrimSuffix(entry.Name(), ".dpapi"))
		}
	}
	sort.Strings(refs)
	return refs, nil
}

func (s *DPAPIStore) refPath(ref string) string {
	safe := strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(ref)
	return filepath.Join(s.dir, safe+".dpapi")
}

func dpapiProtect(value []byte) ([]byte, error) {
	var in, out windows.DataBlob
	in.Size, in.Data = uint32(len(value)), &value[0]
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, 0x01, &out); err != nil {
		return nil, fmt.Errorf("secrets/dpapi: protect: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func dpapiUnprotect(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, errors.New("secrets/dpapi: empty ciphertext")
	}
	var in, out windows.DataBlob
	in.Size, in.Data = uint32(len(value)), &value[0]
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, 0x01, &out); err != nil {
		return nil, fmt.Errorf("secrets/dpapi: unprotect: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
