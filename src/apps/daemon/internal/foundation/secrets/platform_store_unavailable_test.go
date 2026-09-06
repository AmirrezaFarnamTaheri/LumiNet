//go:build !windows && !darwin && !linux

package secrets

import (
	"errors"
	"testing"
)

func TestNativePlatformStoreIsTruthfullyUnavailable(t *testing.T) {
	store, err := OpenNativeStore()
	if store != nil {
		t.Fatalf("unexpected native store %T", store)
	}
	if !errors.Is(err, ErrNativeStoreUnavailable) {
		t.Fatalf("error = %v, want ErrNativeStoreUnavailable", err)
	}
}
